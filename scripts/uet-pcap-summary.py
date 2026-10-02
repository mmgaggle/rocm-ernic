#!/usr/bin/env python3
# Copyright (c) Advanced Micro Devices, Inc. All rights reserved.
#
# SPDX-License-Identifier: MIT
"""Summarise the UET frames in a capture (classic pcap, Ethernet).

    uet-pcap-summary.py FILE.pcap [--probe TOOL:OFFSET] [--json]
                        [--udp-port PORT] [--ipproto PROTO]

For every IPv4 source and destination pair, counts the UET frames by
PDS type, the requests flagged RETX and the frames whose first header
is TSS, and how many came in UDP (to --udp-port, default 4793) and how
many directly in IP (--ipproto, default 253). For requests in the
clear it reports the largest payload and the mean payload, which is the
Payload MTU on a long transfer. ARP frames are counted per sender.

--probe TOOL:OFFSET looks for 32 bytes of a test tool's pattern,
starting at that offset of the window, in every UET frame: found in
the clear without TSS, never found with it. TOOL is uet_ernic_rma
(guest/tools) or test_rma (the libfabric provider's test).

The PDS types are decoded from the UET specification independently
of the provider, as tests/test_uet_engine.c does.
"""

# The file name has dashes, like the other tools in scripts/.
# pylint: disable=invalid-name

import argparse
import collections
import json
import struct
import sys

PDS = {
    0x01: "TSS",
    0x02: "RUD_REQ",
    0x03: "ROD_REQ",
    0x04: "RUDI_REQ",
    0x05: "RUDI_RESP",
    0x06: "UUD_REQ",
    0x07: "ACK",
    0x08: "ACK_CC",
    0x09: "ACK_CCX",
    0x0A: "NACK",
    0x0B: "CTRL",
    0x0C: "NACK_CCX",
    0x0D: "RUD_CC",
    0x0E: "ROD_CC",
}
RETX = 0x10
REQUESTS = {"RUD_REQ", "ROD_REQ", "RUDI_REQ", "RUD_CC", "ROD_CC"}
# Bytes of PDS header in front of the SES header, by request type.
PDS_REQ_LEN = {"RUD_REQ": 12, "ROD_REQ": 12, "RUDI_REQ": 8, "RUD_CC": 16, "ROD_CC": 16}
# Bytes of SES header, by the PDS next-header field: the standard request
# header and the response-with-data header carry payload after them.
SES_LEN = {3: 44, 5: 20}
CRC_LEN = 4
# Counters that are not shown as name=value.
SIZES = ("frames", "bytes", "req_payload_bytes", "req_payload_max")


def rma_pattern(off):
    """uet_ernic_rma's byte at window offset off (guest/tools)."""
    m = (1 << 64) - 1
    z = (off // 8 + 0x9E3779B97F4A7C15) & m
    z = ((z ^ (z >> 30)) * 0xBF58476D1CE4E5B9) & m
    z = ((z ^ (z >> 27)) * 0x94D049BB133111EB) & m
    z ^= z >> 31
    return (z >> ((off % 8) * 8)) & 0xFF


def test_rma_pattern(off):
    """test_rma's byte at window offset off (uet-ref-prov prov/)."""
    return (off * 131 + (off >> 12) * 7 + 13) & 0xFF


PATTERNS = {"uet_ernic_rma": rma_pattern, "test_rma": test_rma_pattern}


def frames(path):
    """Yield (timestamp, frame) for every record of a classic pcap file."""
    with open(path, "rb") as f:
        hdr = f.read(24)
        if len(hdr) < 24:
            return
        magic = struct.unpack("<I", hdr[:4])[0]
        if magic in (0xA1B2C3D4, 0xA1B23C4D):
            end = "<"
        elif magic in (0xD4C3B2A1, 0x4D3CB2A1):
            end = ">"
        else:
            raise SystemExit(f"{path}: not a classic pcap file")
        nsec = magic in (0xA1B23C4D, 0x4D3CB2A1)
        linktype = struct.unpack(end + "I", hdr[20:24])[0]
        if linktype != 1:
            raise SystemExit(f"{path}: link type {linktype}, not Ethernet")
        while True:
            rec = f.read(16)
            if len(rec) < 16:
                return
            sec, frac, incl, _orig = struct.unpack(end + "IIII", rec)
            data = f.read(incl)
            yield sec + frac / (1e9 if nsec else 1e6), data


def ip4(b):
    """Dotted quad of four address bytes."""
    return ".".join(str(x) for x in b)


def uet_offset(f, args):
    """The encapsulation of a UET frame and where its PDS header starts,
    or None when the frame is not UET."""
    ihl = (f[14] & 0x0F) * 4
    if (
        f[23] == 17
        and len(f) >= 14 + ihl + 8
        and struct.unpack(">H", f[16 + ihl : 18 + ihl])[0] == args.udp_port
    ):
        return "UDP", 14 + ihl + 8  # past the UDP header
    if f[23] == args.ipproto:
        return "IP", 14 + ihl + 4  # past the entropy header
    return None


def count_uet(fl, f, o, probe):
    """Count one UET frame whose PDS header is at offset o."""
    if len(f) < o + 2:
        fl["short"] += 1
        return
    w = struct.unpack(">H", f[o : o + 2])[0]
    name = PDS.get(w >> 11, f"type{w >> 11:#x}")
    fl[name] += 1
    if name in REQUESTS and w & RETX:
        fl["RETX"] += 1
    nxt = (w >> 7) & 0x0F
    if name in PDS_REQ_LEN and nxt in SES_LEN:
        payload = len(f) - o - PDS_REQ_LEN[name] - SES_LEN[nxt] - CRC_LEN
        fl["req_payload_bytes"] += max(payload, 0)
        fl["req_payload_max"] = max(fl["req_payload_max"], payload)
    if probe is not None and probe in f:
        fl["probe_in_clear"] += 1


def summarise(args, probe):
    """Walk the capture and count what is in it."""
    flows = collections.OrderedDict()
    arp = collections.Counter()
    t_first = t_last = None
    for ts, f in frames(args.pcap):
        if len(f) < 34:
            continue
        ethertype = struct.unpack(">H", f[12:14])[0]
        if ethertype == 0x0806 and len(f) >= 42:
            op = "request" if f[21] == 1 else "reply"
            arp[f"{ip4(f[28:32])} {op}"] += 1
            continue
        found = uet_offset(f, args) if ethertype == 0x0800 else None
        if found is None:
            continue
        t_first = ts if t_first is None else t_first
        t_last = ts
        key = f"{ip4(f[26:30])} -> {ip4(f[30:34])}"
        fl = flows.setdefault(key, collections.Counter())
        fl["frames"] += 1
        fl["bytes"] += len(f)
        fl[found[0]] += 1
        count_uet(fl, f, found[1], probe)
    seconds = (t_last - t_first) if t_first is not None else 0.0
    return {"pcap": args.pcap, "flows": flows, "arp": arp, "seconds": seconds}


def report(out):
    """Print a summary for people."""
    print(f"{out['pcap']}: UET frames over {out['seconds']:.3f} s")
    for k, c in out["flows"].items():
        rest = " ".join(f"{n}={v}" for n, v in sorted(c.items()) if n not in SIZES)
        reqs = sum(c[n] for n in PDS_REQ_LEN)
        size = ""
        if reqs:
            mean = c["req_payload_bytes"] / reqs
            size = f"; request payload max {c['req_payload_max']}, mean {mean:.0f}"
        print(f"  {k}: {c['frames']} frames, {c['bytes']} bytes; {rest}{size}")
    for k, v in out["arp"].items():
        print(f"  ARP {k}: {v}")
    if not out["flows"]:
        print("  no UET frames")


def main():
    """Parse the arguments, summarise the capture and print it."""
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("pcap")
    ap.add_argument("--probe", metavar="TOOL:OFFSET")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--udp-port", type=int, default=4793)
    ap.add_argument("--ipproto", type=int, default=253)
    a = ap.parse_args()

    probe = None
    if a.probe:
        tool, _, off = a.probe.partition(":")
        if tool not in PATTERNS or not off.isdigit():
            ap.error(f"--probe wants TOOL:OFFSET, TOOL one of {', '.join(PATTERNS)}")
        probe = bytes(PATTERNS[tool](int(off) + i) for i in range(32))

    out = summarise(a, probe)
    if a.json:
        json.dump(out, sys.stdout, indent=1)
        print()
    else:
        report(out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
