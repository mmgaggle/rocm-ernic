#!/usr/bin/env python3
# Copyright (c) Advanced Micro Devices, Inc. All rights reserved.
#
# SPDX-License-Identifier: MIT
"""Summarise the UET frames in a capture (classic pcap, Ethernet).

    uet-pcap-summary.py FILE.pcap [--probe-rma OFFSET] [--json]

For every IPv4 source and destination pair, counts the UET frames
(IPv4 protocol 253) by PDS type, the requests flagged RETX and the
frames whose first header is TSS. ARP frames are counted per sender.

--probe-rma OFFSET looks for 32 bytes of uet_ernic_rma's pattern,
starting at that offset of the window, in every UET frame: found in
the clear without TSS, never found with it.

The PDS types are decoded from the UET specification independently
of the provider, as tests/test_uet_engine.c does.
"""

import argparse
import collections
import json
import struct
import sys

PDS = {
    0x01: "TSS", 0x02: "RUD_REQ", 0x03: "ROD_REQ", 0x04: "RUDI_REQ",
    0x05: "RUDI_RESP", 0x06: "UUD_REQ", 0x07: "ACK", 0x08: "ACK_CC",
    0x09: "ACK_CCX", 0x0a: "NACK", 0x0b: "CTRL", 0x0c: "NACK_CCX",
    0x0d: "RUD_CC", 0x0e: "ROD_CC",
}
RETX = 0x10
REQUESTS = {"RUD_REQ", "ROD_REQ", "RUDI_REQ", "RUD_CC", "ROD_CC"}


def rma_pattern(off):
    """uet_ernic_rma's byte at window offset off (guest/tools)."""
    m = (1 << 64) - 1
    z = (off // 8 + 0x9e3779b97f4a7c15) & m
    z = ((z ^ (z >> 30)) * 0xbf58476d1ce4e5b9) & m
    z = ((z ^ (z >> 27)) * 0x94d049bb133111eb) & m
    z ^= z >> 31
    return (z >> ((off % 8) * 8)) & 0xff


def frames(path):
    with open(path, "rb") as f:
        hdr = f.read(24)
        if len(hdr) < 24:
            return
        magic = struct.unpack("<I", hdr[:4])[0]
        if magic in (0xa1b2c3d4, 0xa1b23c4d):
            end = "<"
        elif magic in (0xd4c3b2a1, 0x4d3cb2a1):
            end = ">"
        else:
            raise SystemExit(f"{path}: not a classic pcap file")
        nsec = magic in (0xa1b23c4d, 0x4d3cb2a1)
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
    return ".".join(str(x) for x in b)


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("pcap")
    ap.add_argument("--probe-rma", type=int, metavar="OFFSET")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()

    probe = None
    if a.probe_rma is not None:
        probe = bytes(rma_pattern(a.probe_rma + i) for i in range(32))

    flows = collections.OrderedDict()
    arp = collections.Counter()
    t_first = t_last = None
    for ts, f in frames(a.pcap):
        if len(f) < 14:
            continue
        ethertype = struct.unpack(">H", f[12:14])[0]
        if ethertype == 0x0806 and len(f) >= 42:
            op = "request" if f[21] == 1 else "reply"
            arp[f"{ip4(f[28:32])} {op}"] += 1
            continue
        if ethertype != 0x0800 or len(f) < 34 or f[23] != 253:
            continue
        t_first = ts if t_first is None else t_first
        t_last = ts
        ihl = (f[14] & 0x0f) * 4
        key = f"{ip4(f[26:30])} -> {ip4(f[30:34])}"
        fl = flows.setdefault(key, collections.Counter())
        fl["frames"] += 1
        fl["bytes"] += len(f)
        o = 14 + ihl + 4  # past the entropy header
        if len(f) < o + 2:
            fl["short"] += 1
            continue
        w = struct.unpack(">H", f[o:o + 2])[0]
        name = PDS.get(w >> 11, f"type{w >> 11:#x}")
        fl[name] += 1
        if name in REQUESTS and w & RETX:
            fl["RETX"] += 1
        if probe is not None and probe in f:
            fl["probe_in_clear"] += 1

    out = {"pcap": a.pcap, "flows": flows, "arp": arp,
           "seconds": (t_last - t_first) if t_first is not None else 0.0}
    if a.json:
        json.dump(out, sys.stdout, indent=1)
        print()
        return 0
    print(f"{a.pcap}: UET frames over {out['seconds']:.3f} s")
    for k, c in flows.items():
        rest = " ".join(f"{n}={v}" for n, v in sorted(c.items())
                        if n not in ("frames", "bytes"))
        print(f"  {k}: {c['frames']} frames, {c['bytes']} bytes; {rest}")
    for k, v in arp.items():
        print(f"  ARP {k}: {v}")
    if not flows:
        print("  no UET frames")
    return 0


if __name__ == "__main__":
    sys.exit(main())
