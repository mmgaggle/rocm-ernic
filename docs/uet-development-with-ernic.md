# UET Development with rocm-ernic and the Reference Provider

rocm-ernic and the UEC reference provider together make a complete
Ultra Ethernet Transport (UET) system that runs on ordinary machines.
A guest application uses libfabric. A device model in userspace on the
host runs the transport as NIC firmware. Real UET frames cross a real or
virtual Ethernet wire. No UET hardware is needed, and the same system
runs at tens of gigabits per second on a stock NIC.

This page describes the parts and how they fit together. It then
lists what the whole is good for in UET development. The reference
for each part is `uet.rst` in this directory.

## The parts

rocm-ernic is a userspace emulated RDMA NIC for virtual machines. It
emulates an AMD Pensando ionic device over the vfio-user protocol. A
guest therefore runs the upstream `ionic` and `ionic_rdma` drivers and
the rdma-core `ionic` provider. With `--uet`, each rocm-ernic instance
also runs a UET engine.

The UET engine is the reference provider's three sublayers, SES, PDS
and TSS, compiled into the device model and run as the device's
firmware. The engine has its own MAC and IPv4 address on the wire. It
builds and parses the real UET packet formats. A frame is Ethernet,
IPv4, and UDP to port 4793 or IP protocol 253 with an entropy header.
Then come the PDS and SES headers and the CRC32C trailer. If security
is on, a TSS header is there as well.

The wire is where the frames go. By default it is the host TAP that
carries the guest's own Ethernet traffic. With the DPDK wire, the
engine owns a DPDK port instead. That port can be a virtual device
such as `net_tap` or `af_packet`, or a physical NIC bound to
`vfio-pci`. On an Intel E810 the port runs with hardware flow rules,
hardware timestamps, and hardware IP checksums. Guest memory is mapped
for DMA, so the NIC reads payload straight from guest memory.

The guest command channel is how a guest drives the engine. The guest
creates an ordinary RC queue pair on its ionic device and connects it
to a reserved queue pair number. Each command is a capsule of at most
64 bytes sent on that queue pair. The ABI is `shared/uet_ernic_abi.h`.

libuet_ernic is the guest library. It implements, over libibverbs and
the command channel, the part of the reference `uet_api.h` that the
libfabric provider calls. A build check compiles its header together
with the reference header, so a drifted prototype breaks the build.

The libfabric `uet` provider is the reference provider's own
libfabric glue, built with `CORE=ernic`. In that build it links
libuet_ernic instead of the reference core. An application then uses
only the public libfabric API, needs no raw socket and no privilege,
and its RMA writes go to the engine.

The reference provider on the host is the fourth role the same code
plays. Its raw socket NIC shim runs on a host netdev and talks on the
wire with the engines. That is the interoperability check: two
independent implementations of the wire, one in the device model and
one in the stock provider, exchange real traffic.

## How they fit together

```
  Guest VM                                   Guest VM
  +---------------------------+              +---------------------------+
  | application               |              | application               |
  |   libfabric  ->  uet prov |              |   libfabric  ->  uet prov |
  |                libuet_ernic              |                libuet_ernic
  |   ionic + ionic_rdma      |              |   ionic + ionic_rdma      |
  +------------|--------------+              +------------|--------------+
               | vfio-user, RC queue pair                 |
  +------------|--------------+              +------------|--------------+
  | rocm-ernic instance 1     |              | rocm-ernic instance 2     |
  |   ionic device model      |              |   ionic device model      |
  |   UET engine (SES/PDS/TSS)|              |   UET engine (SES/PDS/TSS)|
  |   wire: TAP or DPDK port  |              |   wire: TAP or DPDK port  |
  +------------|--------------+              +------------|--------------+
               |         real UET frames                  |
               +-------------- Ethernet ------------------+
                                   |
                       host reference provider
                       (raw socket shim, interop)
```

Data moves like this. The application posts an RMA write through
libfabric. The provider glue hands it to libuet_ernic. If the buffer is not
registered yet, the library registers it. Then it sends a WRITE capsule
on the service queue pair. The engine takes the capsule, reads the page list of the region,
and gives the message to the reference SES. PDS splits it into packets
of the Payload MTU, 8 KiB at MTU 9000, and the engine sends each frame
on the wire. On a DPDK port the payload is not copied: the NIC reads
it from guest memory. The peer engine receives the frames, checks the
CRC, places the payload into the target region, and acknowledges. When
the message completes, the engine sends a reply capsule, and
libuet_ernic turns it into a libfabric completion.

## Why this is useful for UET development

You can run real UET without UET hardware. The frames on the wire are
the frames the specification describes, and a capture on the bridge
shows them. Every delivery mode the reference implements runs: RUD,
ROD, RUDI and UUD, with and without TSS.

You can test applications through the API they will ship with. An
application links only libfabric and finds the `uet` provider through
`FI_PROVIDER_PATH`. The same binary runs over the reference core on a
host and over the engine in a guest.

You can check interoperability between two implementations. The engine
and the host-side reference provider exchange traffic in both
directions, and the CI runs those cases. A wire format change that
breaks one side shows up as a failed transfer, not as a silent
difference.

You can exercise the transport under conditions you choose. The
engine's unit test drops packets at a set rate and checks that
retransmission recovers. The reference provider's impairment and
tuning variables still work, because the engine leaves them to you.
Security runs with the provider's static TSS keys.

You can measure at speed. On the Intel E810 with the DPDK wire, one
engine moves a 1 GiB write at 5.7 GiB/s over RUD and 5.1 GiB/s over
RUDI. That is 48 and 43 Gbit/s. A profile of the engine tells you where
the transport spends its time. Those numbers come from the reference
sublayers themselves, so a cost in SES or PDS shows up there before
anyone commits it to silicon.

You can find bugs in the reference. Running the sublayers as firmware
exercises paths the stock provider does not. Phase 2 found a message
that failed part way through and blocked every later RUD message to
the same peer. The throughput work found three more. The receiver's loop slept with
frames waiting. The PDS window was far too small for a fast wire. The
RUD path copied every payload three times. All
of those were fixed in the reference core or in the engine around it.

You can see where the firmware boundary belongs. The engine is the
sublayers plus a thin NIC shim, a DMA translator for guest memory, a
non-blocking neighbor resolver, and a wire. What the engine needed
from the reference, five small hooks, is what a real device firmware
needs too. The same split shows which work a NIC can take over. On the
E810, flow steering, timestamps and IP checksums moved to hardware.
The CRC32C trailer and the placement copy did not, and they are what
limits the engine today.

You can run it all in CI. The unit tests need no VM, no TAP and no
root: two engines in two processes joined by a socketpair. The two-VM
jobs run on a host with KVM and a TAP bridge. If a port on PCI is
present, the DPDK jobs use it as well.

## What it does not do

The engine offers RMA writes and reads only. There is no immediate
data, no messaging, no atomics, and no target-side events, so a target
checks its window instead of waiting for a signal. Peers are IPv4 on
one Ethernet segment. There is one engine per rocm-ernic process,
because the reference keeps its PDS, RUDI and TSS state in global
variables. The engine runs on the thread that serves vfio-user. One engine is
therefore one thread on one queue. Throughput per port scales with
engines, not with flows. TSS runs in software at tens of microseconds
per packet.

## Where the code is

| Part | Where | Build |
| --- | --- | --- |
| rocm-ernic server and the UET engine | `src/rocm_ernic_server.c`, `src/uet_engine.c`, `src/uet_svc.c`, `src/uet_nic_ernic.c` | `cmake -DERNIC_UET=ON -DERNIC_UET_SOURCE_DIR=<uet-ref-prov>` |
| DPDK wire | `src/uet_wire_dpdk.c` | add `-DERNIC_UET_DPDK=ON` |
| Guest command channel ABI | `shared/uet_ernic_abi.h` | included as is by guest code |
| Guest library | `guest/libuet_ernic` | built in the guest against libibverbs |
| Guest workload | `guest/tools/uet_ernic_rma.c` | built in the guest |
| libfabric provider over the engine | uet-ref-prov `prov/`, `CORE=ernic` | `make -C prov ernic ERNIC=<rocm-ernic>` |
| Reference core as the engine's sublayers | uet-ref-prov, `make libuet_verbs.a` | built by the rocm-ernic build |
| Host-side reference provider for interop | uet-ref-prov `prov/`, default core | `make -C prov` |
| Tests and CI jobs | `tests/test_uet_*.c`, `ci/jobs/vm-uet.sh` | `ctest -R uet` |

To start, read `uet.rst` for the engine's options and the two-VM
setup, and `prov/README.md` in the reference provider for the
libfabric side.
