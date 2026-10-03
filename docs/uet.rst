Ultra Ethernet Transport Engine
===============================

With ``--uet``, a rocm-ernic instance runs an Ultra Ethernet
Transport (UET) engine inside the server. The engine is the
UEC reference provider's semantic, packet delivery and
transport security sublayers (SES, PDS and TSS), running as
the emulated NIC's firmware. It has its own IPv4 and MAC
address on the emulated wire, and it sends and receives real
UET frames: Ethernet, IPv4, UDP to port 4793 (or, with
``encap=ip``, IPv4 protocol 253 and an entropy header), the PDS
and SES headers, and a TSS header when security is on. A full
packet carries the largest Payload MTU that fits the wire's MTU:
1 KiB at 1500, 8 KiB at 9000 (see `Packet Size and
Encapsulation`_).

Phases 1 to 4 of the work are done. The engine runs and
moves data between two engines with every delivery mode Slice
A asks for (phase 1). A guest drives it through a command
channel on an ordinary RC queue pair (phase 2). A guest library,
``libuet_ernic``, implements the part of the reference API that
the libfabric ``uet`` provider calls, on top of that channel
(phase 4). Two VMs move data through their engines, with the
guest tool and with the libfabric provider built over
``libuet_ernic``, and a guest interoperates on the wire with
the software provider running on the host (phase 3, see
`Two VMs`_).

.. contents::
   :local:
   :depth: 1

Building
--------

The engine links the reference provider's ``ENABLE_VERBS=1``
build as a static archive, ``libuet_verbs.a``. That build is
meant for device models and has no runtime libfabric
dependency. It also needs four hooks the provider gained for
device models (see `Provider Changes`_), so it needs a
provider tree that has them.

.. code-block:: bash

   cmake -B build -G Ninja \
     -DERNIC_UET=ON \
     -DERNIC_UET_SOURCE_DIR=/path/to/uet-ref-prov
   cmake --build build

Every build runs ``make libuet_verbs.a`` in the provider
tree. That does nothing when the archive is up to date. To
link an archive built elsewhere instead, set
``ERNIC_UET_LIBRARY`` to its path. ``ERNIC_UET`` is ``OFF``
by default. Without it the server still accepts ``--uet``
on the command line, but refuses to start with it.

With ``ERNIC_UET`` on and libfabric's headers installed (it
uses libfabric's types, not the library), the build also makes
the guest library ``guest/libuet_ernic.so`` and the guest tool
``guest/uet_ernic_rma``. Both link only libibverbs.

Starting the Engine
-------------------

.. code-block:: bash

   ./build/rocm-ernic \
     --socket /tmp/vfio-user-rocm-ernic-1.sock \
     --tap ernic1 \
     --uet ip=192.168.200.101

The argument of ``--uet`` is a comma-separated list of
``key=value`` options. Only ``ip=`` is required.

.. list-table::
   :header-rows: 1
   :widths: 14 20 66

   * - Option
     - Default
     - Meaning
   * - ``ip=``
     - (required)
     - The engine's own IPv4 address. It is separate from the
       guest's address, and each instance needs its own.
   * - ``mac=``
     - ``02:55`` and the address
     - The engine's MAC. By default ``02:55`` followed by the
       four bytes of ``ip=``, so ``192.168.200.101`` answers
       ARP as ``02:55:c0:a8:c8:65``.
   * - ``job=``
     - ``1``
     - The JobID the engine's endpoint sends and accepts,
       0..16777215.
   * - ``pid=``
     - ``0``
     - The endpoint's PIDonFEP, 0..4095.
   * - ``index=``
     - ``15``
     - The endpoint's resource index, 0..4095.
   * - ``initiator=``
     - ``16``
     - The SES initiator ID the endpoint sends.
   * - ``pds=``
     - ``pds``
     - ``pds`` is the full packet delivery sublayer (RUD, ROD,
       RUDI and UUD). ``sng`` is the provider's stop-and-go
       ROD, which is its own default but cannot do RUDI.
   * - ``sec=``
     - ``none``
     - Transport security: ``none``, ``direct`` or ``cluster``.
       Needs ``pds=pds``.
   * - ``ssi=``
     - the IP address
     - The TSS source identifier.
   * - ``rto=``
     - provider (5 ms)
     - PDS retransmit timeout, in milliseconds.
   * - ``retries=``
     - provider (5)
     - PDS retransmit limit.
   * - ``mtu=``
     - the TAP's
     - The wire's IP MTU, 576..9000. Without ``--tap``, 1500.
   * - ``payload=``
     - from ``mtu=``
     - The Payload MTU: 1024, 2048, 4096 or 8192. By default
       the largest whose packets fit the MTU.
   * - ``window=``
     - 128, or 512 on a DPDK port
     - Packets in flight per transfer: the PDS window offered to a
       peer, and the RUDI bound. A multiple of 128, up to 32640.
       The wire's queue has to hold a burst of it. A TAP queues
       1000 frames, and a DPDK port's rings hold 4096.
   * - ``encap=``
     - ``udp``
     - ``udp`` puts UET in UDP to ``port=``; ``ip`` puts it
       directly in IP protocol ``proto=``. Frames in either
       form are received.
   * - ``port=``
     - ``4793``
     - The UDP destination port.
   * - ``proto=``
     - ``253``
     - The IP protocol without UDP; not 1, 6 or 17.
   * - ``wire=``
     - ``tap``
     - ``tap`` sends on the TAP of ``--tap``. ``dpdk`` sends on
       a DPDK port, with the ``dpdk-*`` options (see `DPDK
       Wire`_).

A bad option stops the server before the guest attaches:

.. code-block:: console

   $ ./build/rocm-ernic --uet ip=192.168.200.101,sec=server
   Error: uet engine: sec must be none, direct or cluster (got 'server')

A good one is reported at startup, with the MAC that peers
will find by ARP:

.. code-block:: console

   rocm-ernic: UET engine ip 192.168.200.101 mac 02:55:c0:a8:c8:65 \
       job 1 pid 0 index 15 pds pds sec none mtu 9000 payload 8192 \
       encap udp port 4793 ack every 32768 bytes

The MTU, Payload MTU and ACK coalescing in that line are what the
provider settled on.

Without ``--tap`` the engine starts, but it has nowhere to
send, and the startup line says so.

How It Works
------------

Where the engine runs
^^^^^^^^^^^^^^^^^^^^^

The engine runs on the thread that services vfio-user, the
same thread as the rest of the device. The server's main
loop calls it after it moves frames from the TAP, and the
idle check asks it whether it has work before the loop
sleeps. Every access the engine makes to guest memory happens
in those calls. Before a guest attaches, the loop that waits
for one also runs the engine, so it answers ARP from the
moment the server starts.

The reference provider keeps its PDS, RUDI, TSS and
impairment state in global variables and reads its
configuration from the environment. So there is one engine
per server process, and creating it sets environment
variables (see `Configuration`_).

The wire
^^^^^^^^

UET frames travel on the instance's TAP, like the guest's
own Ethernet traffic. They do not use the TCP mesh that the
``tcp`` backend uses between instances.

A wire-side receive filter in ``ionic_eth_emu_poll_rx()``
sees every frame from the TAP before the guest does. It takes
UET frames that are addressed to the engine's IP and MAC, in
either encapsulation (UDP to ``port=``, with a UDP length that
matches the IP length, or IP protocol ``proto=``), and ARP
packets for the engine's IP. Everything else goes to the
guest as before. With the filter registered, the TAP is
drained even when the guest has no receive ring, so the
engine works before the driver loads. Frames for the guest
that arrive then are dropped, as a NIC with no posted buffers
drops them. The engine transmits straight onto the TAP with
``ionic_eth_emu_wire_send()``, without using the guest's
queues.

The engine answers ARP for its own address, and ICMP echo
requests to it. It answers a burst of 16 pings, then one every
10 ms, and drops the rest. Other ICMP to it is dropped. A host
that finds its peers with ``ping``, as the reference provider's
raw socket shim does, gets its reply at once. To reach a peer
it resolves the peer's MAC by ARP, without blocking: the
first operation to an unresolved peer returns ``-EAGAIN``, an
ARP request goes out, and a retry succeeds once the reply has
arrived. Peers must be on the same Ethernet segment. There is
no gateway support yet.

A peer can be the engine itself. Several programs in one guest
share its engine, and so its address, and one may write into
another's region. The engine resolves its own address to its own
MAC, and a frame it sends to that MAC goes straight to its own
receive queue, never to the wire. The provider then plays both
sides, as initiator and as target, over RUDI or RUD.

Guest memory
^^^^^^^^^^^^

A memory region is described as a driver describes one: a
page buffer list (levels 0, 1 or 2) of guest physical
addresses. The provider reads the list and the pages through
a translator that the server supplies. The translator maps
one page at a time with ``vfu_addr_to_sgl()`` and
``vfu_sgl_get()``. For a store it marks the page dirty first.
The store then happens before control returns to
``vfu_run_ctx()``, which is the only place the dirty bitmap
is read, so live migration cannot miss it.

A region the guest registers through the command channel is
an ionic MR, and the datapath keeps the MR's page list in its
own memory, not in guest memory. The engine copies that list
and serves the provider's reads of it from a window of DMA
addresses no guest memory can occupy (``0xffff`` in the top
bits). That copy is what lets the engine cut a region off by
itself, at once, when the guest destroys the MR.

Configuration
^^^^^^^^^^^^^

The provider reads its settings from the environment, some
of them on every packet. So the engine sets these variables
before ``uet_initialize()`` and leaves them set:
``UET_NIC_SHIM=ernic``, ``UET_PDS`` from ``pds=`` (the
provider's own default is stop-and-go, so this is always
set), ``UET_SEC_MODE`` and ``UET_SEC_SSI`` from ``sec=`` and
``ssi=``, and the tuning variables for options that are
given, and the wire format: ``UET_ENCAP``, ``UET_UDP_PORT``,
``UET_IPPROTO`` and, with ``payload=``, ``UET_MAX_PAYLOAD``
(removed otherwise, so the provider derives the payload from
the MTU). It removes ``UET_IMPAIRMENT_SHIM``, because that shim
transmits from a thread of its own. It also removes
``UET_FORCE_RUDI``, ``UET_FORCE_UUD``, ``UET_SEC_SERVER`` and
``UET_SEC_CLIENT_SSI``. It does not touch the other tuning
variables, so the provider's own variables still work for
experiments.

The TSS keys are the static keys compiled into the provider,
the same ones its own test program uses. There is no key
exchange.

Provider Changes
^^^^^^^^^^^^^^^^

The provider needed five small changes and one fix. Its own
build and its ``uet`` test program work as before. Its
``wip-uet-perf`` branch adds the performance work of `Packet
Size and Encapsulation`_.

- ``uet_nic_register_shim()`` lets an application supply its
  own NIC shim. Before, the shim was chosen from a fixed list
  by ``UET_NIC_SHIM``.
- A shim can supply a next-hop resolver that does not block.
  It replaces the ``popen("ip route")``, ``system("ping")``
  and ``SIOCGARP`` sequence, which would stall the vfio-user
  thread and needs a kernel netdev that has the address.
- ``uet_set_dma_translate()`` installs the guest memory
  translator, with a flag for stores. Before, page list
  addresses were cast to pointers.
- ``uet_ep_setopt(UET_OPT_FORCE_RUDI)`` chooses RUDI per
  endpoint. The engine sets it before each post, so the
  choice is per operation. Before, it was
  ``getenv("UET_FORCE_RUDI")`` on every post.
- ``make libuet_verbs.a`` builds the static archive, and it
  does not need a libfabric tree.
- A fix found by phase 2: a message that failed after some of
  its packets were on the wire (a region revoked part way
  through) completed at once, without telling the PDS. Its PDC
  kept it as the active message forever, so every later RUD
  message to the same peer waited behind it and never
  completed. It now ends through the provider's ``ERR`` state,
  which waits for the packets in flight and then tells the PDS.
  The same commit frees the segment and vector copies that a
  recycled receive descriptor leaked, one per RMA read into a
  segment list.

The Guest Command Channel
-------------------------

This is how a guest drives the engine (phase 2). The ABI is
``shared/uet_ernic_abi.h``, which guest code includes as it
is. The server side is ``src/uet_svc.c``, which knows nothing
about rings, and a little glue in ``ionic_datapath.c``.

The service QP
^^^^^^^^^^^^^^

The guest creates an ordinary RC queue pair on its ionic
device and connects it to destination QPN ``0x00e00001``,
using its own GID as the address. Any QPN in ``0x00e0xxxx``
reaches the engine. ``0x00c0xxxx`` belongs to the NVMe-oF
responder and ``0x00d0xxxx`` to the S3 target, so the
design study's ``0x00d0xxxx`` could not be used.

``process_sq_wqe()`` hands every SEND on such a QP to the
channel, next to the NVMe-oF hook. It fetches the capsule
through the WQE's own SGEs with ``dp_gather()``, and the SEND
completes as usual. A service QP is never sent to the TCP
mesh, whatever GID it was given.

Capsules
^^^^^^^^

Every capsule, in either direction, starts with a 16-byte
header: a magic number, the ABI version, an opcode, flags and
a 64-bit cookie that the guest chooses. No capsule is longer
than 64 bytes. All fields are little-endian.

The ABI is at version 2, which adds ``ABORT`` and the group of a
``WRITE`` or ``READ``. A device takes capsules of version 1 and
version 2. ``QUERY`` reports the device's version. The guest
library sends ``QUERY`` as version 1, which every device takes,
and after that the lower of the device's version and its own.

.. list-table::
   :header-rows: 1
   :widths: 22 78

   * - Command
     - What it does
   * - ``QUERY``
     - Returns the engine's address, MAC, JobID, PIDonFEP,
       resource index, initiator ID, MTU, the highest ABI
       version the device speaks, and whether RUDI, TSS and
       ``ABORT`` work.
   * - ``MR_REG``
     - Registers an ionic MR, named by its lkey, with the
       engine. Returns a handle and the 64-bit key peers use.
       Access is remote read, remote write and
       IDEMPOTENT_SAFE.
   * - ``MR_DEREG``
     - Releases a region handle.
   * - ``PEER_ADD``
     - Makes a peer endpoint (IPv4, PIDonFEP, resource index)
       addressable. Returns a handle. ARP runs in the
       background.
   * - ``PEER_REMOVE``
     - Releases a peer handle.
   * - ``WRITE``, ``READ``
     - RMA between a local region (handle and offset) and a
       remote one (key and offset), with a flag that asks for
       RUDI, and a group that ``ABORT`` names it by.
   * - ``ABORT``
     - Takes back the ``WRITE`` and ``READ`` commands of this
       service QP in one group, or all of them, that are not
       answered yet (see `Taking transfers back`_).

The device answers every command with exactly one reply. It
echoes the opcode and the cookie, and it carries a status:
0 or a Linux errno. Most replies come at once. A ``WRITE``
or ``READ`` is answered when it has completed or failed, so
its reply is its completion. A transfer that cannot be posted
yet, because ARP is still running or the engine is busy,
waits in the device for up to 5 s. After that it fails with
``ETIMEDOUT``.

A ``WRITE`` or ``READ`` that asks for RUDI goes to the engine
in segments of at most 256 packets and 512 KiB, with at most
512 packets and 1 MiB of RUDI in the engine at a time across all
transfers: 256 KiB and 512 KiB with 1 KiB payloads, 64 and 128
packets with 8 KiB ones. The packet bounds keep a burst within
a TAP's queue; the byte bounds keep it within what the receiver
works through in a retransmit timeout. With the packet bounds
alone, 4 MiB RUDI writes with 8 KiB payloads retransmitted 190
to 300 of their 512 packets in two VMs. RUDI has no window: the
provider sends every packet of a message at once and
retransmits each unanswered one after the retransmit timeout.
In two VMs, a 4 MiB RUDI write in one message overflowed the
receiving TAP's queue, and the retransmissions came before the
receiver had worked through the first burst: the capture showed
24555 requests and 11941 responses, and the write failed with
``EIO``. RUD transfers go as one message, under the PDS's own
window. A transfer is answered once all its segments are done,
with the first error of any of them.

A reply is delivered as a SEND into the next receive the
guest has posted on the service QP. So the guest must keep a
receive of 64 bytes or more posted for every command in
flight. A reply that finds no receive waits, in order, until
the guest posts one.

A capsule with a bad magic number cannot be answered and is
dropped. Every other problem is a reply: ``EPROTO`` for an
unknown ABI version, ``EOPNOTSUPP`` for an unknown opcode,
``EINVAL`` for a short or malformed command, ``ENOENT`` for
an lkey the guest never registered, and ``EBADF`` for a
handle that is not this QP's.

Addresses are offsets from the start of a region, not virtual
addresses. This is what the libfabric provider uses: it does
not ask for ``FI_MR_VIRT_ADDR``.

When things go away
^^^^^^^^^^^^^^^^^^^

Handles belong to the service QP that created them.

- **DESTROY_MR, LOCAL_INV, a fast-registration key rotation,
  or a re-registration of the same lkey** revokes every engine
  registration of that MR before the admin command returns.
  Peers stop finding it, and the engine's copy of the page
  list stops resolving. So a transfer that still needs the
  pages fails with ``ECANCELED`` instead of touching memory
  the guest may already be reusing. The handle stays
  allocated, but dead, until the guest sends ``MR_DEREG``.
- **DESTROY_QP of a service QP** releases all of its handles.
  Its transfers that are still waiting are dropped, and those
  in the engine are taken out of it, as ``ABORT`` takes them.
  Nothing of them goes on the wire again, and no reply is
  sent. A reply never lands on a later QP that gets the same
  number. With ``pds=sng`` the engine cannot take them out;
  they run to their end, and their replies are discarded.
- The provider descriptor of a revoked region is kept,
  disabled, for a quarantine of 6 s before it can be reused.
  A partly received message keeps a pointer to the descriptor
  until it completes or goes idle (5 s), and the quarantine
  stops that pointer from reaching a new region.
- A peer handle that is released while transfers use it is
  removed once they finish.

Taking transfers back
^^^^^^^^^^^^^^^^^^^^^

A guest gives each ``WRITE`` and ``READ`` a 32-bit group. The
guest library uses one group for each endpoint. ``ABORT`` names
a group, or all transfers of the QP with ``UET_ERNIC_ABORT_ALL``.

The device answers each transfer it takes back first, with
``ECANCELED``, and then the ``ABORT``, with the number it took
back. Replies go out in order on a QP, so the guest has all of
them when it sees the ``ABORT`` reply. From then on, no packet
of those transfers goes on the wire again. The device drops the
segments that wait to be posted, posts no new ones, and takes the
ones in the engine out of the provider: their packets are
dropped, and a late response to one is ignored. A transfer that
finished before the ``ABORT`` is answered as usual. The
``ABORT`` never waits for a peer, so it is answered at once.

A RUDI transfer is taken back alone. A RUD transfer is part of a
packet delivery context (PDC) that it shares with other RUD
transfers to the same peer. If it has packets that the peer has
not acknowledged, taking them back leaves holes in the PDC's
sequence numbers. So the PDC is closed with the peer, and the
other transfers that still have packets on it fail with an error.
The next transfer opens a new PDC.

The engine needed one more hook from the provider:
``uet_ep_abort_op()`` drops one operation of an endpoint, as
``uet_ep_abort()`` drops all of them. It is on the provider's
``wip-uet-rigor`` branch. With ``pds=sng`` the provider cannot
drop what it has sent, so the device answers ``ABORT`` with
``EOPNOTSUPP`` and does not report ``UET_ERNIC_CAP_ABORT``.

The Guest Library
-----------------

``libuet_ernic`` (``guest/libuet_ernic``) is phase 4. It
implements, over libibverbs and the command channel, the 21
functions of the reference's ``uet_api.h`` that the libfabric
``uet`` provider calls, plus ``uet_read`` and ``uet_cq_close``.
All of them have the reference's ``ENABLE_VERBS=0`` signatures.
``abi_check.c`` compiles its header together with the
reference's ``uet_api.h``, so a prototype or constant that
drifts breaks the build. So the provider can link this library
instead of the reference library and run unchanged.

``uet_initialize()`` opens the device named by
``UET_ERNIC_DEVICE``, or else the first ionic one: one whose
name starts with ``ionic``, or, because the guest image's udev
rule renames it ``rocm-rdma-ernic0``, one whose PCI function
has Pensando's vendor ID 0x1dd8 (``uet_ernic_device_match()``).
It never falls back to another kind of device. It creates the service QP, connects it, posts
64 receives and sends ``QUERY``. Commands that the engine
answers at once are waited for. Each ``WRITE`` and ``READ``
reply becomes an entry in the completion queue of the
endpoint that posted it, in the format the queue was bound
with. Errors appear through ``-FI_EAVAIL`` and
``uet_cq_readerr()``, as in the reference.

These are the differences from the reference library:

- One engine endpoint serves every endpoint opened here, so
  they share its address and JobID.
- RMA writes and reads only. No immediate data, no messages,
  no atomics, no target-side events.
- A local buffer passed without a region, as the libfabric
  provider passes every source buffer, is registered on
  demand: the 2 MiB-aligned window around it, clipped to its
  mapping, is registered with ibverbs and the engine once and
  kept, up to 16 of them, evicted least recently used.
  ``UET_ERNIC_MR_CACHE=0`` drops each one when its transfers
  are done instead. As with any registration cache, a buffer
  must not be written from after it is unmapped and mapped
  again at the same address while the old registration is
  cached.
- ``uet_ep_abort()`` sends one ``ABORT`` for the endpoint's
  group and waits for its reply, which comes at once. The
  endpoint reports no completion for the transfers taken back,
  as the reference does. So ``fi_close()`` on the libfabric
  provider discards the endpoint's writes, and none of them
  lands later. A device that cannot take transfers back (one
  older than ABI version 2, or one with ``pds=sng``) makes
  ``uet_ep_abort()`` return ``-FI_ENOSYS``. The provider then
  waits up to 10 s for the writes, as it does with the
  reference's stop-and-go PDS.
- ``uet_mr_disable()`` keeps the region reachable by peers
  until ``uet_mr_close()``. Re-enabling it would need a new
  key, and callers keep the old one.
- IPv4 peers only.

``guest/uet_ernic_rma`` is the phase 3 workload. A target
registers a window and sends its address and key to an
initiator over TCP on the guests' own network. The initiator
writes a known pattern over RUDI (``-r``) or RUD, reads the
start back, and the target compares every byte.

The library is tested against a fake libibverbs (see below)
and, in two VMs, on the ionic kernel driver and rdma-core's
ionic provider (see `Two VMs`_).

What Works
----------

The ``uet-engine-unit`` test runs Slice A. It needs no VM, no
TAP and no root. It forks two processes, because of the
provider's global state. Each process runs an engine. The two
engines are joined by a ``SOCK_SEQPACKET`` socketpair that
carries their Ethernet frames. Each process has a window of
"guest memory" at guest physical address 4 GiB. The window is
identity-mapped: a guest physical address minus 4 GiB is the
offset in the window. Each process registers its region as a
level 1 page list with the pages in reverse order, and the
list itself is in the window. Because of the 4 GiB base, a
provider that used a guest address without translating it
would fault.

In every case the initiator writes 1 MiB into the target's
region, at an offset that is not page aligned. The target
then compares every byte of the region with what should be
there, including the bytes on each side of the write. The
test also decodes every frame each side transmits, so each
case checks what really crossed the wire.

.. list-table::
   :header-rows: 1
   :widths: 22 78

   * - Case
     - What it checks
   * - ``rudi-1MiB``
     - A RUDI write into an ``IDEMPOTENT_SAFE`` window: 1024
       RUDI requests, 1024 RUDI responses, no RUD on the wire.
   * - ``rud-1MiB``
     - The same write over RUD: 1024 RUD requests,
       acknowledged.
   * - ``rud-drop500``
     - RUD with ``UET_PKT_DROP_THRESH=500``, so 5% of PDS
       transmits are dropped before the wire. Retransmissions
       carry the RETX flag and the data still compares.
   * - ``tss-cluster-rud``
     - RUD with ``UET_SEC_MODE=cluster``. Every UET frame in
       both directions starts with a TSS header, and the
       payload cannot be found on the wire.
   * - ``tss-cluster-rudi``
     - The same, over RUDI.
   * - ``rudi-wireloss2pct``
     - RUDI with 2% of frames lost on the test's wire.
       ``UET_PKT_DROP_THRESH`` only acts on the RUD/ROD path,
       so it cannot force RUDI retransmissions. This case
       does that instead.
   * - ``rudi-1MiB-ip``, ``rud-1MiB-ip``,
       ``tss-cluster-rud-ip``
     - The same with ``encap=ip``: every frame in IP protocol
       253, none in UDP.
   * - ``rudi-jumbo``, ``rud-jumbo``, ``rud-jumbo-ip``,
       ``tss-cluster-rudi-jumbo``, ``rud-drop500-jumbo``
     - At ``mtu=9000``: a Payload MTU of 8192, so 128 requests
       for the megabyte, the longest frame within 9014 bytes.
   * - ``sng-1MiB``, ``sng-1MiB-ip``
     - The write over the stop-and-go PDS (``pds=sng``), in
       both encapsulations.
   * - ``loopback-rudi``, ``loopback-rud``,
       ``loopback-rudi-jumbo``
     - One engine writes from one part of its region to another,
       its own address as the peer. The copy compares, the bytes
       around it are untouched, and no UET frame reaches the wire.
   * - ``abort-rudi``, ``abort-rud``
     - Two writes of half a megabyte each while the wire loses
       every IP frame. The first is taken back, the wire comes
       back, and the second lands. The first never completes,
       nothing of it reaches the target, and no request goes
       on the wire once the second is done. In ``abort-rud`` a
       first write sets up the PDC, so taking the write back
       closes a live PDC.

The cases without ``-ip`` run over UDP, and the cases without
``-jumbo`` at an MTU of 1500 (1 KiB payloads). Every case checks
both engines' MTU and Payload MTU, the encapsulation of every
frame, and that the longest frame carries a full payload.

Each case also checks that the target's MAC was found by
ARP, that both sides reached their regions only through the
translator, and that no translation failed.

One run, on a Debug build with AddressSanitizer:

.. code-block:: text

   case rudi-1MiB: 1048576 bytes in 6.5 ms (153.3 MiB/s), 0 wrong
     initiator 1024 RUDI req; target 1024 RUDI resp
   case rud-1MiB: 1048576 bytes in 6.1 ms (163.9 MiB/s), 0 wrong
     initiator 1024 RUD req; target 184 ACK
   case rud-drop500: 1048576 bytes in 181.0 ms (5.5 MiB/s), 0 wrong
     initiator 1771 RUD req (812 RETX); target 699 ACK, 212 NACK
   case tss-cluster-rud: 1048576 bytes in 257.5 ms (3.9 MiB/s), 0 wrong
     1024 + 184 frames, all TSS-wrapped
   case tss-cluster-rudi: 1048576 bytes in 271.8 ms (3.7 MiB/s), 0 wrong
     1024 + 1024 frames, all TSS-wrapped
   case rudi-wireloss2pct: 1048576 bytes in 25.3 ms (39.5 MiB/s), 0 wrong
     initiator 1063 RUDI req for 1024 packets

The ``uet-ci`` test starts the server with valid ``--uet``
options and checks the startup line and a clean shutdown. It
also checks that 20 bad options are refused before the
server creates its socket.

The ``uet-datapath-unit`` test covers phase 2 through the real
ionic rings. Two processes each run a real ionic datapath
(``ionic_datapath.c`` is included, as in
``test_ionic_cq_arm.c``) and a real engine, joined by a
socketpair. Guest memory is a byte array behind fake vfio-user
DMA calls. Each process plays its guest's driver: it lays out
a CQ, an RC service QP and MRs with page tables, writes
command capsules into SQ WQEs, rings the doorbells, and reads
replies out of the receives they landed in. It checks:

- the capsule errors listed above, and a reply that has to
  wait for a receive to be posted;
- ``QUERY``, ``MR_REG`` of a paged MR and of a contiguous one,
  and ``PEER_ADD``;
- a RUDI and a RUD ``WRITE`` of 512 KiB each, both in flight,
  into a remote MR window, byte-compared by the target, and a
  RUD and a RUDI ``READ`` back;
- a ``WRITE`` whose MR is destroyed while it is in flight:
  ``ECANCELED``, and a dead handle;
- the service QP destroyed while a ``WRITE`` is in flight,
  and its number reused: no stale reply, and the old handles
  are gone;
- a ``WRITE`` into a window whose owner destroyed its service
  QP: ``EIO``, and the window is untouched;
- ``ABORT`` with unknown flags or a short capsule, ``ABORT`` of
  a group with nothing in flight, and versions 0, 1 and 3;
- two RUDI ``WRITE`` commands in two groups while the wire
  loses every frame, and ``ABORT`` of one group: its ``WRITE``
  is answered ``ECANCELED`` ahead of the ``ABORT``, the other
  lands once the wire is back, and nothing of the first ever
  does;
- nothing left in the channel or the engine at the end.

The ``uet-guest-lib-unit`` test covers phase 4. It runs two
guests and two devices, four processes. Each guest runs
``libuet_ernic`` over a fake libibverbs. Each device is
``tests/uet_fake_device.c``, which runs the real channel and
engine behind a socket that stands in for the rings. A
guest's memory is a memfd that its device maps too. The
guests call the library as the provider does, write over RUDI
and RUD, read back, and check the calls the library refuses
and an error completion. Then two endpoints each write while
the device loses every frame, and ``uet_ep_abort()`` aborts the
first. It reports no completion and nothing of it lands; the
other endpoint's write completes. Afterwards each device must
hold nothing.

One run, on a Debug build with AddressSanitizer:

.. code-block:: text

   case svc-channel: capsules through ionic rings, two engines
     2 x 512 KiB WRITE (RUDI + RUD) in 21.7 ms, 2 x 32 KiB READ
     back; target compared 1048579 bytes, 0 wrong
     WRITE from an MR destroyed mid-flight: Operation canceled
     WRITE into a window whose service QP was destroyed:
     Input/output error
   case guest-lib: libuet_ernic over fake verbs, real channel
     2 x 512 KiB uet_write (RUDI + RUD) in 21.8 ms, 32 KiB
     uet_read back, 1 error completion; 11 capsules, 11 replies
     device A: left: 0 regions 0 peers 0 ops
     device B: left: 0 regions 0 peers 0 ops

Two VMs
-------

Phase 3 runs the engine for real: two rocm-ernic instances,
each with ``--tap`` on one Linux bridge and its own
``--uet ip=``, and a VM on each. The guests are the CI image
(Ubuntu 26.04, kernel 7.2.3, the ionic DKMS modules and
rdma-core 61 from guest setup). Guest RC traffic still goes
over the TCP mesh; UET frames go over the TAPs and the bridge.

``ci/jobs/vm-uet.sh`` is the lane. It copies the guest-side
sources into both guests and builds them there:
``libuet_ernic.so``, ``uet_ernic_rma`` and, from the
reference tree in ``UET_PROV_DIR``, the libfabric ``uet``
provider over ``libuet_ernic`` (``make -C prov ernic``) and its
``test_rma``. It installs ``libfabric-dev`` and
``libfabric-bin`` in the guests if they are missing. Then it
runs, each as its own result record:

- ``uet_ernic_rma``, 4 MiB, from VM 1 to VM 2 and back, over
  RUDI and over RUD, with a 64 KiB read back;
- ``fi_info -p uet`` in each guest;
- ``test_rma`` writes of 4 MiB through the provider, both
  ways, one over RUD (``FI_UET_RUDI=0``), and two writer
  processes into one 8 MiB window;
- with ``interop`` in ``UET_CHECKS``, the software provider on
  the host against each guest, both ways (see `Interop with
  the software provider`_).

With ``sudo -n tcpdump`` allowed, every transfer is captured on
the bridge (``ip proto 253 or udp port 4793 or arp``, with the
``proto=`` and ``port=`` of ``ERNIC_UET``) and summarised by
``scripts/uet-pcap-summary.py``. A check fails unless the
capture shows UET frames both ways between the two engines and
nowhere else, all in the encapsulation ``ERNIC_UET`` asks for,
with the expected requests (``RUDI_REQ`` or ``RUD_REQ``) and the
payload in the clear, the largest of them carrying a full
Payload MTU, or, with ``sec=``, every frame wrapped in TSS and
the payload nowhere in the clear.

To run it:

.. code-block:: bash

   export CI_BUILD_DIR=$PWD/build-uet   # -DERNIC_UET=ON
   export ERNIC_UET='ip=192.168.200.10%i'
   export UET_PROV_DIR=/path/to/uet-ref-prov   # prov/ has CORE=ernic
   bash ci/jobs/vm-up.sh
   bash ci/jobs/vm-functional.sh   # guest setup
   bash ci/jobs/vm-uet.sh

The engines take their MTU from the TAPs, which
``ci/runner/install-runner.sh`` creates with ``CI_TAP_MTU``
(9000 by default, so 8 KiB payloads); ``vm-up.sh`` and
``ci/doctor.sh`` warn when the bridge or a TAP has another
MTU. To run with the standard MTU instead:

.. code-block:: bash

   for d in ernic-ci-br0 ernic-ci-tap1 ernic-ci-tap2; do
       sudo ip link set "$d" mtu 1500
   done
   export CI_TAP_MTU=1500

For the TSS pass, restart the instances with
``ERNIC_UET='ip=192.168.200.10%i,sec=cluster,rto=1000'``:
``CI_KEEP_OVERLAYS=true bash ci/jobs/vm-down.sh``, then
``vm-up.sh``, ``vm-functional.sh`` and ``vm-uet.sh`` again. The
overlays keep the guest setup, so it takes about 30 s.

Results
^^^^^^^

These are the phase 3 numbers: 1 KiB payloads directly over IP
at an MTU of 1500, with the provider core built without
optimization. `Packet Size and Encapsulation`_ has the numbers
with 8 KiB payloads over UDP.

One run, KVM, 4 vCPUs and 8 GiB per guest, Release build of
the server, every check passed. Rates are the tools' own, for
4 MiB, from VM 1 to VM 2 and from VM 2 to VM 1:

.. list-table::
   :header-rows: 1
   :widths: 28 22 50

   * - Case
     - sec=none
     - On the wire, one way (sec=none)
   * - ``uet_ernic_rma`` RUDI
     - 163, 150 MiB/s
     - 4160 ``RUDI_REQ``, 4160 ``RUDI_RESP``: the write and
       the read, no retransmission
   * - ``uet_ernic_rma`` RUD
     - 180, 179 MiB/s
     - 4160 ``RUD_REQ`` and 64 ``ACK`` out, 380 ``ACK`` and
       64 ``RUD_REQ`` back (the read)
   * - ``test_rma`` RUDI
     - 152, 163 MiB/s
     - 4096 ``RUDI_REQ``, 4096 ``RUDI_RESP``
   * - ``test_rma`` RUD (1 to 2)
     - 184 MiB/s
     - 4096 ``RUD_REQ``, 256 ``ACK``
   * - ``test_rma``, two writers in VM 1
     - 75 and 78 MiB/s
     - 8818 ``RUDI_REQ`` for 8192 packets

With ``sec=cluster,rto=1000`` every frame both ways starts with
a TSS header, the payload is never in the clear, and the rates
are 3.7 to 4.0 MiB/s for one writer and 1.9 and 2.0 MiB/s for
two. That is the provider's software AES-GCM, which the engine
runs on its one thread.

Interop with the software provider
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The engine and the reference provider's software path speak
the same protocol, so a guest can exchange UET with a process
on the host. Give the bridge an address in the engines' subnet,
build the provider with the reference core, and add the checks:

.. code-block:: bash

   sudo ip addr add 192.168.200.250/24 dev ernic-ci-br0
   make -C /path/to/uet-ref-prov/prov   # CORE=ref
   UET_HOST_PROV_DIR=/path/to/uet-ref-prov/prov \
   UET_CHECKS="rma prov interop" bash ci/jobs/vm-uet.sh

The host's ``test_rma`` runs the raw socket NIC shim on the
bridge, with ``CAP_NET_RAW`` from ``sudo -n setpriv``. It writes
4 MiB into each guest's window, and each guest writes 4 MiB into
a window on the host. All four passed with ``sec=none`` (4096
``RUDI_REQ`` and 4096 ``RUDI_RESP`` each) and with
``sec=cluster`` (all TSS; the host's TSS counted 4096 packets
authenticated each way). Guests wrote to the host at
217 and 218 MiB/s, the host to the guests at 106 and 110 MiB/s
(3.7 to 3.9 MiB/s with TSS). The host's first write to a
guest took about 10 s longer then, because the reference
provider resolved the next hop with ``ping``, and the engine
answered ARP but not ICMP. The engine now answers ``ping``.

Packet Size and Encapsulation
-----------------------------

UEC 1.0.1 runs UET over UDP, destination port 4793 with the
entropy in the source port and a zero checksum, or
experimentally directly over IP (3.2.5, 3.5.10.1, Table 3-28).
Its Payload MTU, the payload of a full packet, is 1024, 2048,
4096 or 8192 bytes, the same on every FEP, and must leave the
packet within the path's MTU (3.4.1.11). Phase 3 sent IP
protocol 253 with 1024-byte payloads whatever the wire, which on
a jumbo frame link is eight times the packets the data needs.
Every packet costs a TAP ``write()`` or ``read()``, a parse, a
PDS lookup, timers and, on receive, a guest page translation.

What changed, in the engine and in the provider (``uet-ref-prov``
branch ``wip-uet-perf``):

- UET goes in UDP to port 4793 by default (``encap=``,
  ``port=``, ``proto=``). Both forms are received. The
  provider's ``UET_UDP_PORT`` was 49150; it is 4793.
- The Payload MTU follows the MTU: the largest of the four
  that leaves 160 bytes of headers (IPv6, UDP, TSS with an SSI,
  a RUD request, the SES standard header with its rendezvous
  extension, the ICV) within it. That is 1024 at 1500 and 8192
  at 9000. The engine's MTU is its TAP's unless ``mtu=`` says
  otherwise. Every peer must use the same Payload MTU, so give
  the TAPs, the bridge and the host's interfaces the same MTU.
- ACK coalescing counts bytes, so the trigger is now four
  payloads (16 KiB up to 4 KiB payloads, and 32 KiB, the most
  the specification requires, at 8 KiB), and the minimum per
  packet a sixteenth of it.
- The command channel bounds RUDI in packets and in bytes (see
  `Capsules`_).
- The provider core is built at ``-O2 -g`` (its Makefile set
  no ``-O``), and computes the CRC32C of every packet with the
  CPU's CRC32 instruction, three streams at a time, instead of
  a table lookup per byte.
- The libfabric provider's write segments are 16 packets of the
  Payload MTU (``FI_UET_ENCAP`` and ``FI_UET_MAX_PAYLOAD`` set
  the core's encapsulation and Payload MTU).

Work per byte, from callgrind: instructions the engine executes
per byte of a 1 MiB RUD write, at the target and at the
initiator, counting only the ``uet_engine_*`` calls the test
makes. Unlike a rate, this does not move with the load on the
host. The table CRC was 57 to 66 percent of it after ``-O2``.

.. list-table::
   :header-rows: 1
   :widths: 60 40

   * - Build
     - Instructions per byte
   * - Provider ``-O0``, server Debug, 1 KiB over IP
     - 35.7 + 31.4
   * - Provider ``-O2``, server RelWithDebInfo, 1 KiB over IP
     - 15.1 + 13.1
   * - and the CRC32 instruction
     - 8.1 + 6.6
   * - and UDP
     - 7.7 + 6.1
   * - and 8 KiB payloads (``mtu=9000``)
     - 4.1 + 2.4

To measure it:

.. code-block:: bash

   cmake -B build-perf -G Ninja -DCMAKE_BUILD_TYPE=RelWithDebInfo \
     -DERNIC_UET=ON -DERNIC_UET_SOURCE_DIR=/path/to/uet-ref-prov \
     -DERNIC_UNIT_TEST_SANITIZERS=OFF
   cmake --build build-perf
   GLIBC_TUNABLES=glibc.cpu.x86_rep_stosb_threshold=100000000:glibc.cpu.x86_rep_movsb_threshold=100000000 \
   UET_ENGINE_TEST_RTO_MS=10000 \
     valgrind --tool=callgrind --trace-children=yes \
     --collect-atstart=no --toggle-collect=uet_engine_poll \
     --toggle-collect=uet_engine_rx_frame \
     --toggle-collect=uet_engine_post_write \
     --toggle-collect=uet_engine_poll_comp --toggle-collect=wire_tx \
     build-perf/tests/test_uet_engine rud-jumbo
   callgrind_annotate callgrind.out.<pid>

The tunables make glibc copy and clear with vector loops rather
than ``rep movsb`` and ``rep stosb``, which callgrind counts as
one instruction per byte. ``UET_ENGINE_TEST_RTO_MS`` keeps the
slowed-down engines from retransmitting, and
``UET_ENGINE_TEST_LEN`` changes the 1 MiB.

In two VMs, as in `Results`_ (KVM, 4 vCPUs and 8 GiB per guest),
with ``vm-uet.sh`` and the interop checks, every check passed.
Rates are MiB/s for 4 MiB, from VM 1 to VM 2 and back. The host
is shared, and its load average (in brackets) moves the rates by
a factor of two or more, so these are from the quietest runs:

.. list-table::
   :header-rows: 1
   :widths: 22 13 13 13 13 13 13

   * - Build, payload, encapsulation
     - ``uet_ernic_rma`` RUDI
     - ``uet_ernic_rma`` RUD
     - ``test_rma`` RUDI
     - host to guest
     - guest to host
     - packets
   * - ``-O0``, 1 KiB, IP [13]
     - 142, 154
     - 158, 170
     - 130, 133
     - 96, 95
     - 162, 189
     - 4096
   * - ``-O2``, 1 KiB, IP [33]
     - 147, 153
     - 173, 182
     - 144
     - 103, 100
     - 169, 183
     - 4096
   * - ``-O2``, CRC32, 1 KiB, IP [20-34]
     - 183, 191
     - 240, 244
     - 205, 185
     - 118, 125
     - 236, 238
     - 4096
   * - ``-O2``, CRC32, 8 KiB, UDP [13]
     - 515, 806
     - 791, 722
     - 540, 490
     - 498, 443
     - 737, 854
     - 512

"packets" is the requests that carry a 4 MiB write. With 8 KiB
payloads no request was retransmitted; two writers into one
window ran at 396 and 450 MiB/s, and ``test_rma`` over RUD at
599. The software provider alone, between network namespaces
(``prov/run_tests.sh`` with ``UETFI_TEST_MTU=9000``), writes
1 MiB at about 900 MiB/s instead of 230.

To run the two passes, jumbo frames over UDP and the standard
MTU over IP protocol 253:

.. code-block:: bash

   # MTU 9000, UDP (the defaults)
   export ERNIC_UET='ip=192.168.200.10%i'
   bash ci/jobs/vm-up.sh && bash ci/jobs/vm-functional.sh
   UET_HOST_PROV_DIR=/path/to/uet-ref-prov/prov \
   UET_CHECKS="rma prov interop" bash ci/jobs/vm-uet.sh

   # MTU 1500, IP protocol 253
   CI_KEEP_OVERLAYS=true bash ci/jobs/vm-down.sh
   for d in ernic-ci-br0 ernic-ci-tap1 ernic-ci-tap2; do
       sudo ip link set "$d" mtu 1500
   done
   export CI_TAP_MTU=1500 ERNIC_UET='ip=192.168.200.10%i,encap=ip'
   bash ci/jobs/vm-up.sh && bash ci/jobs/vm-functional.sh
   UET_HOST_PROV_DIR=/path/to/uet-ref-prov/prov \
   UET_CHECKS="rma prov interop" bash ci/jobs/vm-uet.sh

DPDK Wire
---------

With ``wire=dpdk``, the engine sends and receives on a DPDK port
instead of the TAP. The TAP stays the guest's Ethernet. The server
polls the port from its main loop, in bursts of up to 64 frames. A
received frame stays in its mbuf until the provider reads it. The
backend is ``src/uet_wire_dpdk.c``.

Each offload has a capability check and a software fallback. The
startup line names the path that each offload took:

.. code-block:: console

   rocm-ernic: UET wire dpdk net_af_packet0 (vdev): flow sw filter \
       (UDP rule: Function not implemented); rss off, 1 queue; \
       tx extbuf zero-copy; rx split off; dma memcpy; ts rx hw tx sw; \
       ipv4 csum tx sw rx sw; udp csum none (UET sends 0); \
       mac promisc; guest mem by VA, no device needs it mapped

Building the DPDK Wire
^^^^^^^^^^^^^^^^^^^^^^

The default build does not need DPDK. To build the DPDK wire,
install DPDK 24.11 and turn on ``ERNIC_UET_DPDK``:

.. code-block:: bash

   sudo dnf install dpdk-devel dpdk-tools
   cmake -B build-dpdk -G Ninja -DCMAKE_BUILD_TYPE=RelWithDebInfo \
     -DERNIC_UET=ON -DERNIC_UET_DPDK=ON \
     -DERNIC_UET_SOURCE_DIR=/path/to/uet-ref-prov
   cmake --build build-dpdk
   ctest --test-dir build-dpdk -R uet-dpdk

The two tests need no privileges and no hugepages.
``uet-dpdk-unit`` runs two engines in two processes, joined by
``net_memif``. ``uet-dpdk-map-unit`` checks the guest memory
mapping on ``net_ring`` loopback ports (see `Guest Memory on PCI`_).

DPDK Options
^^^^^^^^^^^^

In ``--uet``, a ``;`` stands for a ``,`` in ``dpdk-dev=`` and
``dpdk-dma=``. In ``dpdk-eal=``, a ``;`` separates the arguments.

.. list-table::
   :header-rows: 1
   :widths: 18 14 68

   * - Option
     - Default
     - Meaning
   * - ``dpdk-dev=``
     - (required)
     - The port: the devargs of a vdev, for example
       ``net_tap0;iface=uet1``, or a PCI address, for example
       ``0000:c1:00.0``.
   * - ``dpdk-dma=``
     - none
     - A dmadev that places received payload in guest memory:
       ``dma_skeleton``, or a PCI address.
   * - ``dpdk-eal=``
     - none
     - More EAL arguments.
   * - ``dpdk-queues=``
     - ``1``
     - Receive and transmit queue pairs, 1..16.
   * - ``dpdk-map=``
     - ``auto``
     - Map guest memory for the devices on a bus (``auto``), for
       every device (``on``), or for none (``off``). See
       `Guest Memory on PCI`_.
   * - ``dpdk-split=``
     - ``off``
     - ``on`` asks for receive buffer split.

The backend starts the EAL with one lcore, the server's thread. If
every device is a vdev, it adds ``--no-huge -m 512 --no-shconf
--no-pci``. If a device is on PCI, it adds ``--in-memory``. Then the
devices DMA from hugepages, and a second engine can run beside the
first without a ``--file-prefix``.

Offloads
^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 18 18 32 32

   * - Offload
     - Fallback
     - On the virtual devices
     - Hardware that runs it
   * - Flow steering. ``rte_flow`` rules send UDP to port 4793,
       IP protocol 253, ICMP to the engine's address and ARP to
       the engine's queues. If all four rules validate, the port
       is isolated, and other frames stay with the kernel.
     - The engine's filter sees every frame and gives the
       frames that are not UET to the guest.
     - ``net_tap``: rules as TC filters, isolated. ``af_packet``,
       ``memif`` and ``ring``: the fallback.
     - ConnectX-6 and ConnectX-7 (mlx5, isolated). E810 (ice):
       rules without isolation.
   * - RSS over the UDP source port, which carries the entropy.
     - One queue.
     - ``net_tap``: RSS, but its flow rules cannot carry an RSS
       action, so UET goes to queue 0. The others: the fallback.
     - ConnectX-6 and ConnectX-7, E810.
   * - Zero-copy transmit. The payload goes out as an external
       buffer in guest memory.
     - One mbuf, copied.
     - ``net_tap``, ``af_packet``, ``memif`` and ``ring``. The
       PMD copies the payload in software.
     - Any NIC with multi-segment transmit. On PCI, only from
       DMA-mapped guest memory.
   * - Receive buffer split, off by default. The engine gathers
       a split frame into one buffer, and that costs a copy.
     - One buffer per frame.
     - None of the virtual PMDs.
     - ConnectX-6 and ConnectX-7 (by length), E810 (by protocol,
       after the UDP header).
   * - Payload placement in guest memory by a dmadev.
     - ``memcpy()``.
     - ``dma_skeleton``, a thread that calls ``memcpy()``.
     - Intel DSA (``dma_idxd``). See `Guest Memory on PCI`_.
   * - Receive timestamps.
     - The host clock, once per burst.
     - ``af_packet``, from the kernel.
     - ConnectX-6 and ConnectX-7, E810.
   * - Transmit timestamps.
     - The host clock.
     - None.
     - IEEE 1588 timesync only.
   * - IPv4 header checksum.
     - Computed in software.
     - ``net_tap``. The PMD computes it in software.
     - All.

UET sends a zero UDP checksum, and receivers ignore it (UEC 1.0.1,
3.5.10.1). So there is no UDP checksum to offload. The PDS does not
use the timestamps yet. The stats count them, and each received
frame carries one: ``ts_ns`` and ``hw_ts`` in ``struct
uet_wire_dpdk_frame``. Congestion control can take them from there.

Guest Memory on PCI
^^^^^^^^^^^^^^^^^^^

A port or a dmadev on PCI reaches memory through the IOMMU. The EAL
maps its own memory in the VFIO container. The server maps guest
memory from vfio-user, and the IOMMU does not know about it.
Zero-copy transmit and dmadev placement use guest memory directly,
so the backend maps it for the device.

The server gives each vfio-user DMA region to the backend when
vfio-user adds it, and again before vfio-user removes it. For each
device on a bus, the backend does these steps:

1. It registers the region with ``rte_extmem_register()``.
2. It maps the region with ``rte_dev_dma_map()``. The IOVA is the
   virtual address.
3. At removal, it waits until the port gives back every frame
   attached to guest memory. It flushes, calls
   ``rte_eth_tx_done_cleanup()``, and after 100 ms stops and starts
   the transmit queue.
4. It unmaps and unregisters the region.

A port and a dmadev on PCI share one VFIO container, so one mapping
serves both. If a mapping fails, the payload in that region goes out
copied, and placement into it is a ``memcpy()``. Read-only regions
and regions beyond 32 also take the copy path. Virtual devices reach
memory by its virtual address, and need no mapping. With
``dpdk-map=on``, the backend maps for virtual devices too. On a
vdev, ``rte_dev_dma_map()`` does nothing, so this runs the path
without hardware.

Each region gets a log line, and the stats at exit count the
mappings, the copies and the waits:

.. code-block:: console

   rocm-ernic: UET wire: guest memory iova 0x100000000+0x180000000 \
       at 0x7fb3a00c0000: DMA-mapped for the port and the dmadev
   rocm-ernic: UET wire: guest memory iova 0xc0000+0xb000 \
       at 0x7fb5ae3e3000: not mapped (read-only): payload in it is copied
   rocm-ernic: UET wire guest mem: 11 regions DMA-mapped, 4 not \
       (4 mapping failures); copied as not mapped: tx 0 frames, \
       2080 placements; removals waited 0 times (0 timed out, \
       0 queue restarts)

The 2080 placements in that line come from the provider. It copies
each received frame into a buffer of its own, from ``calloc()``, in
``uet_pds_sec_rx_pkt()``. Then it places the payload from that
buffer. A dmadev on a bus cannot reach the buffer, so the backend
uses ``memcpy()``. The dmadev becomes useful when the provider
places the payload from the frame in its mbuf.

Two VMs on Virtual Devices
^^^^^^^^^^^^^^^^^^^^^^^^^^

``net_tap`` and ``af_packet`` need ``CAP_NET_ADMIN`` and
``CAP_NET_RAW``. The launcher wrapper ``ci/uet-dpdk-launcher`` runs
each instance as your user with these two capabilities, through
``sudo -n setpriv``. It also puts each ``net_tap`` interface on the
CI bridge.

To run the checks with ``net_tap``:

.. code-block:: bash

   export CI_BUILD_DIR=$PWD/build-dpdk
   export UET_PROV_DIR=/path/to/uet-ref-prov
   export ERNIC_LAUNCHER=$PWD/ci/uet-dpdk-launcher
   export ERNIC_UET='ip=192.168.200.10%i,mtu=9000,wire=dpdk,dpdk-dev=net_tap0;iface=ernic-dtap%i'
   bash ci/jobs/vm-up.sh && bash ci/jobs/vm-functional.sh
   UET_HOST_PROV_DIR=/path/to/uet-ref-prov/prov \
   UET_CHECKS="rma prov interop" bash ci/jobs/vm-uet.sh

To run them with ``af_packet``, make a veth pair for each engine
first, and put one end on the bridge:

.. code-block:: bash

   for i in 1 2; do
       sudo ip link add ernic-dp$i type veth peer name ernic-dp${i}b
       sudo ip link set ernic-dp$i mtu 9000 up
       sudo ip link set ernic-dp${i}b mtu 9000 master ernic-ci-br0 up
   done
   export ERNIC_UET='ip=192.168.200.10%i,mtu=9000,wire=dpdk,dpdk-dev=net_af_packet0;iface=ernic-dp%i;framesz=10240;blocksz=40960;framecnt=1024'

``framesz=10240`` holds a 9000-byte MTU and the TPACKET header. Add
``dpdk-dma=dma_skeleton`` to place payload with the skeleton dmadev.
Add ``dpdk-map=on`` to map guest memory as for PCI.

The checks passed on each wire, one after the other on a quiet host
(1-minute load in brackets). Rates are MiB/s for 4 MiB at MTU 9000
over UDP, from VM 1 to VM 2 and back, as in `Packet Size and
Encapsulation`_. Each write took 512 requests.

.. list-table::
   :header-rows: 1
   :widths: 25 13 13 13 12 12 12

   * - Wire
     - ``uet_ernic_rma`` RUDI
     - ``uet_ernic_rma`` RUD
     - ``test_rma`` RUDI
     - ``test_rma`` RUD
     - host to guest
     - guest to host
   * - TAP [4]
     - 814, 979
     - 1039, 1013
     - 659, 484
     - 790
     - 557, 511
     - 1013, 878
   * - ``net_tap`` [2]
     - 789, 761
     - 777, 918
     - 595, 777
     - 377
     - 1002, 901
     - 970, 897
   * - ``af_packet`` [2]
     - 860, 1074
     - 851, 874
     - 671, 623
     - 661
     - 581, 546
     - 948, 838
   * - ``af_packet``, ``dpdk-map=on`` [4]
     - 849, 989
     - 956, 929
     - 675, 646
     - 623
     - 552, 531
     - 911, 810

The virtual PMDs copy each frame in software and make a system call
per frame or per burst, as the TAP does. So they run at about the
TAP's rate. They run the DPDK paths, but they do not make them
faster. The ``net_tap`` ``test_rma`` RUD write retransmitted 32
requests, and that is its lower rate.

An Intel E810
^^^^^^^^^^^^^

These steps run one engine on each port of an E810, with a cable
between the two ports. Both ports go to ``vfio-pci``, so the host has
no netdev on that wire. So run the ``rma`` and ``prov`` checks only,
and run them with ``UET_PCAP=0``. The checks capture on the CI
bridge, which the wire does not cross, so a capture would be empty
and the check would fail on it.
The commands use ``0000:c1:00.0`` and ``0000:c1:00.1``. Use the
addresses that ``dpdk-devbind.py -s`` shows.

1. Make sure that the IOMMU is on. The command must show groups.

   .. code-block:: bash

      ls /sys/kernel/iommu_groups

2. Make sure that each port is in its own IOMMU group. Two engines
   cannot share a group.

   .. code-block:: bash

      for d in 0000:c1:00.0 0000:c1:00.1; do
          basename "$(readlink /sys/bus/pci/devices/$d/iommu_group)"
      done

3. Give DPDK the DDP package, uncompressed. DPDK 24.11 reads
   ``ice.pkg``, and Fedora installs only ``ice.pkg.xz``. Without
   the package, the port does not start. With the devarg
   ``safe-mode-support=1``, it starts in Safe Mode, without RSS and
   without flow rules.

   .. code-block:: bash

      sudo mkdir -p /lib/firmware/updates/intel/ice/ddp
      xz -dc /lib/firmware/intel/ice/ddp/ice.pkg.xz |
          sudo tee /lib/firmware/updates/intel/ice/ddp/ice.pkg >/dev/null

4. Bind both ports to ``vfio-pci``, and give their group nodes to
   your user.

   .. code-block:: bash

      sudo modprobe vfio-pci
      sudo dpdk-devbind.py -b vfio-pci 0000:c1:00.0 0000:c1:00.1
      for d in 0000:c1:00.0 0000:c1:00.1; do
          g=$(basename "$(readlink /sys/bus/pci/devices/$d/iommu_group)")
          sudo chown "$USER" "/dev/vfio/$g"
      done

5. Reserve hugepages. An engine uses about 100 MiB of them, so
   1 GiB is enough for two.

   .. code-block:: bash

      sudo dpdk-hugepages.py -p 2M --setup 1G

6. Start the VMs with one engine on each port, and run the checks.
   In ``ERNIC_UET``, ``%j`` is the instance id less one.

   .. code-block:: bash

      export CI_BUILD_DIR=$PWD/build-dpdk
      export UET_PROV_DIR=/path/to/uet-ref-prov
      export ERNIC_LAUNCHER=$PWD/ci/uet-dpdk-launcher
      export ERNIC_UET='ip=192.168.200.10%i,mtu=9000,wire=dpdk,dpdk-dev=0000:c1:00.%j'
      bash ci/jobs/vm-up.sh && bash ci/jobs/vm-functional.sh
      UET_PCAP=0 UET_CHECKS="rma prov" bash ci/jobs/vm-uet.sh

7. Make sure that the startup line shows ``(pci)``, ``flow hw``,
   ``tx extbuf zero-copy`` and ``guest mem dma-mapped``. Make sure
   that each region line shows ``DMA-mapped``, except the
   read-only ones. At exit, the stats line must count no transmit
   frames copied as not mapped. The engine line must show
   ``window 512``.

   .. code-block:: bash

      grep 'UET wire\|UET engine' /var/tmp/ernic-ci-work/log/1.log

The wrapper raises ``RLIMIT_MEMLOCK`` to unlimited for a port on
PCI, because VFIO pins the hugepages and each guest region. To see
the DDP package that ice loaded, add
``dpdk-eal=--log-level=pmd.net.ice.init:info`` to ``ERNIC_UET``,
and look for ``Active package is`` in the log.

Guest memory on 2 MiB pages is worth about 5%: the engine reads
every payload for the CRC and copies every received one into guest
memory, and the translation works a page at a time. The guests' RAM
is a memfd mapping, so transparent huge pages for shared memory
cover it. The setting does not survive a reboot.

.. code-block:: bash

   echo always | sudo tee /sys/kernel/mm/transparent_hugepage/shmem_enabled
   echo madvise | sudo tee /sys/kernel/mm/transparent_hugepage/enabled

With all of this, a 1 GiB write from one guest to the other moves
5.7 GiB/s over RUD and 5.1 GiB/s over RUDI, with each engine on one
core. The sender's time is the CRC over the payload in guest memory,
and the receiver's is the copy into guest memory. The 4 MiB writes
the checks make are too short to show this: they finish in about a
millisecond and measure the setup.

To give the ports back to the kernel and free the hugepages:

.. code-block:: bash

   bash ci/jobs/vm-down.sh
   sudo dpdk-devbind.py -b ice 0000:c1:00.0 0000:c1:00.1
   sudo dpdk-hugepages.py --clear

Known Limits and Findings
-------------------------

- IPv4 only, peers on the same segment only, no VLANs.
- No target-side events. A write lands in the target's
  memory, but the target's guest is not told.
- The reference provider sets no RETX flag on a retransmitted
  RUDI request. The test counts RUDI retransmissions as
  requests beyond one per data packet.
- RUDI has no window. The whole message is encrypted and sent
  when the write is posted. The provider's AES-GCM and its
  per-packet key derivation run in software, at tens of
  microseconds per packet even at ``-O2``. With TSS, the retransmit timeout
  must be longer than the time to send the whole message.
  Otherwise the initiator keeps encrypting retransmissions
  and never reads a response. ``tss-cluster-rudi`` uses
  1 s. With the 50 ms that the RUD case uses, every packet
  reached its retry limit and the write failed.
- The SES layer copies a packet's payload out of the region
  before it asks PDS whether the packet can be sent. When the
  congestion window is closed, it repeats the copy on every
  progress call. In ``rud-drop500`` that was about 420,000
  page translations for 1771 packets. That is correct, but
  costly for a device model, and is worth fixing in the
  provider before phase 3.
- ``sec=server`` (TSS client/server mode) and key rotation
  are not offered.
- The libfabric provider over ``libuet_ernic`` offers no
  immediate data (``cq_data_size`` is 0, ``fi_writedata()``
  returns ``-FI_ENOSYS``), because the engine raises no events at
  the target. ``test_rma`` targets therefore check their window
  rather than wait for a signal.
- Taking back a RUD transfer closes the PDC it shares with the
  other RUD transfers to that peer, and those fail (see `Taking
  transfers back`_). RUDI transfers are taken back alone.
- On hardware, the DPDK wire ran on an Intel E810 only, with
  hardware flow rules, timestamps and checksums, and guest memory
  DMA-mapped for the port. RSS through a flow rule, buffer split
  and a dmadev have run on virtual devices only, with
  ``dma_skeleton`` as the dmadev.
- ``net_memif`` in DPDK 24.11 crashes when a memif buffer is larger
  than an mbuf, and when a peer disconnects while the other side
  polls. ``uet-dpdk-unit`` uses 8 KiB buffers, and its memif server
  closes first.
- The provider copies each received frame before it reads it:
  ``calloc()`` of the largest packet, which clears it, then a copy
  (``uet_pds_sec_rx_pkt()``). That is two passes over each byte
  before the placement copy. It also keeps a dmadev on a bus out of
  the placement.
- After a VM quits, its instance does not exit within the 2 s that
  the launcher gives it after ``SIGTERM``, and the launcher kills
  it. Phase 3 shows the same. The stats lines at exit can then be
  missing from the log.

Next Phases
-----------

- Target-side events, for immediate data and ``fi_writedata``.
- Throughput: each segment is a command and a reply on the
  service QP, and the engine runs on the vfio-user thread.
