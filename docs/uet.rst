Ultra Ethernet Transport Engine
===============================

With ``--uet``, a rocm-ernic instance runs an Ultra Ethernet
Transport (UET) engine inside the server. The engine is the
UEC reference provider's semantic, packet delivery and
transport security sublayers (SES, PDS and TSS), running as
the emulated NIC's firmware. It has its own IPv4 and MAC
address on the emulated wire, and it sends and receives real
UET frames: Ethernet, IPv4 protocol 253, the PDS and SES
headers, and a TSS header when security is on.

Phases 1, 2 and 4 of the work are done. The engine runs and
moves data between two engines with every delivery mode Slice
A asks for (phase 1). A guest drives it through a command
channel on an ordinary RC queue pair (phase 2). A guest library,
``libuet_ernic``, implements the part of the reference API that
the libfabric ``uet`` provider calls, on top of that channel
(phase 4). Everything is tested without a VM. Running it in two
VMs is phase 3, and what it still needs is listed at the end of
this page.

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
     - ``1500``
     - The wire's IP MTU, 576..9000.

A bad option stops the server before the guest attaches:

.. code-block:: console

   $ ./build/rocm-ernic --uet ip=192.168.200.101,sec=server
   Error: uet engine: sec must be none, direct or cluster (got 'server')

A good one is reported at startup, with the MAC that peers
will find by ARP:

.. code-block:: console

   rocm-ernic: UET engine ip 192.168.200.101 mac 02:55:c0:a8:c8:65 \
       job 1 pid 0 index 15 pds pds sec none mtu 1500

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
UET frames that are addressed to the engine's IP and MAC, and
ARP packets for the engine's IP. Everything else goes to the
guest as before. With the filter registered, the TAP is
drained even when the guest has no receive ring, so the
engine works before the driver loads. Frames for the guest
that arrive then are dropped, as a NIC with no posted buffers
drops them. The engine transmits straight onto the TAP with
``ionic_eth_emu_wire_send()``, without using the guest's
queues.

The engine answers ARP for its own address. To reach a peer
it resolves the peer's MAC by ARP, without blocking: the
first operation to an unresolved peer returns ``-EAGAIN``, an
ARP request goes out, and a retry succeeds once the reply has
arrived. Peers must be on the same Ethernet segment. There is
no gateway support yet.

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
given. It removes ``UET_IMPAIRMENT_SHIM``, because that shim
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
build and its ``uet`` test program work as before.

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

.. list-table::
   :header-rows: 1
   :widths: 22 78

   * - Command
     - What it does
   * - ``QUERY``
     - Returns the engine's address, MAC, JobID, PIDonFEP,
       resource index, initiator ID, MTU, the highest ABI
       version the device speaks, and whether RUDI and TSS
       are on.
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
       RUDI.

The device answers every command with exactly one reply. It
echoes the opcode and the cookie, and it carries a status:
0 or a Linux errno. Most replies come at once. A ``WRITE``
or ``READ`` is answered when it has completed or failed, so
its reply is its completion. A transfer that cannot be posted
yet, because ARP is still running or the engine is busy,
waits in the device for up to 5 s. After that it fails with
``ETIMEDOUT``.

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
  Its transfers that are still waiting are dropped. Those
  already in the engine run to completion, and their replies
  are discarded. A reply never lands on a later QP that gets
  the same number.
- The provider descriptor of a revoked region is kept,
  disabled, for a quarantine of 6 s before it can be reused.
  A partly received message keeps a pointer to the descriptor
  until it completes or goes idle (5 s), and the quarantine
  stops that pointer from reaching a new region.
- A peer handle that is released while transfers use it is
  removed once they finish.

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

``uet_initialize()`` opens the first ionic device, or the one
named by ``UET_ERNIC_DEVICE``. It never falls back to another
kind of device. It creates the service QP, connects it, posts
64 receives and sends ``QUERY``. Commands that the engine
answers at once are waited for. Each ``WRITE`` and ``READ``
reply becomes an entry in the completion queue of the
endpoint that posted it, in the format the queue was bound
with. Errors appear through ``-FI_EAVAIL`` and
``uet_cq_readerr()``, as in the reference.

These are the differences from the reference library:

- One engine endpoint serves every endpoint opened here, so
  they share its address and JobID.
- RMA writes and reads only, and only from registered memory:
  the local buffer must lie in the region named by the
  handle. No immediate data, no messages, no atomics, no
  target-side events.
- ``uet_mr_disable()`` keeps the region reachable by peers
  until ``uet_mr_close()``. Re-enabling it would need a new
  key, and callers keep the old one.
- IPv4 peers only.

``guest/uet_ernic_rma`` is the phase 3 workload. A target
registers a window and sends its address and key to an
initiator over TCP on the guests' own network. The initiator
writes a known pattern over RUDI (``-r``) or RUD, reads the
start back, and the target compares every byte.

The library has been compiled and tested only against a fake
libibverbs (see below). It has not run on an ionic device or
the ionic kernel driver, which needs a VM.

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
- nothing left in the channel or the engine at the end.

The ``uet-guest-lib-unit`` test covers phase 4. It runs two
guests and two devices, four processes. Each guest runs
``libuet_ernic`` over a fake libibverbs. Each device is
``tests/uet_fake_device.c``, which runs the real channel and
engine behind a socket that stands in for the rings. A
guest's memory is a memfd that its device maps too. The
guests call the library as the provider does, write over RUDI
and RUD, read back, and check the calls the library refuses
and an error completion. Afterwards each device must hold
nothing.

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
  per-packet key derivation run in software (its Makefile
  builds without optimization), at about a quarter of a
  millisecond per packet. With TSS, the retransmit timeout
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

Next Phases
-----------

Phase 3: two VMs
^^^^^^^^^^^^^^^^

Two instances, each with ``--tap`` on one Linux bridge and its
own ``--uet ip=``, and ``uet_ernic_rma`` built and run in each
guest. What is left:

- Host: the bridge and two TAPs that ``ci/doctor.sh`` asks for,
  the guest image (``scripts/fetch-guest-image.sh``, which needs
  ``oras``), a writable image directory, and the QEMU the CI
  jobs expect (Fedora's QEMU 10.2.2 has ``vfio-user-pci``, but
  the jobs look for a custom build first).
- Guest: libfabric's headers and the reference tree's
  ``uet_addr.h``, to build ``libuet_ernic`` and
  ``uet_ernic_rma`` in the guest, or a host-built copy.
- A CI job (``ci/jobs/vm-uet.sh`` and a playbook) that starts
  both instances with ``--uet`` and runs the tool both ways,
  RUDI and RUD, plus ``sec=cluster``.
- Not yet shown: that the ionic driver and the userspace
  provider accept an RC QP connected to QPN ``0x00e00001`` at
  the guest's own GID. The datapath sees only the destination
  QPN, so this is expected to work.

Phase 4 leftovers
^^^^^^^^^^^^^^^^^

The library is complete for the provider's calls. To run the
provider on it, link the provider against ``libuet_ernic``
instead of the reference library and set ``UET_FORCE_RUDI`` as
the provider already does.
