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

This is phase 1 of the work. The engine runs, it moves data
between two engines with every delivery mode Slice A asks for,
and it is wired into the server. The guest cannot drive it
yet; that is phase 2, described at the end of this page.

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

The provider needed five small changes. Its own build and its
``uet`` test program work as before.

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

Known Limits and Findings
-------------------------

- The guest has no way to use the engine yet (phase 2).
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

Phase 2: a command channel from the guest
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The guest drives the engine through an ordinary RC queue pair,
a "UET service QP", whose destination QPN is in a reserved
range. ``process_sq_wqe()`` in ``ionic_datapath.c``
intercepts SENDs on such a QP, as ``dp_nvmeof_rc_send()``
already does for the NVMe-oF controller.

The design study proposed ``0x00d0xxxx`` for that range, but
the ``s3`` backend already uses it (``S3_TARGET_QPN_BASE``),
and NVMe-oF uses ``0x00c0xxxx``. Use ``0x00e0xxxx`` instead.

The steps:

#. Add ``UET_SVC_QPN_BASE 0x00e00000u``, the matching mask,
   and an ``is_svc_qpn()`` test.
#. Define the command capsule: a versioned, little-endian
   header with an opcode and a cookie, and these commands:
   ``MR_REG``, ``MR_DEREG``, ``PEER_ADD``, ``PEER_REMOVE``,
   ``WRITE`` (with a ``rudi`` flag), and later ``READ``. Put
   it in a header that phase 4's guest library will share.
#. Add ``ionic_datapath_attach_uet()``, and handle service-QP
   SENDs next to the NVMe-oF hook. Fetch the capsule with
   ``dp_gather()``. Run it on the engine. Answer with a SEND
   into the guest's next posted receive, using
   ``deliver_recv()``.
#. A ``WRITE`` completes later. Keep the guest's QP and the
   cookie in a pending table. Reap ``uet_engine_poll_comp()``
   from ``ionic_datapath_poll()``, and send the completion
   capsule then.
#. Let ``MR_REG`` name an ionic MR by its lkey. ``mr_find()``
   gives the page list. The datapath keeps that list in its
   own memory (``struct dp_buf``), not in guest memory. So
   add ``uet_engine_mr_reg_pages()``, which keeps a copy of
   the list in engine-owned memory and resolves it through a
   device-memory window in the translator. A region that is
   one page, or contiguous, can be registered at level 0
   directly.
#. Add a unit test that includes ``ionic_datapath.c``, as
   ``test_ionic_query_qp.c`` does. It posts service-QP WQEs
   into fake guest memory and checks the response capsules,
   without a VM.

Phase 3: two VMs
^^^^^^^^^^^^^^^^

Two instances on one Linux bridge, each with ``--tap`` and its
own ``--uet ip=``, and a guest test program on each that uses
the phase 2 channel to repeat Slice A between them.

Phase 4: a guest library
^^^^^^^^^^^^^^^^^^^^^^^^

A guest ``libuet_ernic`` that implements the provider's verbs
entry points over the phase 2 channel, so the libfabric
``uet`` provider runs unchanged in the guest.
