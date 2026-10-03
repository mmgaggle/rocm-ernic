/*
 * uet_ernic_abi.h -- the UET engine's guest command channel
 *
 * Copyright (c) Advanced Micro Devices, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: MIT
 *
 * A guest drives the UET engine that runs inside rocm-ernic through an
 * ordinary RC queue pair, its "service QP", connected to the destination
 * QPN UET_ERNIC_SVC_QPN on the guest's own ionic device. Every SEND on that
 * QP carries one command capsule; the device answers every command with
 * exactly one reply capsule, delivered as a SEND into the next receive the
 * guest has posted on the same QP. So the guest must keep a receive of at
 * least UET_ERNIC_CAPSULE_SIZE bytes posted for every command in flight.
 *
 * Most commands are answered at once. A WRITE or READ is answered when the
 * transfer has completed or failed, so its reply is its completion.
 *
 * This header is shared with guest code, so it is self-contained C11. Every
 * multi-byte field is little-endian. Reserved fields must be zero.
 *
 * Handles (memory regions, peers) belong to the service QP that created
 * them. Destroying the service QP releases them, and replies for commands
 * still in flight on it are discarded. Destroying an ionic memory region
 * that the engine has registered revokes the engine's registration at once:
 * transfers that still need the region fail with ECANCELED or EIO, and the
 * handle stays allocated, but dead, until the guest deregisters it.
 *
 * Remote addresses are offsets from the start of the remote region, not
 * virtual addresses, and local addresses are offsets from the start of the
 * local region named by its handle.
 *
 * Version 2 adds ABORT, which takes back transfers the device has accepted,
 * and the group of a WRITE or READ, which ABORT names them by. A device
 * accepts capsules of every version from UET_ERNIC_ABI_VERSION_MIN up to
 * its own, and QUERY reports its own. A guest sends the lower of that and
 * its own version; QUERY itself goes as version 1, which every device
 * takes.
 *
 * MR_REKEY, which gives a region a new key, came later in version 2: a
 * device has it when QUERY reports UET_ERNIC_CAP_REKEY, and answers
 * EOPNOTSUPP otherwise.
 */

#ifndef UET_ERNIC_ABI_H
#define UET_ERNIC_ABI_H

#include <stddef.h>
#include <stdint.h>

#define UET_ERNIC_ABI_VERSION     2u
#define UET_ERNIC_ABI_VERSION_MIN 1u

/* "UETC" in memory order. */
#define UET_ERNIC_MAGIC 0x43544555u

/*
 * Destination QPNs that reach the engine. ionic hands guest QPs out from 0
 * up, the NVMe-oF responder owns 0x00c0xxxx and the S3 target 0x00d0xxxx.
 */
#define UET_ERNIC_SVC_QPN_BASE 0x00e00000u
#define UET_ERNIC_SVC_QPN_MASK 0x00ff0000u
#define UET_ERNIC_SVC_QPN      (UET_ERNIC_SVC_QPN_BASE | 1u)

static inline int uet_ernic_is_svc_qpn(uint32_t qpn)
{
    return (qpn & UET_ERNIC_SVC_QPN_MASK) == UET_ERNIC_SVC_QPN_BASE;
}

/* Every capsule, in both directions, is at most this long. */
#define UET_ERNIC_CAPSULE_SIZE 64u

enum uet_ernic_op {
    UET_ERNIC_OP_QUERY = 1,       /* engine identity and limits */
    UET_ERNIC_OP_MR_REG = 2,      /* register an ionic MR by its lkey */
    UET_ERNIC_OP_MR_DEREG = 3,    /* release a region handle */
    UET_ERNIC_OP_PEER_ADD = 4,    /* make a peer endpoint addressable */
    UET_ERNIC_OP_PEER_REMOVE = 5, /* release a peer handle */
    UET_ERNIC_OP_WRITE = 6,       /* RMA write, answered on completion */
    UET_ERNIC_OP_READ = 7,        /* RMA read, answered on completion */
    UET_ERNIC_OP_ABORT = 8,       /* take transfers back (version 2) */
    UET_ERNIC_OP_MR_REKEY = 9,    /* a new key for a region (version 2,
                                   * UET_ERNIC_CAP_REKEY) */
};

/* hdr.flags */
#define UET_ERNIC_F_REPLY 0x01u /* set on every reply */

/* Starts every capsule. A reply echoes the request's opcode and cookie. */
struct uet_ernic_hdr {
    uint32_t magic;   /* UET_ERNIC_MAGIC */
    uint16_t version; /* UET_ERNIC_ABI_VERSION of the sender */
    uint8_t opcode;   /* enum uet_ernic_op */
    uint8_t flags;    /* UET_ERNIC_F_* */
    uint64_t cookie;  /* chosen by the guest, returned in the reply */
};

/* ---- requests ---------------------------------------------------------- */

/* UET_ERNIC_OP_QUERY: the header alone. */

/* mr_reg.access */
#define UET_ERNIC_ACC_REMOTE_READ     0x01u
#define UET_ERNIC_ACC_REMOTE_WRITE    0x02u
#define UET_ERNIC_ACC_IDEMPOTENT_SAFE 0x04u /* peers may target it by RUDI */

/*
 * UET_ERNIC_OP_MR_REG: give the engine an ionic memory region the guest has
 * already registered (ibv_reg_mr). The whole region is registered; local
 * reads and writes are always allowed.
 */
struct uet_ernic_mr_reg {
    struct uet_ernic_hdr hdr;
    uint32_t lkey;   /* the ionic lkey */
    uint32_t access; /* UET_ERNIC_ACC_* */
};

/*
 * UET_ERNIC_OP_MR_DEREG and UET_ERNIC_OP_PEER_REMOVE; and UET_ERNIC_OP_MR_REKEY
 * (version 2, UET_ERNIC_CAP_REKEY), which gives the region a new key,
 * answered like MR_REG with the handle, which stays, and the new key. The
 * old key is dead once the reply is sent: a request naming it places
 * nothing and is answered "bad key", whether a late duplicate of a write
 * that completed or a message still arriving, as if the region had been
 * deregistered. The region keeps its pages and its transfers, and takes
 * nothing more on the device, so a region can be re-keyed as often as
 * needed; deregistering and registering again holds an entry for the
 * device's quarantine (6 s) each time.
 */
struct uet_ernic_release {
    struct uet_ernic_hdr hdr;
    uint32_t handle;
    uint32_t reserved;
};

/* UET_ERNIC_OP_PEER_ADD: an endpoint on another engine. */
struct uet_ernic_peer_add {
    struct uet_ernic_hdr hdr;
    uint32_t ipv4;           /* the peer engine's address, 0xc0a8c865 for
                              * 192.168.200.101 */
    uint16_t pid_on_fep;     /* the peer endpoint's PIDonFEP */
    uint16_t resource_index; /* and its resource index */
};

/* rma.flags */
#define UET_ERNIC_RMA_RUDI 0x01u /* use RUDI if the key and peer allow it */

/* UET_ERNIC_OP_WRITE and UET_ERNIC_OP_READ. */
struct uet_ernic_rma {
    struct uet_ernic_hdr hdr;
    uint32_t peer;          /* peer handle */
    uint32_t mr;            /* local region handle */
    uint64_t local_offset;  /* into the local region */
    uint64_t length;        /* bytes */
    uint64_t remote_offset; /* into the remote region */
    uint64_t rkey;          /* the remote region's key */
    uint32_t flags;         /* UET_ERNIC_RMA_* */
    uint32_t group;         /* chosen by the guest, for ABORT; reserved
                             * (zero) in version 1 */
};

/* abort.flags */
#define UET_ERNIC_ABORT_ALL 0x01u /* every transfer of the QP, any group */

/*
 * UET_ERNIC_OP_ABORT (version 2): take back the WRITEs and READs of this
 * service QP in @group that have not been answered yet.
 *
 * Each transfer taken back is answered first, with ECANCELED, and then the
 * ABORT, with the number taken back. Once the ABORT is answered, no packet
 * of those transfers goes on the wire again, a late response to one is
 * ignored, and nothing of a READ is placed any more. A transfer that
 * finished before the ABORT was handled is answered as usual. The ABORT
 * never waits for a peer.
 *
 * A RUDI transfer is taken back alone. A RUD transfer that has packets on
 * the wire that the peer has not acknowledged leaves holes in its packet
 * delivery context, which is then closed with the peer: other RUD
 * transfers that still have packets on it, of any QP, fail with an error.
 *
 * A device whose engine cannot take transfers back (pds=sng) answers
 * EOPNOTSUPP and takes nothing back; it does not report UET_ERNIC_CAP_ABORT
 * in QUERY.  A device with no room for the answers takes nothing back and
 * answers EAGAIN: send the ABORT again.  A device that could not take some
 * transfer out of its engine answers EBUSY; that transfer is answered when
 * it leaves the engine, and may still land until then.
 */
struct uet_ernic_abort {
    struct uet_ernic_hdr hdr;
    uint32_t group;
    uint32_t flags; /* UET_ERNIC_ABORT_* */
};

/* ---- replies ----------------------------------------------------------- */

/* reply.query.caps */
#define UET_ERNIC_CAP_RUDI  0x01u /* the engine can use RUDI */
#define UET_ERNIC_CAP_TSS   0x02u /* the engine's traffic is encrypted */
#define UET_ERNIC_CAP_ABORT 0x04u /* ABORT takes transfers back */
#define UET_ERNIC_CAP_REKEY 0x08u /* MR_REKEY */

/*
 * Every reply. status is 0 or a positive Linux errno value: EPROTO for a
 * bad version, EOPNOTSUPP for an unknown opcode, EINVAL for a malformed
 * request, ENOENT for an unknown lkey, EBADF for a handle that is not this
 * QP's, ENOSPC when a table is full, ECANCELED when a region or session
 * went away underneath a transfer, ETIMEDOUT when a transfer could not be
 * started (the peer never answered ARP), and whatever the transport
 * reported for a transfer that failed on the wire.
 */
struct uet_ernic_reply {
    struct uet_ernic_hdr hdr;
    int32_t status;
    uint32_t reserved;
    union {
        struct {
            uint16_t abi_version; /* highest version the device speaks */
            uint16_t mtu;
            uint32_t ipv4;           /* the engine's address */
            uint8_t mac[6];          /* and MAC */
            uint16_t pid_on_fep;     /* its endpoint's PIDonFEP */
            uint16_t resource_index; /* and resource index */
            uint16_t reserved;
            uint32_t job_id;       /* the JobID every transfer carries */
            uint32_t initiator_id; /* the SES initiator ID it sends */
            uint32_t caps;         /* UET_ERNIC_CAP_* */
        } query;
        struct {
            uint32_t handle;
            uint32_t reserved;
            uint64_t rkey; /* what peers name the region by */
        } mr_reg; /* MR_REG and MR_REKEY */
        struct {
            uint32_t handle;
            uint32_t reserved;
        } peer_add;
        struct {
            uint64_t length; /* bytes moved */
        } rma;
        struct {
            uint32_t count; /* transfers taken back */
            uint32_t reserved;
        } abort;
        uint8_t raw[40];
    } u;
};

_Static_assert(sizeof(struct uet_ernic_hdr) == 16, "capsule header layout");
_Static_assert(sizeof(struct uet_ernic_mr_reg) == 24, "MR_REG layout");
_Static_assert(sizeof(struct uet_ernic_release) == 24, "release layout");
_Static_assert(sizeof(struct uet_ernic_peer_add) == 24, "PEER_ADD layout");
_Static_assert(sizeof(struct uet_ernic_rma) == UET_ERNIC_CAPSULE_SIZE,
               "WRITE/READ layout");
_Static_assert(sizeof(struct uet_ernic_abort) == 24, "ABORT layout");
_Static_assert(sizeof(struct uet_ernic_reply) == UET_ERNIC_CAPSULE_SIZE,
               "reply layout");
_Static_assert(offsetof(struct uet_ernic_reply, u) == 24, "reply payload");

#endif /* UET_ERNIC_ABI_H */
