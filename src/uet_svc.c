/*
 * uet_svc.c -- the UET engine's guest command channel
 *
 * See uet_svc.h for what this is, and shared/uet_ernic_abi.h for the
 * capsules.
 *
 * Copyright (C) Advanced Micro Devices, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <endian.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "uet_engine.h"
#include "uet_ernic_abi.h"
#include "uet_svc.h"

#define SVC_MAX_MRS     UET_ENGINE_MAX_MRS
#define SVC_MAX_PEERS   UET_ENGINE_MAX_PEERS
#define SVC_MAX_OPS     256u  /* WRITE/READ accepted and not yet answered */
#define SVC_MAX_REPLIES 1024u /* replies waiting for a posted receive */
#define SVC_MAX_BLOCKED 8u    /* QPs a flush skips before it gives up */

/* How long a WRITE/READ may wait to be posted (ARP, engine slots). */
#define SVC_POST_TIMEOUT_MS 5000u

/*
 * RUDI has no window: the provider sends every packet of a message at once
 * and retransmits each one that is not answered within the retransmit
 * timeout.  A burst larger than the receiving side's TAP queue is lost, and
 * the retransmissions of a large one come before the receiver has worked
 * through it, so a 4 MiB write failed on its retry limit.  RUDI transfers
 * therefore go to the engine in segments, with a cap on the RUDI bytes in
 * the engine across all transfers.  RUD has the PDS's own window and goes
 * as one message.
 */
#define SVC_RUDI_SEG    (256u * 1024u) /* bytes per RUDI segment */
#define SVC_RUDI_WINDOW (512u * 1024u) /* RUDI bytes in the engine, at most */
#define SVC_MAX_SEGS    4u             /* segments of one transfer in flight */
_Static_assert(SVC_RUDI_WINDOW / SVC_RUDI_SEG <= SVC_MAX_SEGS,
               "a transfer can have the whole window in flight");

/* A region the engine cannot address is refused rather than registered:
 * 2^22 pages is 16 GiB of 4 KiB pages. */
#define SVC_MAX_PAGES (1u << 22)

#define HANDLE_INDEX_MASK 0xffffu
#define HANDLE_GEN_SHIFT  16u

struct svc_mr {
    bool used;
    bool dead;    /* the ionic region went away; the engine's copy too */
    uint16_t gen; /* bumped on every reuse of the slot */
    uint32_t qp_id;
    uint32_t lkey;
    uint32_t emr; /* engine handle */
};

struct svc_peer {
    bool used;
    uint16_t gen;
    uint32_t qp_id;
    uint32_t epeer;
};

struct svc_op {
    bool used;
    bool posted; /* some of it is, or was, in the engine */
    bool orphan; /* its QP went away: the completion is dropped */
    bool stop;   /* post no more of it: it failed, or its QP went */
    uint8_t opcode;
    uint32_t qp_id;
    uint32_t mr;     /* region slot */
    uint32_t peer;   /* peer slot */
    uint64_t cookie; /* the guest's */
    uint64_t seq;    /* tags the engine cookies */
    uint64_t deadline_ms;
    int status;    /* the first error, a positive errno */
    uint64_t sent; /* bytes handed to the engine */
    uint32_t segs_out;
    uint8_t seg_busy; /* bit per entry of seg_len */
    uint64_t seg_len[SVC_MAX_SEGS];
    struct uet_engine_rma rma; /* the whole transfer */
};

struct svc_reply {
    uint32_t qp_id;
    uint8_t buf[UET_ERNIC_CAPSULE_SIZE];
};

struct uet_svc {
    struct uet_engine *e;
    struct uet_svc_ops ops;
    void *ctx;

    struct svc_mr mrs[SVC_MAX_MRS];
    struct svc_peer peers[SVC_MAX_PEERS];
    struct svc_op ops_tab[SVC_MAX_OPS];
    uint64_t next_seq;
    uint64_t rudi_out; /* RUDI bytes in the engine */

    struct svc_reply *replies; /* FIFO, oldest first */
    uint32_t nreplies;

    struct uet_svc_stats stats;
};

static uint64_t now_ms(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

/* ------------------------------------------------------------------ */
/* Handles                                                            */
/* ------------------------------------------------------------------ */

static uint32_t handle_of(uint32_t idx, uint16_t gen)
{
    return ((uint32_t)gen << HANDLE_GEN_SHIFT) | (idx + 1u);
}

/* The slot a handle names, or UINT32_MAX when it names none. */
static uint32_t handle_slot(uint32_t handle, uint32_t max)
{
    uint32_t idx = handle & HANDLE_INDEX_MASK;

    if (idx == 0 || idx > max)
        return UINT32_MAX;
    return idx - 1u;
}

static struct svc_mr *mr_lookup(struct uet_svc *s, uint32_t qp_id,
                                uint32_t handle)
{
    uint32_t i = handle_slot(handle, SVC_MAX_MRS);

    if (i == UINT32_MAX || !s->mrs[i].used || s->mrs[i].qp_id != qp_id ||
        (uint16_t)(handle >> HANDLE_GEN_SHIFT) != s->mrs[i].gen)
        return NULL;
    return &s->mrs[i];
}

static struct svc_peer *peer_lookup(struct uet_svc *s, uint32_t qp_id,
                                    uint32_t handle)
{
    uint32_t i = handle_slot(handle, SVC_MAX_PEERS);

    if (i == UINT32_MAX || !s->peers[i].used || s->peers[i].qp_id != qp_id ||
        (uint16_t)(handle >> HANDLE_GEN_SHIFT) != s->peers[i].gen)
        return NULL;
    return &s->peers[i];
}

/* ------------------------------------------------------------------ */
/* Replies                                                            */
/* ------------------------------------------------------------------ */

static void reply_init(struct uet_ernic_reply *r, uint8_t opcode,
                       uint64_t cookie, int status)
{
    memset(r, 0, sizeof(*r));
    r->hdr.magic = htole32(UET_ERNIC_MAGIC);
    r->hdr.version = htole16(UET_ERNIC_ABI_VERSION);
    r->hdr.opcode = opcode;
    r->hdr.flags = UET_ERNIC_F_REPLY;
    r->hdr.cookie = htole64(cookie);
    r->status = (int32_t)htole32((uint32_t)status);
}

/*
 * Deliver what can be delivered, in order per QP.  A QP with no receive
 * posted blocks only its own later replies; everyone else's keep moving.
 */
static void flush_replies(struct uet_svc *s)
{
    uint32_t blocked[SVC_MAX_BLOCKED];
    uint32_t nblocked = 0, kept = 0;

    for (uint32_t i = 0; i < s->nreplies; i++) {
        struct svc_reply *r = &s->replies[i];
        bool skip = false;

        for (uint32_t b = 0; b < nblocked; b++)
            skip = skip || blocked[b] == r->qp_id;
        if (!skip && nblocked < SVC_MAX_BLOCKED) {
            if (s->ops.reply(s->ctx, r->qp_id, r->buf, sizeof(r->buf))) {
                s->stats.replies++;
                continue;
            }
            s->stats.replies_waited++;
            blocked[nblocked++] = r->qp_id;
        }
        if (kept != i)
            s->replies[kept] = *r;
        kept++;
    }
    s->nreplies = kept;
}

static void send_reply(struct uet_svc *s, uint32_t qp_id,
                       const struct uet_ernic_reply *r)
{
    if (s->nreplies == SVC_MAX_REPLIES) {
        /* A guest with this many replies unclaimed is not posting receives
         * at all; the ABI requires one per command in flight. */
        s->stats.replies_discarded++;
        return;
    }
    s->replies[s->nreplies].qp_id = qp_id;
    memcpy(s->replies[s->nreplies].buf, r, sizeof(*r));
    s->nreplies++;
    flush_replies(s);
}

static void reply_status(struct uet_svc *s, uint32_t qp_id, uint8_t opcode,
                         uint64_t cookie, int status)
{
    struct uet_ernic_reply r;

    reply_init(&r, opcode, cookie, status);
    send_reply(s, qp_id, &r);
}

/* ------------------------------------------------------------------ */
/* Transfers                                                          */
/* ------------------------------------------------------------------ */

static void op_finish(struct uet_svc *s, struct svc_op *op, int status)
{
    if (!op->orphan) {
        struct uet_ernic_reply r;

        reply_init(&r, op->opcode, op->cookie, status);
        if (status == 0)
            r.u.rma.length = htole64(op->rma.len);
        send_reply(s, op->qp_id, &r);
        if (status == 0)
            s->stats.ops_completed++;
        else
            s->stats.ops_failed++;
    }
    memset(op, 0, sizeof(*op));
}

/*
 * The engine cookie of segment @k of @op: the slot, the segment and the
 * sequence number, so a completion for a slot that has since been reused
 * is not mistaken for the new occupant's.
 */
static uint64_t op_engine_cookie(const struct uet_svc *s,
                                 const struct svc_op *op, uint32_t k)
{
    return (op->seq << 16) | ((uint64_t)k << 8) |
           (uint64_t)(op - s->ops_tab);
}

/*
 * Hand what the engine can take of a transfer to it, and answer the
 * transfer once nothing of it is left to post or in flight.
 */
static void op_pump(struct uet_svc *s, struct svc_op *op, uint64_t now)
{
    while (!op->stop && op->sent < op->rma.len &&
           op->segs_out < SVC_MAX_SEGS) {
        uint64_t seg = op->rma.len - op->sent;
        uint32_t k = 0;

        if (op->rma.rudi) {
            if (seg > SVC_RUDI_SEG)
                seg = SVC_RUDI_SEG;
            /* Wait for the window; completions open it, so this is
             * not a reason to time out. */
            if (s->rudi_out != 0 && s->rudi_out + seg > SVC_RUDI_WINDOW)
                break;
        }
        while (op->seg_busy & (1u << k))
            k++;

        struct uet_engine_rma r = op->rma;
        r.local_addr += op->sent;
        r.remote_addr += op->sent;
        r.len = seg;
        r.cookie = op_engine_cookie(s, op, k);
        int rc = op->opcode == UET_ERNIC_OP_WRITE
                     ? uet_engine_post_write(s->e, &r)
                     : uet_engine_post_read(s->e, &r);
        if (rc == 0) {
            op->posted = true;
            op->sent += seg;
            op->segs_out++;
            op->seg_busy |= (uint8_t)(1u << k);
            op->seg_len[k] = seg;
            if (op->rma.rudi)
                s->rudi_out += seg;
            op->deadline_ms = now + SVC_POST_TIMEOUT_MS;
            continue;
        }
        if (rc == -EAGAIN && now < op->deadline_ms)
            break;
        op->status = rc == -EAGAIN ? ETIMEDOUT : -rc;
        op->stop = true;
    }
    if (op->segs_out == 0 && (op->stop || op->sent == op->rma.len))
        op_finish(s, op, op->status);
}

/* A segment of a transfer has left the engine. */
static void op_seg_done(struct uet_svc *s, uint64_t cookie, int status,
                        uint64_t now)
{
    uint64_t slot = cookie & 0xffu;
    uint32_t k = (uint32_t)(cookie >> 8) & 0xffu;
    struct svc_op *op;

    if (slot >= SVC_MAX_OPS || k >= SVC_MAX_SEGS)
        return;
    op = &s->ops_tab[slot];
    if (!op->used || op->seq != cookie >> 16 ||
        (op->seg_busy & (1u << k)) == 0)
        return;

    op->seg_busy &= (uint8_t) ~(1u << k);
    op->segs_out--;
    if (op->rma.rudi)
        s->rudi_out -= op->seg_len[k];
    if (status != 0 && op->status == 0) {
        op->status = status;
        op->stop = true;
    }
    op_pump(s, op, now);
}

static void cmd_rma(struct uet_svc *s, uint32_t qp_id, const void *capsule,
                    size_t len, uint8_t opcode, uint64_t cookie)
{
    struct uet_ernic_rma req;
    struct svc_mr *m;
    struct svc_peer *p;
    struct svc_op *op = NULL;

    if (len < sizeof(req)) {
        reply_status(s, qp_id, opcode, cookie, EINVAL);
        return;
    }
    memcpy(&req, capsule, sizeof(req));

    uint32_t flags = le32toh(req.flags);
    uint64_t length = le64toh(req.length);
    if ((flags & ~UET_ERNIC_RMA_RUDI) != 0 || req.reserved != 0 ||
        length == 0) {
        reply_status(s, qp_id, opcode, cookie, EINVAL);
        return;
    }

    m = mr_lookup(s, qp_id, le32toh(req.mr));
    p = peer_lookup(s, qp_id, le32toh(req.peer));
    if (m == NULL || p == NULL) {
        reply_status(s, qp_id, opcode, cookie, EBADF);
        return;
    }
    if (m->dead) {
        reply_status(s, qp_id, opcode, cookie, ECANCELED);
        return;
    }

    for (uint32_t i = 0; i < SVC_MAX_OPS; i++) {
        if (!s->ops_tab[i].used) {
            op = &s->ops_tab[i];
            break;
        }
    }
    if (op == NULL) {
        reply_status(s, qp_id, opcode, cookie, EAGAIN);
        return;
    }

    uint64_t now = now_ms();
    memset(op, 0, sizeof(*op));
    op->used = true;
    op->opcode = opcode;
    op->qp_id = qp_id;
    op->mr = (uint32_t)(m - s->mrs);
    op->peer = (uint32_t)(p - s->peers);
    op->cookie = cookie;
    op->seq = ++s->next_seq;
    op->deadline_ms = now + SVC_POST_TIMEOUT_MS;
    op->rma.peer = p->epeer;
    op->rma.mr = m->emr;
    op->rma.local_addr = le64toh(req.local_offset);
    op->rma.len = length;
    op->rma.remote_addr = le64toh(req.remote_offset);
    op->rma.rkey = le64toh(req.rkey);
    op->rma.rudi = (flags & UET_ERNIC_RMA_RUDI) != 0;

    op_pump(s, op, now);
}

/*
 * Post nothing more of the transfers that use a region or peer slot.  Those
 * with nothing in the engine are answered at once; the others when their
 * segments in the engine have failed there.
 */
static void cancel_waiting(struct uet_svc *s, bool by_mr, uint32_t slot)
{
    for (uint32_t i = 0; i < SVC_MAX_OPS; i++) {
        struct svc_op *op = &s->ops_tab[i];

        if (!op->used || op->stop || op->sent == op->rma.len ||
            (by_mr ? op->mr != slot : op->peer != slot))
            continue;
        op->stop = true;
        if (op->status == 0)
            op->status = ECANCELED;
        if (op->segs_out == 0)
            op_finish(s, op, op->status);
    }
}

/* ------------------------------------------------------------------ */
/* Commands                                                           */
/* ------------------------------------------------------------------ */

static void cmd_query(struct uet_svc *s, uint32_t qp_id, uint64_t cookie)
{
    struct uet_engine_cfg id;
    struct uet_ernic_reply r;

    uet_engine_identity(s->e, &id);
    reply_init(&r, UET_ERNIC_OP_QUERY, cookie, 0);
    r.u.query.abi_version = htole16(UET_ERNIC_ABI_VERSION);
    r.u.query.mtu = htole16(id.mtu);
    r.u.query.ipv4 = htole32(id.ip);
    memcpy(r.u.query.mac, id.mac, sizeof(r.u.query.mac));
    r.u.query.pid_on_fep = htole16(id.pid_on_fep);
    r.u.query.resource_index = htole16(id.resource_index);
    r.u.query.job_id = htole32(id.job_id);
    r.u.query.initiator_id = htole32(id.initiator_id);
    r.u.query.caps =
        htole32((id.pds == UET_ENGINE_PDS_FULL ? UET_ERNIC_CAP_RUDI : 0u) |
                (id.sec != UET_ENGINE_SEC_NONE ? UET_ERNIC_CAP_TSS : 0u));
    send_reply(s, qp_id, &r);
}

/* Register the view with the engine, making up a page list for a region
 * the driver handed over as one contiguous run. */
static int register_view(struct uet_svc *s, const struct uet_svc_mr_view *v,
                         uint32_t access, uint32_t *emr, uint64_t *rkey)
{
    struct uet_engine_pages p;
    uint64_t *synth = NULL;
    int rc;

    if (v->length == 0 || v->page_size < 512 ||
        (v->page_size & (v->page_size - 1u)) != 0)
        return -EINVAL;

    memset(&p, 0, sizeof(p));
    p.page_size = v->page_size;
    p.len = v->length;
    p.remote_read = (access & UET_ERNIC_ACC_REMOTE_READ) != 0;
    p.remote_write = (access & UET_ERNIC_ACC_REMOTE_WRITE) != 0;
    p.idempotent_safe = (access & UET_ERNIC_ACC_IDEMPOTENT_SAFE) != 0;

    if (v->pages != NULL) {
        p.pages = v->pages;
        p.npages = v->npages;
        p.page_offset = v->first_off;
    } else {
        uint64_t mask = (uint64_t)v->page_size - 1u;
        uint64_t first = v->base & ~mask;
        uint64_t off = v->base & mask;
        uint64_t n = (off + v->length + mask) / v->page_size;

        if (v->length > UINT64_MAX - off - mask || n > SVC_MAX_PAGES)
            return -EINVAL;
        synth = malloc((size_t)n * sizeof(*synth));
        if (synth == NULL)
            return -ENOMEM;
        for (uint64_t i = 0; i < n; i++)
            synth[i] = first + i * v->page_size;
        p.pages = synth;
        p.npages = (uint32_t)n;
        p.page_offset = (uint32_t)off;
    }

    rc = uet_engine_mr_reg_pages(s->e, &p, emr, rkey);
    free(synth);
    return rc;
}

static void cmd_mr_reg(struct uet_svc *s, uint32_t qp_id, const void *capsule,
                       size_t len, uint64_t cookie)
{
    struct uet_ernic_mr_reg req;
    struct uet_svc_mr_view v;
    struct uet_ernic_reply r;
    struct svc_mr *m = NULL;
    uint64_t rkey;
    uint32_t emr;
    int rc;

    if (len < sizeof(req)) {
        reply_status(s, qp_id, UET_ERNIC_OP_MR_REG, cookie, EINVAL);
        return;
    }
    memcpy(&req, capsule, sizeof(req));
    uint32_t access = le32toh(req.access);
    uint32_t lkey = le32toh(req.lkey);
    if ((access & ~(UET_ERNIC_ACC_REMOTE_READ | UET_ERNIC_ACC_REMOTE_WRITE |
                    UET_ERNIC_ACC_IDEMPOTENT_SAFE)) != 0) {
        reply_status(s, qp_id, UET_ERNIC_OP_MR_REG, cookie, EINVAL);
        return;
    }

    memset(&v, 0, sizeof(v));
    if (lkey == 0 || !s->ops.mr_view(s->ctx, lkey, &v)) {
        reply_status(s, qp_id, UET_ERNIC_OP_MR_REG, cookie, ENOENT);
        return;
    }

    for (uint32_t i = 0; i < SVC_MAX_MRS; i++) {
        if (!s->mrs[i].used) {
            m = &s->mrs[i];
            break;
        }
    }
    if (m == NULL) {
        reply_status(s, qp_id, UET_ERNIC_OP_MR_REG, cookie, ENOSPC);
        return;
    }

    rc = register_view(s, &v, access, &emr, &rkey);
    if (rc != 0) {
        reply_status(s, qp_id, UET_ERNIC_OP_MR_REG, cookie, -rc);
        return;
    }

    m->used = true;
    m->dead = false;
    m->gen++;
    m->qp_id = qp_id;
    m->lkey = lkey;
    m->emr = emr;

    reply_init(&r, UET_ERNIC_OP_MR_REG, cookie, 0);
    r.u.mr_reg.handle = htole32(handle_of((uint32_t)(m - s->mrs), m->gen));
    r.u.mr_reg.rkey = htole64(rkey);
    send_reply(s, qp_id, &r);
}

/* Drop a region handle; a transfer still on the engine fails there. */
static void mr_release(struct uet_svc *s, struct svc_mr *m)
{
    cancel_waiting(s, true, (uint32_t)(m - s->mrs));
    if (!m->dead)
        (void)uet_engine_mr_dereg(s->e, m->emr);
    m->used = false;
    m->dead = false;
}

static void peer_release(struct uet_svc *s, struct svc_peer *p)
{
    cancel_waiting(s, false, (uint32_t)(p - s->peers));
    (void)uet_engine_peer_remove(s->e, p->epeer);
    p->used = false;
}

static void cmd_release(struct uet_svc *s, uint32_t qp_id, const void *capsule,
                        size_t len, uint8_t opcode, uint64_t cookie)
{
    struct uet_ernic_release req;

    if (len < sizeof(req)) {
        reply_status(s, qp_id, opcode, cookie, EINVAL);
        return;
    }
    memcpy(&req, capsule, sizeof(req));
    if (req.reserved != 0) {
        reply_status(s, qp_id, opcode, cookie, EINVAL);
        return;
    }

    uint32_t handle = le32toh(req.handle);
    if (opcode == UET_ERNIC_OP_MR_DEREG) {
        struct svc_mr *m = mr_lookup(s, qp_id, handle);

        if (m == NULL) {
            reply_status(s, qp_id, opcode, cookie, EBADF);
            return;
        }
        mr_release(s, m);
    } else {
        struct svc_peer *p = peer_lookup(s, qp_id, handle);

        if (p == NULL) {
            reply_status(s, qp_id, opcode, cookie, EBADF);
            return;
        }
        peer_release(s, p);
    }
    reply_status(s, qp_id, opcode, cookie, 0);
}

static void cmd_peer_add(struct uet_svc *s, uint32_t qp_id, const void *capsule,
                         size_t len, uint64_t cookie)
{
    struct uet_ernic_peer_add req;
    struct uet_ernic_reply r;
    struct svc_peer *p = NULL;
    uint32_t epeer;
    int rc;

    if (len < sizeof(req)) {
        reply_status(s, qp_id, UET_ERNIC_OP_PEER_ADD, cookie, EINVAL);
        return;
    }
    memcpy(&req, capsule, sizeof(req));

    for (uint32_t i = 0; i < SVC_MAX_PEERS; i++) {
        if (!s->peers[i].used) {
            p = &s->peers[i];
            break;
        }
    }
    if (p == NULL) {
        reply_status(s, qp_id, UET_ERNIC_OP_PEER_ADD, cookie, ENOSPC);
        return;
    }

    rc = uet_engine_peer_add(s->e, le32toh(req.ipv4), le16toh(req.pid_on_fep),
                             le16toh(req.resource_index), &epeer);
    if (rc != 0) {
        reply_status(s, qp_id, UET_ERNIC_OP_PEER_ADD, cookie, -rc);
        return;
    }

    p->used = true;
    p->gen++;
    p->qp_id = qp_id;
    p->epeer = epeer;

    reply_init(&r, UET_ERNIC_OP_PEER_ADD, cookie, 0);
    r.u.peer_add.handle = htole32(handle_of((uint32_t)(p - s->peers), p->gen));
    send_reply(s, qp_id, &r);
}

void uet_svc_command(struct uet_svc *s, uint32_t qp_id, const void *capsule,
                     size_t len)
{
    struct uet_ernic_hdr h;

    if (s == NULL)
        return;
    s->stats.commands++;

    /* Without an intact header there is no cookie to answer with. */
    if (capsule == NULL || len < sizeof(h)) {
        s->stats.dropped++;
        return;
    }
    memcpy(&h, capsule, sizeof(h));
    if (le32toh(h.magic) != UET_ERNIC_MAGIC ||
        (h.flags & UET_ERNIC_F_REPLY) != 0) {
        s->stats.dropped++;
        return;
    }

    uint64_t cookie = le64toh(h.cookie);
    if (le16toh(h.version) != UET_ERNIC_ABI_VERSION || h.flags != 0) {
        reply_status(s, qp_id, h.opcode, cookie, EPROTO);
        return;
    }

    switch (h.opcode) {
    case UET_ERNIC_OP_QUERY:
        cmd_query(s, qp_id, cookie);
        break;
    case UET_ERNIC_OP_MR_REG:
        cmd_mr_reg(s, qp_id, capsule, len, cookie);
        break;
    case UET_ERNIC_OP_MR_DEREG:
    case UET_ERNIC_OP_PEER_REMOVE:
        cmd_release(s, qp_id, capsule, len, h.opcode, cookie);
        break;
    case UET_ERNIC_OP_PEER_ADD:
        cmd_peer_add(s, qp_id, capsule, len, cookie);
        break;
    case UET_ERNIC_OP_WRITE:
    case UET_ERNIC_OP_READ:
        cmd_rma(s, qp_id, capsule, len, h.opcode, cookie);
        break;
    default:
        reply_status(s, qp_id, h.opcode, cookie, EOPNOTSUPP);
        break;
    }
}

/* ------------------------------------------------------------------ */
/* Lifecycle and progress                                             */
/* ------------------------------------------------------------------ */

struct uet_svc *uet_svc_create(struct uet_engine *engine,
                               const struct uet_svc_ops *ops, void *ctx)
{
    struct uet_svc *s;

    if (engine == NULL || ops == NULL || ops->mr_view == NULL ||
        ops->reply == NULL)
        return NULL;

    s = calloc(1, sizeof(*s));
    if (s == NULL)
        return NULL;
    s->replies = calloc(SVC_MAX_REPLIES, sizeof(*s->replies));
    if (s->replies == NULL) {
        free(s);
        return NULL;
    }
    s->e = engine;
    s->ops = *ops;
    s->ctx = ctx;
    return s;
}

void uet_svc_destroy(struct uet_svc *s)
{
    if (s == NULL)
        return;

    /* Transfers still on the engine fail there once their region goes;
     * nobody is left to answer. */
    for (uint32_t i = 0; i < SVC_MAX_OPS; i++)
        s->ops_tab[i].orphan = true;
    for (uint32_t i = 0; i < SVC_MAX_MRS; i++) {
        if (s->mrs[i].used)
            mr_release(s, &s->mrs[i]);
    }
    for (uint32_t i = 0; i < SVC_MAX_PEERS; i++) {
        if (s->peers[i].used)
            peer_release(s, &s->peers[i]);
    }
    free(s->replies);
    free(s);
}

void uet_svc_poll(struct uet_svc *s)
{
    struct uet_engine_comp comp[16];
    size_t n;

    if (s == NULL)
        return;

    uint64_t now = now_ms();
    while ((n = uet_engine_poll_comp(s->e, comp, 16)) > 0) {
        for (size_t i = 0; i < n; i++)
            op_seg_done(s, comp[i].cookie, -comp[i].status, now);
    }

    for (uint32_t i = 0; i < SVC_MAX_OPS; i++) {
        struct svc_op *op = &s->ops_tab[i];

        if (op->used && !op->stop && op->sent < op->rma.len)
            op_pump(s, op, now);
    }

    if (s->nreplies > 0)
        flush_replies(s);
}

bool uet_svc_has_work(const struct uet_svc *s)
{
    if (s == NULL)
        return false;
    for (uint32_t i = 0; i < SVC_MAX_OPS; i++) {
        const struct svc_op *op = &s->ops_tab[i];

        if (op->used && !op->stop && op->sent < op->rma.len)
            return true;
    }
    return false;
}

void uet_svc_qp_gone(struct uet_svc *s, uint32_t qp_id)
{
    uint32_t kept = 0;

    if (s == NULL)
        return;

    /* Its replies have nowhere to go, and must not land on whatever QP
     * reuses the number. */
    for (uint32_t i = 0; i < s->nreplies; i++) {
        if (s->replies[i].qp_id == qp_id) {
            s->stats.replies_discarded++;
            continue;
        }
        if (kept != i)
            s->replies[kept] = s->replies[i];
        kept++;
    }
    s->nreplies = kept;

    for (uint32_t i = 0; i < SVC_MAX_OPS; i++) {
        struct svc_op *op = &s->ops_tab[i];

        if (!op->used || op->qp_id != qp_id)
            continue;
        if (op->segs_out > 0) {
            /* Settled, unanswered, once the engine is done with it. */
            op->orphan = true;
            op->stop = true;
        } else {
            memset(op, 0, sizeof(*op));
        }
    }
    for (uint32_t i = 0; i < SVC_MAX_MRS; i++) {
        if (s->mrs[i].used && s->mrs[i].qp_id == qp_id)
            mr_release(s, &s->mrs[i]);
    }
    for (uint32_t i = 0; i < SVC_MAX_PEERS; i++) {
        if (s->peers[i].used && s->peers[i].qp_id == qp_id)
            peer_release(s, &s->peers[i]);
    }
}

void uet_svc_mr_gone(struct uet_svc *s, uint32_t lkey)
{
    if (s == NULL || lkey == 0)
        return;

    for (uint32_t i = 0; i < SVC_MAX_MRS; i++) {
        struct svc_mr *m = &s->mrs[i];

        if (!m->used || m->dead || m->lkey != lkey)
            continue;
        cancel_waiting(s, true, i);
        (void)uet_engine_mr_dereg(s->e, m->emr);
        m->dead = true;
    }
}

void uet_svc_get_stats(const struct uet_svc *s, struct uet_svc_stats *out)
{
    if (s == NULL || out == NULL)
        return;

    *out = s->stats;
    out->ops_queued = 0;
    out->ops_posted = 0;
    for (uint32_t i = 0; i < SVC_MAX_OPS; i++) {
        if (s->ops_tab[i].used && s->ops_tab[i].posted)
            out->ops_posted++;
        else if (s->ops_tab[i].used)
            out->ops_queued++;
    }
    out->mrs = 0;
    for (uint32_t i = 0; i < SVC_MAX_MRS; i++)
        out->mrs += s->mrs[i].used ? 1u : 0u;
    out->peers = 0;
    for (uint32_t i = 0; i < SVC_MAX_PEERS; i++)
        out->peers += s->peers[i].used ? 1u : 0u;
    out->replies_pending = s->nreplies;
}
