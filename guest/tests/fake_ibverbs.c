/*
 * fake_ibverbs.c -- the parts of libibverbs libuet_ernic uses, faked
 *
 * Copyright (c) Advanced Micro Devices, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: MIT
 *
 * Linked into the guest library's test in place of libibverbs. It plays one
 * ionic device whose only peer is the UET engine: a SEND on an RC QP
 * connected to the engine's service QPN goes to the fake device process as
 * a command capsule, and the device's replies land in that QP's posted
 * receives, with completions, the way the real datapath delivers them.
 * Memory registrations are passed on by lkey, so the device can find the
 * pages in the guest memory both processes share.
 *
 * ibv_post_send(), ibv_post_recv() and ibv_poll_cq() are inline in
 * verbs.h and call through the context's ops, so those are filled in.
 */

#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#include <infiniband/verbs.h>

#include "fake_device_proto.h"
#include "fake_ibverbs.h"
#include "uet_ernic_abi.h"

/* verbs.h turns these names into inline wrappers; the fake defines the
 * functions behind them. */
#undef ibv_query_port
#undef ibv_reg_mr
#undef ibv_get_device_list

#define FAKE_MAX_MR   64u
#define FAKE_QP_DEPTH 256u
#define FAKE_CQ_DEPTH 512u
#define FAKE_QPN      17u

struct fake_cq {
    struct ibv_cq cq;
    struct ibv_wc ring[FAKE_CQ_DEPTH];
    unsigned head;
    unsigned count;
};

struct fake_recv {
    uint64_t wr_id;
    uint64_t addr;
    uint32_t length;
};

struct fake_qp {
    struct ibv_qp qp;
    struct fake_recv rq[FAKE_QP_DEPTH];
    unsigned rq_head;
    unsigned rq_count;
    uint32_t dest_qpn;
};

static struct {
    int chan;
    uint8_t *mem;
    size_t mem_len;
    struct ibv_device dev;
    struct ibv_device *list[2];
    struct ibv_context ctx;
    struct ibv_mr *mrs[FAKE_MAX_MR];
    uint32_t next_key;
    struct fake_qp *qp; /* the one QP the library creates */
    /* replies that came before a receive was posted, oldest first */
    struct fdev_msg backlog[FAKE_QP_DEPTH];
    unsigned backlog_count;
    struct fake_ibv_stats stats;
} g;

void fake_ibv_attach(int chan_fd, void *mem, size_t mem_len)
{
    g.chan = chan_fd;
    g.mem = mem;
    g.mem_len = mem_len;
}

void fake_ibv_get_stats(struct fake_ibv_stats *out)
{
    *out = g.stats;
}

static int chan_send(const struct fdev_msg *m)
{
    return send(g.chan, m, sizeof(*m), 0) == (ssize_t)sizeof(*m) ? 0 : EIO;
}

static void cq_push(struct ibv_cq *ibcq, const struct ibv_wc *wc)
{
    struct fake_cq *cq = (struct fake_cq *)ibcq;

    if (cq->count < FAKE_CQ_DEPTH) {
        cq->ring[(cq->head + cq->count) % FAKE_CQ_DEPTH] = *wc;
        cq->count++;
    }
}

/* A reply into the next posted receive.  False when none is posted. */
static bool deliver(const struct fdev_msg *m)
{
    struct fake_qp *q = g.qp;
    struct fake_recv *r;
    struct ibv_wc wc;

    if (q == NULL || q->qp.qp_num != m->qp || q->rq_count == 0)
        return false;
    r = &q->rq[q->rq_head];
    q->rq_head = (q->rq_head + 1) % FAKE_QP_DEPTH;
    q->rq_count--;

    uint32_t n = m->len < r->length ? m->len : r->length;
    memcpy((void *)(uintptr_t)r->addr, m->data, n);

    memset(&wc, 0, sizeof(wc));
    wc.wr_id = r->wr_id;
    wc.status = n == m->len ? IBV_WC_SUCCESS : IBV_WC_LOC_LEN_ERR;
    wc.opcode = IBV_WC_RECV;
    wc.byte_len = n;
    wc.qp_num = q->qp.qp_num;
    wc.src_qp = UET_ERNIC_SVC_QPN;
    cq_push(q->qp.recv_cq, &wc);
    g.stats.replies++;
    return true;
}

static void drain_channel(void)
{
    struct fdev_msg m;

    while (g.backlog_count > 0 && deliver(&g.backlog[0])) {
        g.backlog_count--;
        memmove(&g.backlog[0], &g.backlog[1],
                g.backlog_count * sizeof(g.backlog[0]));
    }
    while (recv(g.chan, &m, sizeof(m), MSG_DONTWAIT) == (ssize_t)sizeof(m)) {
        if (m.type != FDEV_REPLY)
            continue;
        if ((g.backlog_count > 0 || !deliver(&m)) &&
            g.backlog_count < FAKE_QP_DEPTH)
            g.backlog[g.backlog_count++] = m;
    }
}

static struct ibv_mr *mr_of(uint32_t lkey)
{
    for (unsigned i = 0; i < FAKE_MAX_MR; i++) {
        if (g.mrs[i] != NULL && g.mrs[i]->lkey == lkey)
            return g.mrs[i];
    }
    return NULL;
}

/* ---- ops called through the context ------------------------------------ */

static int fake_post_send(struct ibv_qp *ibqp, struct ibv_send_wr *wr,
                          struct ibv_send_wr **bad)
{
    struct fake_qp *q = (struct fake_qp *)ibqp;

    for (; wr != NULL; wr = wr->next) {
        struct fdev_msg m;
        struct ibv_wc wc;

        memset(&m, 0, sizeof(m));
        m.type = FDEV_CMD;
        m.qp = ibqp->qp_num;
        /* The datapath only hands SENDs on a connected service QP to the
         * engine; anything else is a library bug here. */
        if (wr->opcode != IBV_WR_SEND || ibqp->state != IBV_QPS_RTS ||
            q->dest_qpn != UET_ERNIC_SVC_QPN) {
            g.stats.bad_sends++;
            *bad = wr;
            return EINVAL;
        }
        for (int i = 0; i < wr->num_sge; i++) {
            const struct ibv_sge *s = &wr->sg_list[i];
            struct ibv_mr *mr = mr_of(s->lkey);

            if (mr == NULL || s->addr < (uintptr_t)mr->addr ||
                s->addr + s->length > (uintptr_t)mr->addr + mr->length ||
                m.len + s->length > sizeof(m.data)) {
                g.stats.bad_sends++;
                *bad = wr;
                return EINVAL;
            }
            memcpy(m.data + m.len, (void *)(uintptr_t)s->addr, s->length);
            m.len += s->length;
        }
        if (chan_send(&m) != 0) {
            *bad = wr;
            return EIO;
        }
        g.stats.sends++;

        if (wr->send_flags & IBV_SEND_SIGNALED) {
            memset(&wc, 0, sizeof(wc));
            wc.wr_id = wr->wr_id;
            wc.status = IBV_WC_SUCCESS;
            wc.opcode = IBV_WC_SEND;
            wc.qp_num = ibqp->qp_num;
            cq_push(ibqp->send_cq, &wc);
        }
    }
    return 0;
}

static int fake_post_recv(struct ibv_qp *ibqp, struct ibv_recv_wr *wr,
                          struct ibv_recv_wr **bad)
{
    struct fake_qp *q = (struct fake_qp *)ibqp;

    for (; wr != NULL; wr = wr->next) {
        if (q->rq_count == FAKE_QP_DEPTH || wr->num_sge != 1 ||
            mr_of(wr->sg_list[0].lkey) == NULL) {
            *bad = wr;
            return ENOMEM;
        }
        struct fake_recv *r =
            &q->rq[(q->rq_head + q->rq_count) % FAKE_QP_DEPTH];
        r->wr_id = wr->wr_id;
        r->addr = wr->sg_list[0].addr;
        r->length = wr->sg_list[0].length;
        q->rq_count++;
    }
    return 0;
}

static int fake_poll_cq(struct ibv_cq *ibcq, int num, struct ibv_wc *wc)
{
    struct fake_cq *cq = (struct fake_cq *)ibcq;
    int n = 0;

    drain_channel();
    while (n < num && cq->count > 0) {
        wc[n++] = cq->ring[cq->head];
        cq->head = (cq->head + 1) % FAKE_CQ_DEPTH;
        cq->count--;
    }
    return n;
}

/* ---- the library's entry points ---------------------------------------- */

struct ibv_device **ibv_get_device_list(int *num_devices)
{
    memset(&g.dev, 0, sizeof(g.dev));
    strcpy(g.dev.name, "ionic_0");
    g.list[0] = &g.dev;
    g.list[1] = NULL;
    if (num_devices != NULL)
        *num_devices = 1;
    return g.list;
}

void ibv_free_device_list(struct ibv_device **list)
{
    (void)list;
}

const char *ibv_get_device_name(struct ibv_device *device)
{
    return device->name;
}

struct ibv_context *ibv_open_device(struct ibv_device *device)
{
    memset(&g.ctx, 0, sizeof(g.ctx));
    g.ctx.device = device;
    g.ctx.ops.post_send = fake_post_send;
    g.ctx.ops.post_recv = fake_post_recv;
    g.ctx.ops.poll_cq = fake_poll_cq;
    g.next_key = 1;
    return &g.ctx;
}

int ibv_close_device(struct ibv_context *context)
{
    struct fdev_msg m;

    (void)context;
    memset(&m, 0, sizeof(m));
    m.type = FDEV_BYE;
    return chan_send(&m);
}

int ibv_query_gid(struct ibv_context *context, uint8_t port_num, int index,
                  union ibv_gid *gid)
{
    (void)context;
    if (port_num != 1 || index != 0)
        return EINVAL;
    memset(gid, 0, sizeof(*gid));
    gid->raw[0] = 0xfe;
    gid->raw[1] = 0x80;
    gid->raw[15] = 1;
    return 0;
}

int ibv_query_port(struct ibv_context *context, uint8_t port_num,
                   struct _compat_ibv_port_attr *port_attr)
{
    (void)context;
    (void)port_num;
    (void)port_attr;
    return EOPNOTSUPP;
}

struct ibv_pd *ibv_alloc_pd(struct ibv_context *context)
{
    struct ibv_pd *pd = calloc(1, sizeof(*pd));

    if (pd != NULL)
        pd->context = context;
    return pd;
}

int ibv_dealloc_pd(struct ibv_pd *pd)
{
    free(pd);
    return 0;
}

struct ibv_mr *ibv_reg_mr_iova2(struct ibv_pd *pd, void *addr, size_t length,
                                uint64_t iova, unsigned int access)
{
    struct ibv_mr *mr;
    struct fdev_msg m;
    uint8_t *a = addr;
    unsigned slot;

    (void)iova;
    (void)access;
    if (length == 0) {
        errno = EINVAL;
        return NULL;
    }
    for (slot = 0; slot < FAKE_MAX_MR; slot++) {
        if (g.mrs[slot] == NULL)
            break;
    }
    if (slot == FAKE_MAX_MR) {
        errno = ENOMEM;
        return NULL;
    }
    mr = calloc(1, sizeof(*mr));
    if (mr == NULL)
        return NULL;
    mr->context = pd->context;
    mr->pd = pd;
    mr->addr = addr;
    mr->length = length;
    /* ionic's form: an index and a key byte */
    mr->lkey = (slot + 1u) | (g.next_key++ << 24);
    mr->rkey = mr->lkey;

    /* Memory outside the shared guest memory is registered, but the
     * device is told it cannot reach it, so the engine refuses it: that is
     * what a buffer the device cannot DMA looks like.  The capsule slots
     * are such a buffer, which is fine because this fake moves capsules
     * itself. */
    memset(&m, 0, sizeof(m));
    m.type = FDEV_REG;
    m.lkey = mr->lkey;
    m.length = length;
    if (a >= g.mem && length <= g.mem_len &&
        (size_t)(a - g.mem) <= g.mem_len - length)
        m.offset = (uint64_t)(a - g.mem);
    else
        m.offset = UINT64_MAX;
    if (chan_send(&m) != 0) {
        free(mr);
        errno = EIO;
        return NULL;
    }
    g.mrs[slot] = mr;
    g.stats.mr_regs++;
    return mr;
}

struct ibv_mr *ibv_reg_mr(struct ibv_pd *pd, void *addr, size_t length,
                          int access)
{
    return ibv_reg_mr_iova2(pd, addr, length, (uintptr_t)addr,
                            (unsigned int)access);
}

int ibv_dereg_mr(struct ibv_mr *mr)
{
    struct fdev_msg m;

    for (unsigned i = 0; i < FAKE_MAX_MR; i++) {
        if (g.mrs[i] == mr)
            g.mrs[i] = NULL;
    }
    memset(&m, 0, sizeof(m));
    m.type = FDEV_DEREG;
    m.lkey = mr->lkey;
    free(mr);
    g.stats.mr_deregs++;
    return chan_send(&m);
}

struct ibv_cq *ibv_create_cq(struct ibv_context *context, int cqe,
                             void *cq_context, struct ibv_comp_channel *channel,
                             int comp_vector)
{
    struct fake_cq *cq;

    (void)comp_vector;
    if (cqe <= 0 || (unsigned)cqe > FAKE_CQ_DEPTH)
        return NULL;
    cq = calloc(1, sizeof(*cq));
    if (cq == NULL)
        return NULL;
    cq->cq.context = context;
    cq->cq.cq_context = cq_context;
    cq->cq.channel = channel;
    cq->cq.cqe = cqe;
    return &cq->cq;
}

int ibv_destroy_cq(struct ibv_cq *cq)
{
    free(cq);
    return 0;
}

struct ibv_qp *ibv_create_qp(struct ibv_pd *pd,
                             struct ibv_qp_init_attr *qp_init_attr)
{
    struct fake_qp *q;

    if (g.qp != NULL || qp_init_attr->qp_type != IBV_QPT_RC)
        return NULL;
    q = calloc(1, sizeof(*q));
    if (q == NULL)
        return NULL;
    q->qp.context = pd->context;
    q->qp.pd = pd;
    q->qp.send_cq = qp_init_attr->send_cq;
    q->qp.recv_cq = qp_init_attr->recv_cq;
    q->qp.qp_num = FAKE_QPN;
    q->qp.state = IBV_QPS_RESET;
    q->qp.qp_type = IBV_QPT_RC;
    g.qp = q;
    return &q->qp;
}

int ibv_modify_qp(struct ibv_qp *ibqp, struct ibv_qp_attr *attr, int attr_mask)
{
    struct fake_qp *q = (struct fake_qp *)ibqp;

    if (attr_mask & IBV_QP_DEST_QPN)
        q->dest_qpn = attr->dest_qp_num;
    if (attr_mask & IBV_QP_STATE)
        ibqp->state = attr->qp_state;
    return 0;
}

int ibv_destroy_qp(struct ibv_qp *ibqp)
{
    struct fdev_msg m;

    memset(&m, 0, sizeof(m));
    m.type = FDEV_QP_GONE;
    m.qp = ibqp->qp_num;
    if (g.qp == (struct fake_qp *)ibqp)
        g.qp = NULL;
    free(ibqp);
    g.backlog_count = 0;
    g.stats.qp_destroys++;
    return chan_send(&m);
}
