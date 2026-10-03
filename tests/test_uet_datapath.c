/*
 * test_uet_datapath.c -- the UET command channel, end to end, without a VM
 *
 * Two processes, each with a real ionic datapath (this file #includes
 * ionic_datapath.c, as test_ionic_cq_arm.c does) and a real UET engine,
 * joined by a socketpair that carries their Ethernet frames.  Each process
 * plays its own guest driver: it lays out a CQ, an RC QP and its memory
 * regions in a fake guest memory, connects the QP to the engine's service
 * QPN, and writes command capsules into SQ WQEs, rings the doorbell, and
 * reads the reply capsules back out of the receives the replies landed in.
 * So every capsule here goes through process_sq_wqe(), dp_gather(), the
 * command channel, the engine and the wire, and every reply through
 * deliver_recv() and a real CQE.
 *
 * The initiator WRITEs into an MR window the target registered (RUDI and
 * RUD), READs some of it back, and the target compares its memory.  Then
 * the lifecycle cases: an MR destroyed while a WRITE from it is in flight,
 * the initiator's service QP destroyed while a WRITE is in flight and its
 * QP number reused, and the target's service QP destroyed so its window is
 * gone, and ABORT: two WRITEs in two groups on a wire that loses every
 * frame, one group taken back; a WRITE posted again at once on a new
 * group; ABORT of every group; ABORT of a WRITE still waiting in the
 * device for ARP; and ABORT with too little room for its answers (the
 * test builds the channel with a 16-reply queue).  Before any of that, the
 * capsule checks: bad magic, bad version, unknown opcode, short capsules,
 * unknown lkeys and handles, a malformed ABORT, and a reply that has to wait
 * for the guest to post a receive.
 *
 * Copyright (C) Advanced Micro Devices, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the LICENSE_GPL.md file in the top-level directory.
 */

#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

/* Pull in the code under test (including its static functions). */
#include "ionic_datapath.c"

#include "uet_engine.h"
#include "uet_ernic_abi.h"
#include "uet_svc.h"

/* ---- Fake guest memory --------------------------------------------------
 *
 * Guest physical addresses start at 4 GiB so that nothing could pass by
 * using one as a pointer.  The datapath reaches the memory through the
 * vfio-user DMA calls below, the engine through its map callback; both are
 * the same arithmetic.
 */
#define GPA_BASE  UINT64_C(0x100000000)
#define ARENA_LEN (8u * 1024u * 1024u)
#define PAGE      4096u

static uint8_t *g_mem;

static void *gpa_ptr(uint64_t gpa, size_t len)
{
    if (gpa < GPA_BASE || len > ARENA_LEN || gpa - GPA_BASE > ARENA_LEN - len)
        return NULL;
    return g_mem + (gpa - GPA_BASE);
}

struct fake_sg {
    uint64_t addr;
    size_t len;
};

size_t dma_sg_size(void)
{
    return sizeof(struct fake_sg);
}

int vfu_addr_to_sgl(vfu_ctx_t *vfu_ctx, vfu_dma_addr_t dma_addr, size_t len,
                    dma_sg_t *sgl, size_t max_nr_sgs, int prot)
{
    struct fake_sg *sg = (struct fake_sg *)sgl;
    uint64_t addr = (uint64_t)(uintptr_t)dma_addr;

    (void)vfu_ctx;
    (void)prot;
    if (max_nr_sgs < 1 || gpa_ptr(addr, len) == NULL)
        return -1;
    sg->addr = addr;
    sg->len = len;
    return 1;
}

int vfu_sgl_get(vfu_ctx_t *vfu_ctx, dma_sg_t *sgl, struct iovec *iov,
                size_t cnt, int flags)
{
    struct fake_sg *sg = (struct fake_sg *)sgl;

    (void)vfu_ctx;
    (void)flags;
    if (cnt < 1)
        return -1;
    iov->iov_base = gpa_ptr(sg->addr, sg->len);
    iov->iov_len = sg->len;
    return 0;
}

void vfu_sgl_put(vfu_ctx_t *vfu_ctx, dma_sg_t *sgl, struct iovec *iov,
                 size_t cnt)
{
    (void)vfu_ctx;
    (void)sgl;
    (void)iov;
    (void)cnt;
}

void vfu_sgl_mark_dirty(vfu_ctx_t *vfu_ctx, dma_sg_t *sgl, size_t cnt)
{
    (void)vfu_ctx;
    (void)sgl;
    (void)cnt;
}

/* The datapath logs on every doorbell; keep it out of the way. */
void vfu_log(vfu_ctx_t *vfu_ctx, int level, const char *fmt, ...)
{
    (void)vfu_ctx;
    (void)level;
    (void)fmt;
}

/* ---- Stubs for the TU's other external symbols (as test_ionic_cq_arm) -- */
int ionic_eth_emu_trigger_irq(struct ionic_eth_emu *emu, int vec)
{
    (void)emu;
    (void)vec;
    return 0;
}

uint32_t ionic_mesh_local_node(pvrdma_handle_t handle)
{
    (void)handle;
    return UINT32_MAX;
}
uint32_t ionic_mesh_node_from_gid(pvrdma_handle_t handle, const uint8_t *gid)
{
    (void)handle;
    (void)gid;
    return UINT32_MAX;
}
int ionic_mesh_sendv(pvrdma_handle_t handle, uint32_t dst_node, const void *hdr,
                     size_t hdr_len, const void *body, size_t body_len)
{
    (void)handle;
    (void)dst_node;
    (void)hdr;
    (void)hdr_len;
    (void)body;
    (void)body_len;
    return -1;
}
void ionic_mesh_set_recv_cb(pvrdma_handle_t handle, ionic_mesh_recv_fn fn,
                            void *opaque)
{
    (void)handle;
    (void)fn;
    (void)opaque;
}

struct nvmeof_target *nvmeof_target_create(const struct nvmeof_target_cfg *cfg,
                                           char *err, size_t errlen)
{
    (void)cfg;
    (void)err;
    (void)errlen;
    return NULL;
}
void nvmeof_target_destroy(struct nvmeof_target *t)
{
    (void)t;
}
struct nvmeof_queue *nvmeof_target_find_queue(struct nvmeof_target *t,
                                              uint32_t handle)
{
    (void)t;
    (void)handle;
    return NULL;
}
int nvmeof_queue_exec(struct nvmeof_queue *q, const void *capsule, size_t len,
                      const struct nvmeof_dma_ops *dma, void *dma_ctx,
                      void *rsp)
{
    (void)q;
    (void)capsule;
    (void)len;
    (void)dma;
    (void)dma_ctx;
    (void)rsp;
    return -1;
}
struct nvmeof_cm *nvmeof_cm_create(struct nvmeof_target *target,
                                   uint32_t traddr, uint16_t trsvcid)
{
    (void)target;
    (void)traddr;
    (void)trsvcid;
    return NULL;
}
void nvmeof_cm_destroy(struct nvmeof_cm *cm)
{
    (void)cm;
}
void nvmeof_cm_drop_qp(struct nvmeof_cm *cm, uint32_t guest_qpn)
{
    (void)cm;
    (void)guest_qpn;
}
bool nvmeof_cm_handle_mad(struct nvmeof_cm *cm, const void *mad, size_t len,
                          void *rsp, struct nvmeof_cm_result *res)
{
    (void)cm;
    (void)mad;
    (void)len;
    (void)rsp;
    (void)res;
    return false;
}

struct s3_target *s3_target_create(const struct s3_target_cfg *cfg, char *err,
                                   size_t errlen)
{
    (void)cfg;
    (void)err;
    (void)errlen;
    return NULL;
}
void s3_target_destroy(struct s3_target *t)
{
    (void)t;
}
void s3_tcp_cfg_from_target(struct s3_tcp_cfg *cfg,
                            const struct s3_target *target)
{
    (void)cfg;
    (void)target;
}
struct s3_tcp *s3_tcp_create(const struct s3_tcp_cfg *cfg,
                             struct s3_target *target,
                             const struct s3_dma_ops *dma, void *dma_ctx,
                             s3_tcp_tx_fn tx, void *tx_ctx, char *err,
                             size_t errlen)
{
    (void)cfg;
    (void)target;
    (void)dma;
    (void)dma_ctx;
    (void)tx;
    (void)tx_ctx;
    (void)err;
    (void)errlen;
    return NULL;
}
void s3_tcp_destroy(struct s3_tcp *s)
{
    (void)s;
}
bool s3_tcp_rx_frame(struct s3_tcp *s, const void *frame, size_t len,
                     uint64_t now_ms)
{
    (void)s;
    (void)frame;
    (void)len;
    (void)now_ms;
    return false;
}
bool s3_tcp_poll(struct s3_tcp *s, uint64_t now_ms)
{
    (void)s;
    (void)now_ms;
    return false;
}
bool s3_tcp_has_work(const struct s3_tcp *s)
{
    (void)s;
    return false;
}

void ionic_eth_emu_register_tx_filter(struct ionic_eth_emu *emu,
                                      ionic_eth_tx_filter_fn fn, void *ctx)
{
    (void)emu;
    (void)fn;
    (void)ctx;
}
int ionic_eth_emu_queue_rx_frame(struct ionic_eth_emu *emu, const void *frame,
                                 size_t len)
{
    (void)emu;
    (void)frame;
    (void)len;
    return -1;
}

void pvrdma_qp_cqe_count(pvrdma_handle_t handle, uint32_t qp_id)
{
    (void)handle;
    (void)qp_id;
}
void pvrdma_qp_doorbell_count(pvrdma_handle_t handle, uint32_t qp_id,
                              bool is_send)
{
    (void)handle;
    (void)qp_id;
    (void)is_send;
}
void pvrdma_qp_wqe_count(pvrdma_handle_t handle, uint32_t qp_id,
                         unsigned int pvrdma_opcode)
{
    (void)handle;
    (void)qp_id;
    (void)pvrdma_opcode;
}
void pvrdma_rdma_bytes_count(pvrdma_handle_t handle, uint32_t qp_id,
                             uint64_t bytes, enum pvrdma_stat_op op)
{
    (void)handle;
    (void)qp_id;
    (void)bytes;
    (void)op;
}

/* ---- Layout ------------------------------------------------------------ */

#define IP_INITIATOR 0xc0a8c865u /* 192.168.200.101 */
#define IP_TARGET    0xc0a8c866u /* 192.168.200.102 */
#define IP_NOBODY    0xc0a8c8fau /* 192.168.200.250: never answers ARP */
#define PEER_PID     0u
#define PEER_INDEX   15u

#define SVC_QP 9u /* the guest's service QP number */
#define CQ_ID  3u

#define CQ_DEPTH_LOG2 8u
#define CQ_DEPTH      (1u << CQ_DEPTH_LOG2)
#define WQ_DEPTH_LOG2 6u
#define WQ_DEPTH      (1u << WQ_DEPTH_LOG2)
#define WQ_STRIDE_L2  6u
#define WQ_STRIDE     (1u << WQ_STRIDE_L2)
#define RECVS         8u /* receives kept posted */

/* Offsets into guest memory. */
#define OFF_CQ   0x0000u /* 256 CQEs */
#define OFF_SQ   0x2000u
#define OFF_RQ   0x3000u
#define OFF_SEND 0x4000u /* one capsule per SQ slot */
#define OFF_RECV 0x5000u /* one capsule per RQ slot */
#define OFF_PTAB 0x6000u /* page table of the data region, two pages */
#define OFF_READ 0x8000u /* contiguous region READs land in */
#define OFF_DATA 0x20000u
#define READ_LEN (64u * 1024u)

/* ionic lkeys are index | key << 24; 0 is the reserved DMA key. */
#define CAP_LKEY  0x01000001u
#define SRC_LKEY  0x02000002u
#define SRC2_LKEY 0x03000003u
#define READ_LKEY 0x04000004u
#define TGT_LKEY  0x05000005u

#define CAP_VA  UINT64_C(0x7f0000004000)
#define DATA_VA UINT64_C(0x7f1000000000)
#define READ_VA UINT64_C(0x7f2000000000)

#define SRC_LEN (1024u * 1024u)
#define SRC_OFF 100u /* the region starts this far into its first page */
#define TGT_LEN (3u * 1024u * 1024u)
#define TGT_OFF 300u

/* Where things land in the target's region. */
#define T1     (4096u + 7u)                   /* RUDI, 512 KiB */
#define T2     (T1 + 512u * 1024u + 3u)       /* RUD, 512 KiB */
#define T3     (1024u * 1024u + 64u * 1024u)  /* cut short by DESTROY_MR */
#define T4     (2048u * 1024u + 128u * 1024u) /* refused: window gone */
#define T4_LEN (64u * 1024u)
#define T5     (2048u * 1024u + 256u * 1024u) /* taken back by ABORT */
#define T5_LEN (256u * 1024u)
#define T6     (T5 + T5_LEN + 4096u + 5u) /* the other group: lands */
#define T6_LEN (256u * 1024u)

#define HALF (512u * 1024u)

#define CASE_TIMEOUT_S 90

/* ---- Data -------------------------------------------------------------- */

static uint8_t pattern(size_t off)
{
    uint64_t z = (uint64_t)(off / 8) + UINT64_C(0x9e3779b97f4a7c15);

    z = (z ^ (z >> 30)) * UINT64_C(0xbf58476d1ce4e5b9);
    z = (z ^ (z >> 27)) * UINT64_C(0x94d049bb133111eb);
    z ^= z >> 31;
    return (uint8_t)(z >> ((off % 8) * 8));
}

/* A region on reversed pages, its page table at OFF_PTAB. */
struct region {
    uint32_t first_off;
    uint64_t len;
    uint32_t npages;
};

static uint64_t page_gpa(const struct region *r, uint32_t i)
{
    return GPA_BASE + OFF_DATA + (uint64_t)(r->npages - 1u - i) * PAGE;
}

static void region_init(struct region *r, uint32_t first_off, uint64_t len)
{
    r->first_off = first_off;
    r->len = len;
    r->npages = (uint32_t)((first_off + len + PAGE - 1u) / PAGE);
    for (uint32_t i = 0; i < r->npages; i++) {
        uint64_t le = htole64(page_gpa(r, i));
        memcpy(gpa_ptr(GPA_BASE + OFF_PTAB + (uint64_t)i * 8u, 8), &le, 8);
    }
}

static uint8_t *region_byte(const struct region *r, uint64_t off)
{
    uint64_t abs = r->first_off + off;

    return gpa_ptr(page_gpa(r, (uint32_t)(abs / PAGE)) + abs % PAGE, 1);
}

/* Register it the way CREATE_MR does: a page table in guest memory. */
static void region_register(struct ionic_datapath *dp, const struct region *r,
                            uint32_t lkey)
{
    struct ionic_dp_buf_desc buf = {
        .dma_addr = GPA_BASE + OFF_PTAB,
        .map_count = r->npages,
        .page_size_log2 = 12,
    };

    ionic_datapath_register_mr(dp, lkey, DATA_VA + r->first_off, r->len, &buf);
}

/* ---- One process: a guest, its device, and the device's engine --------- */

struct report {
    int ok;
    char why[240];
    double write_ms;
    int status_mr_gone;     /* WRITE whose MR was destroyed under it */
    int status_window_gone; /* WRITE into a window that was withdrawn */
    int status_aborted;     /* WRITE taken back by ABORT */
    uint32_t abort_count;   /* what the ABORT reported */
    double abort_wait_ms;   /* ABORT of a WRITE waiting for ARP */
    uint64_t aborts_deferred;
    uint64_t revoked_hits;
    uint64_t replies_discarded;
    uint64_t compared;
    uint64_t wrong;
    struct uet_svc_stats svc;
    struct uet_engine_stats eng;
    uint32_t churn_peak; /* engine regions held at most in the churn */
};

struct node {
    struct ionic_datapath *dp;
    struct uet_engine *e;
    int wire_fd;
    int ctl_fd;
    struct report *rep;

    uint32_t sq_prod;
    uint32_t rq_prod;
    uint32_t recvs_out; /* receives posted and not yet consumed */
    bool auto_repost;
    bool wire_down; /* lose every IP frame (ARP still passes) */
    uint64_t wire_lost;
    uint32_t cq_cons;
    bool cq_color;
    uint64_t next_cookie;
    unsigned send_errors;

    struct {
        bool used;
        uint64_t cookie;
        struct uet_ernic_reply r;
    } box[64];
};

static int g_fake_ctx;

static void fail(struct report *rep, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));

static void fail(struct report *rep, const char *fmt, ...)
{
    va_list ap;

    if (!rep->ok)
        return; /* keep the first reason */
    rep->ok = 0;
    va_start(ap, fmt);
    vsnprintf(rep->why, sizeof(rep->why), fmt, ap);
    va_end(ap);
}

static double now_ms_f(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1000.0 + (double)ts.tv_nsec / 1e6;
}

static uint32_t rd_be32(const uint8_t *p)
{
    uint32_t v;

    memcpy(&v, p, 4);
    return be32toh(v);
}

static void wr_be32(uint8_t *p, uint32_t v)
{
    v = htobe32(v);
    memcpy(p, &v, 4);
}

static uint64_t db(uint32_t qid, uint8_t ring, uint16_t p_index)
{
    return (uint64_t)p_index | ((uint64_t)ring << 16) |
           ((uint64_t)(qid & 0xffu) << 24) |
           ((uint64_t)((qid >> 8) & 0xffffu) << 32);
}

static void put_sge(uint8_t *wqe, uint64_t va, uint32_t len, uint32_t lkey)
{
    uint64_t va_be = htobe64(va);

    memcpy(wqe + WQE_PLD_OFF, &va_be, 8);
    wr_be32(wqe + WQE_PLD_OFF + 8, len);
    wr_be32(wqe + WQE_PLD_OFF + 12, lkey);
}

static void post_recv(struct node *n)
{
    uint32_t slot = n->rq_prod % WQ_DEPTH;
    uint8_t *wqe = gpa_ptr(GPA_BASE + OFF_RQ + slot * WQ_STRIDE, WQ_STRIDE);
    uint64_t id = slot;

    memset(wqe, 0, WQ_STRIDE);
    memcpy(wqe, &id, 8); /* native, as the driver's rq_meta index */
    wqe[9] = 1;          /* one SGE */
    put_sge(wqe, CAP_VA + (OFF_RECV - OFF_SEND) + slot * 64u, 64, CAP_LKEY);
    n->rq_prod++;
    n->recvs_out++;
    ionic_datapath_doorbell(n->dp, DP_QTYPE_RQ,
                            db(SVC_QP, 0, (uint16_t)n->rq_prod));
}

static void post_send(struct node *n, const void *capsule, uint32_t len)
{
    uint32_t slot = n->sq_prod % WQ_DEPTH;
    uint8_t *wqe = gpa_ptr(GPA_BASE + OFF_SQ + slot * WQ_STRIDE, WQ_STRIDE);
    uint64_t id = n->sq_prod;
    uint16_t flags = htobe16(IONIC_V1_FLAG_SIG);

    memcpy(gpa_ptr(GPA_BASE + OFF_SEND + slot * 64u, 64), capsule, len);
    memset(wqe, 0, WQ_STRIDE);
    memcpy(wqe, &id, 8);
    wqe[8] = IONIC_V1_OP_SEND;
    wqe[9] = 1;
    memcpy(wqe + 10, &flags, 2);
    wr_be32(wqe + WQE_SEND_LEN_OFF, len);
    put_sge(wqe, CAP_VA + slot * 64u, len, CAP_LKEY);
    n->sq_prod++;
    ionic_datapath_doorbell(n->dp, DP_QTYPE_SQ,
                            db(SVC_QP, 0, (uint16_t)n->sq_prod));
}

/* Reap CQEs the way the driver does: by colour. */
static void poll_cq(struct node *n)
{
    for (;;) {
        uint8_t *cqe = gpa_ptr(GPA_BASE + OFF_CQ +
                                   (uint64_t)(n->cq_cons % CQ_DEPTH) * CQE_SIZE,
                               CQE_SIZE);
        uint32_t qtf = rd_be32(cqe + 28);

        if (((qtf & CQE_COLOR_BIT) != 0) != n->cq_color)
            break;

        uint32_t type = qtf & (7u << 5);
        bool error = (qtf & CQE_ERROR_BIT) != 0;
        uint32_t status_len = rd_be32(cqe + 24);

        if (type == CQE_TYPE_RECV) {
            uint64_t slot;
            memcpy(&slot, cqe, 8);
            n->recvs_out--;
            if (error || status_len != UET_ERNIC_CAPSULE_SIZE) {
                fail(n->rep, "receive completed with %s %u",
                     error ? "status" : "length", status_len);
            } else {
                struct uet_ernic_reply r;
                memcpy(
                    &r,
                    gpa_ptr(GPA_BASE + OFF_RECV + (slot % WQ_DEPTH) * 64u, 64),
                    sizeof(r));
                uint64_t cookie = le64toh(r.hdr.cookie);
                bool stored = false;
                for (unsigned i = 0; i < 64 && !stored; i++) {
                    if (!n->box[i].used) {
                        n->box[i].used = true;
                        n->box[i].cookie = cookie;
                        n->box[i].r = r;
                        stored = true;
                    }
                }
                if (!stored)
                    fail(n->rep, "reply mailbox overflow");
            }
            if (n->auto_repost)
                post_recv(n);
        } else if (type == CQE_TYPE_SEND_MSN && error) {
            n->send_errors++;
        }

        n->cq_cons++;
        if (n->cq_cons % CQ_DEPTH == 0)
            n->cq_color = !n->cq_color;
    }
}

/* Frames in, transport, command channel, completions out. */
static void pump(struct node *n)
{
    uint8_t buf[9216];
    struct pollfd p = {.fd = n->wire_fd, .events = POLLIN};

    if (!uet_engine_has_work(n->e) && !uet_svc_has_work(n->dp->uet_svc))
        (void)poll(&p, 1, 1);
    for (unsigned i = 0; i < 256; i++) {
        ssize_t r = recv(n->wire_fd, buf, sizeof(buf), MSG_DONTWAIT);
        if (r <= 0)
            break;
        (void)uet_engine_rx_frame(n->e, buf, (size_t)r);
    }
    uet_engine_poll(n->e);
    ionic_datapath_poll(n->dp);
    poll_cq(n);
}

static void pump_for(struct node *n, double ms)
{
    double end = now_ms_f() + ms;

    while (now_ms_f() < end)
        pump(n);
}

static bool take_reply(struct node *n, uint64_t cookie,
                       struct uet_ernic_reply *out)
{
    for (unsigned i = 0; i < 64; i++) {
        if (n->box[i].used && n->box[i].cookie == cookie) {
            *out = n->box[i].r;
            n->box[i].used = false;
            return true;
        }
    }
    return false;
}

static bool wait_reply(struct node *n, uint64_t cookie, double ms,
                       struct uet_ernic_reply *out)
{
    double end = now_ms_f() + ms;

    while (!take_reply(n, cookie, out)) {
        if (now_ms_f() > end)
            return false;
        pump(n);
    }
    return true;
}

static void hdr_init(struct uet_ernic_hdr *h, uint8_t op, uint64_t cookie)
{
    memset(h, 0, sizeof(*h));
    h->magic = htole32(UET_ERNIC_MAGIC);
    h->version = htole16(UET_ERNIC_ABI_VERSION);
    h->opcode = op;
    h->cookie = htole64(cookie);
}

/*
 * Send a capsule and wait for its reply.  Returns the reply's status, or
 * -1 when none came (which also fails the case).
 */
static int call(struct node *n, void *capsule, uint32_t len, const char *what,
                struct uet_ernic_reply *reply)
{
    struct uet_ernic_hdr h;
    struct uet_ernic_reply r;

    memcpy(&h, capsule, sizeof(h));
    post_send(n, capsule, len);
    if (!wait_reply(n, le64toh(h.cookie), 20000.0, &r)) {
        fail(n->rep, "%s: no reply", what);
        return -1;
    }
    if (le32toh(r.hdr.magic) != UET_ERNIC_MAGIC ||
        r.hdr.flags != UET_ERNIC_F_REPLY || r.hdr.opcode != h.opcode)
        fail(n->rep, "%s: malformed reply", what);
    if (reply)
        *reply = r;
    return (int32_t)le32toh((uint32_t)r.status);
}

static void expect(struct node *n, int got, int want, const char *what)
{
    if (got != want)
        fail(n->rep, "%s: status %d (%s), wanted %d (%s)", what, got,
             got > 0 ? strerror(got) : "-", want,
             want > 0 ? strerror(want) : "ok");
}

static int query(struct node *n, struct uet_ernic_reply *r)
{
    struct uet_ernic_hdr h;

    hdr_init(&h, UET_ERNIC_OP_QUERY, ++n->next_cookie);
    return call(n, &h, sizeof(h), "QUERY", r);
}

static int mr_reg(struct node *n, uint32_t lkey, uint32_t access,
                  uint32_t *handle, uint64_t *rkey)
{
    struct uet_ernic_mr_reg q;
    struct uet_ernic_reply r;
    int st;

    memset(&q, 0, sizeof(q));
    hdr_init(&q.hdr, UET_ERNIC_OP_MR_REG, ++n->next_cookie);
    q.lkey = htole32(lkey);
    q.access = htole32(access);
    st = call(n, &q, sizeof(q), "MR_REG", &r);
    if (handle)
        *handle = le32toh(r.u.mr_reg.handle);
    if (rkey)
        *rkey = le64toh(r.u.mr_reg.rkey);
    return st;
}

static int release(struct node *n, uint8_t op, uint32_t handle)
{
    struct uet_ernic_release q;

    memset(&q, 0, sizeof(q));
    hdr_init(&q.hdr, op, ++n->next_cookie);
    q.handle = htole32(handle);
    return call(n, &q, sizeof(q), "release", NULL);
}

static int peer_add(struct node *n, uint32_t ip, uint32_t *handle)
{
    struct uet_ernic_peer_add q;
    struct uet_ernic_reply r;
    int st;

    memset(&q, 0, sizeof(q));
    hdr_init(&q.hdr, UET_ERNIC_OP_PEER_ADD, ++n->next_cookie);
    q.ipv4 = htole32(ip);
    q.pid_on_fep = htole16(PEER_PID);
    q.resource_index = htole16(PEER_INDEX);
    st = call(n, &q, sizeof(q), "PEER_ADD", &r);
    if (handle)
        *handle = le32toh(r.u.peer_add.handle);
    return st;
}

/* Post a WRITE or READ in ABORT group @group without waiting; returns its
 * cookie. */
static uint64_t rma_post_group(struct node *n, uint8_t op, uint32_t peer,
                               uint32_t mr, uint64_t local, uint64_t len,
                               uint64_t remote, uint64_t rkey, bool rudi,
                               uint32_t group)
{
    struct uet_ernic_rma q;
    uint64_t cookie = ++n->next_cookie;

    memset(&q, 0, sizeof(q));
    hdr_init(&q.hdr, op, cookie);
    q.peer = htole32(peer);
    q.mr = htole32(mr);
    q.local_offset = htole64(local);
    q.length = htole64(len);
    q.remote_offset = htole64(remote);
    q.rkey = htole64(rkey);
    q.flags = htole32(rudi ? UET_ERNIC_RMA_RUDI : 0u);
    q.group = htole32(group);
    post_send(n, &q, sizeof(q));
    return cookie;
}

static uint64_t rma_post(struct node *n, uint8_t op, uint32_t peer, uint32_t mr,
                         uint64_t local, uint64_t len, uint64_t remote,
                         uint64_t rkey, bool rudi)
{
    return rma_post_group(n, op, peer, mr, local, len, remote, rkey, rudi, 0);
}

static int abort_group(struct node *n, uint32_t group, uint32_t flags,
                       struct uet_ernic_reply *r)
{
    struct uet_ernic_abort q;

    memset(&q, 0, sizeof(q));
    hdr_init(&q.hdr, UET_ERNIC_OP_ABORT, ++n->next_cookie);
    q.group = htole32(group);
    q.flags = htole32(flags);
    return call(n, &q, sizeof(q), "ABORT", r);
}

static int rma_wait(struct node *n, uint64_t cookie, const char *what,
                    uint64_t *moved)
{
    struct uet_ernic_reply r;

    if (!wait_reply(n, cookie, 30000.0, &r)) {
        struct uet_svc_stats st;
        struct uet_engine_stats es;
        uet_svc_get_stats(n->dp->uet_svc, &st);
        uet_engine_get_stats(n->e, &es);
        fprintf(stderr,
                "%s timed out: channel queued=%u posted=%u replies_pending=%u "
                "waited=%" PRIu64 " engine posted=%" PRIu64 " ok=%" PRIu64
                " failed=%" PRIu64 " inflight=%u recvs_out=%u rq=%u sq=%u\n",
                what, st.ops_queued, st.ops_posted, st.replies_pending,
                st.replies_waited, es.ops_posted, es.ops_completed,
                es.ops_failed, es.ops_in_flight, n->recvs_out, n->rq_prod,
                n->sq_prod);
        fail(n->rep, "%s: never completed", what);
        return -1;
    }
    if (moved)
        *moved = le64toh(r.u.rma.length);
    return (int32_t)le32toh((uint32_t)r.status);
}

/* A fresh service QP: rings zeroed, connected to the engine, receives up. */
static void svc_qp_create(struct node *n)
{
    struct ionic_dp_ring_desc sq = {
        .buf = {.dma_addr = GPA_BASE + OFF_SQ,
                .map_count = 1,
                .page_size_log2 = 12},
        .depth_log2 = WQ_DEPTH_LOG2,
        .stride_log2 = WQ_STRIDE_L2,
    };
    struct ionic_dp_ring_desc rq = sq;

    rq.buf.dma_addr = GPA_BASE + OFF_RQ;
    memset(gpa_ptr(GPA_BASE + OFF_SQ, 0x2000), 0, 0x2000);
    n->sq_prod = 0;
    n->rq_prod = 0;
    n->recvs_out = 0;
    ionic_datapath_register_qp(n->dp, SVC_QP, 2 /* RC */, CQ_ID, &sq, CQ_ID,
                               &rq);
    /* What MODIFY_QP to RTR sets from dest_qp_num and the AH. */
    ionic_datapath_set_dest(n->dp, SVC_QP, UET_ERNIC_SVC_QPN, UINT32_MAX);
    for (unsigned i = 0; i < RECVS; i++)
        post_recv(n);
}

static void cq_event(void *opaque, uint32_t eq_id, uint32_t cq_id)
{
    (void)opaque;
    (void)eq_id;
    (void)cq_id;
}

static int wire_tx(void *ctx, const void *frame, size_t len)
{
    struct node *n = ctx;
    const uint8_t *f = frame;

    if (n->wire_down && len >= 14 && f[12] == 0x08 && f[13] == 0x00) {
        n->wire_lost++;
        return 0;
    }
    if (send(n->wire_fd, frame, len, MSG_DONTWAIT) < 0)
        return (errno == EAGAIN || errno == ENOBUFS) ? -EAGAIN : -errno;
    return 0;
}

static void *engine_map(void *ctx, uint64_t addr, size_t len, bool write)
{
    (void)ctx;
    (void)write;
    return gpa_ptr(addr, len);
}

static bool node_start(struct node *n, uint32_t ip)
{
    struct uet_engine_cfg cfg;
    char err[256] = "";

    g_mem = aligned_alloc(PAGE, ARENA_LEN);
    if (g_mem == NULL) {
        fail(n->rep, "no memory");
        return false;
    }
    memset(g_mem, 0, ARENA_LEN);

    uet_engine_cfg_defaults(&cfg);
    cfg.ip = ip;
    cfg.rto_ms = 20;
    cfg.max_retries = 10;
    cfg.mr_quarantine_ms = 50;
    struct uet_engine_wire wire = {.tx = wire_tx, .ctx = n};
    struct uet_engine_dma dma = {.map = engine_map, .ctx = NULL};
    n->e = uet_engine_create(&cfg, &wire, &dma, err, sizeof(err));
    if (n->e == NULL) {
        fail(n->rep, "uet_engine_create: %s", err);
        return false;
    }

    n->dp = ionic_datapath_create((vfu_ctx_t *)&g_fake_ctx, NULL);
    if (n->dp == NULL ||
        !ionic_datapath_attach_uet(n->dp, n->e, err, sizeof(err))) {
        fail(n->rep, "datapath: %s", err);
        return false;
    }
    ionic_datapath_set_cq_event_cb(n->dp, cq_event, NULL);

    struct ionic_dp_ring_desc cq = {
        .buf = {.dma_addr = GPA_BASE + OFF_CQ,
                .map_count = 1,
                .page_size_log2 = 12},
        .depth_log2 = CQ_DEPTH_LOG2,
        .stride_log2 = 5,
    };
    ionic_datapath_register_cq(n->dp, CQ_ID, 0, &cq);
    n->cq_color = true;

    struct ionic_dp_buf_desc caps = {
        .dma_addr = GPA_BASE + OFF_SEND, .map_count = 1, .page_size_log2 = 12};
    ionic_datapath_register_mr(n->dp, CAP_LKEY, CAP_VA, 0x2000, &caps);

    n->auto_repost = true;
    svc_qp_create(n);
    return true;
}

static void node_finish(struct node *n)
{
    struct report *rep = n->rep;

    if (n->dp != NULL) {
        uet_svc_get_stats(n->dp->uet_svc, &rep->svc);
        if (n->send_errors != 0)
            fail(rep, "%u command SENDs completed in error", n->send_errors);
        ionic_datapath_destroy(n->dp);
    }
    if (n->e != NULL) {
        uet_engine_get_stats(n->e, &rep->eng);
        uet_engine_destroy(n->e);
    }
    free(g_mem);
}

/* ---- Control channel ---------------------------------------------------- */

enum { CTL_KEY = 1, CTL_VERIFY, CTL_VERIFIED, CTL_DROP, CTL_DROPPED, CTL_DONE };

struct ctl {
    uint32_t type;
    int32_t status;
    uint64_t rkey;
};

static void ctl_send(struct node *n, uint32_t type, int32_t status,
                     uint64_t rkey)
{
    struct ctl m = {.type = type, .status = status, .rkey = rkey};

    if (send(n->ctl_fd, &m, sizeof(m), 0) != (ssize_t)sizeof(m))
        fail(n->rep, "control channel");
}

/* Pump until the peer sends @type; false on a hangup or timeout. */
static bool ctl_wait(struct node *n, uint32_t type, struct ctl *out)
{
    double end = now_ms_f() + 60000.0;

    for (;;) {
        ssize_t r = recv(n->ctl_fd, out, sizeof(*out), MSG_DONTWAIT);
        if (r == (ssize_t)sizeof(*out) && out->type == type)
            return true;
        if (r == 0 || now_ms_f() > end) {
            fail(n->rep, "waited for control message %u in vain", type);
            return false;
        }
        pump(n);
    }
}

/* ---- The capsule checks ------------------------------------------------- */

static void capsule_checks(struct node *n)
{
    struct report *rep = n->rep;
    struct uet_svc_stats st;
    struct uet_ernic_hdr h;
    struct uet_ernic_reply r;
    uint8_t raw[UET_ERNIC_CAPSULE_SIZE];

    /* No intact header, no cookie to answer: dropped, and counted. */
    hdr_init(&h, UET_ERNIC_OP_QUERY, 0xbad);
    h.magic = htole32(0xdeadbeefu);
    post_send(n, &h, sizeof(h));
    pump_for(n, 50.0);
    uet_svc_get_stats(n->dp->uet_svc, &st);
    if (take_reply(n, 0xbad, &r) || st.dropped != 1)
        fail(rep, "a capsule with a bad magic was answered");

    hdr_init(&h, UET_ERNIC_OP_QUERY, ++n->next_cookie);
    h.version = htole16(UET_ERNIC_ABI_VERSION + 1u);
    expect(n, call(n, &h, sizeof(h), "a version from the future", NULL), EPROTO,
           "a version from the future");
    hdr_init(&h, UET_ERNIC_OP_QUERY, ++n->next_cookie);
    h.version = 0;
    expect(n, call(n, &h, sizeof(h), "version 0", NULL), EPROTO, "version 0");
    /* Every version from the oldest one up is taken. */
    hdr_init(&h, UET_ERNIC_OP_QUERY, ++n->next_cookie);
    h.version = htole16(UET_ERNIC_ABI_VERSION_MIN);
    expect(n, call(n, &h, sizeof(h), "version 1", NULL), 0, "version 1");

    /* ABORT: unknown flags and a short capsule are refused; a group with
     * nothing in flight takes nothing back. */
    {
        struct uet_ernic_reply ar;

        expect(n, abort_group(n, 1, 0x80u, NULL), EINVAL,
               "ABORT with unknown flags");
        hdr_init(&h, UET_ERNIC_OP_ABORT, ++n->next_cookie);
        expect(n, call(n, &h, sizeof(h), "short ABORT", NULL), EINVAL,
               "short ABORT");
        expect(n, abort_group(n, 42, 0, &ar), 0, "ABORT of an idle group");
        if (le32toh(ar.u.abort.count) != 0)
            fail(rep, "ABORT of an idle group took %u back",
                 le32toh(ar.u.abort.count));
        expect(n, abort_group(n, 0, UET_ERNIC_ABORT_ALL, &ar), 0,
               "ABORT of everything, with nothing in flight");
    }

    hdr_init(&h, 200, ++n->next_cookie);
    expect(n, call(n, &h, sizeof(h), "opcode 200", NULL), EOPNOTSUPP,
           "opcode 200");

    hdr_init(&h, UET_ERNIC_OP_MR_REG, ++n->next_cookie);
    expect(n, call(n, &h, sizeof(h), "short MR_REG", NULL), EINVAL,
           "short MR_REG");

    expect(n, mr_reg(n, 0x0abcdef1u, 0, NULL, NULL), ENOENT,
           "MR_REG of an unknown lkey");
    expect(n, mr_reg(n, CAP_LKEY, 0x80u, NULL, NULL), EINVAL,
           "MR_REG with unknown access bits");
    expect(n, release(n, UET_ERNIC_OP_MR_DEREG, 0x12345u), EBADF,
           "MR_DEREG of a handle never handed out");
    expect(n, release(n, UET_ERNIC_OP_PEER_REMOVE, 7u), EBADF,
           "PEER_REMOVE of a handle never handed out");

    uint64_t c = rma_post(n, UET_ERNIC_OP_WRITE, 1, 1, 0, 64, 0, 0, false);
    expect(n, rma_wait(n, c, "WRITE with bad handles", NULL), EBADF,
           "WRITE with bad handles");

    /* An oversized capsule is read only up to the capsule size. */
    memset(raw, 0, sizeof(raw));
    hdr_init(&h, UET_ERNIC_OP_QUERY, ++n->next_cookie);
    memcpy(raw, &h, sizeof(h));
    expect(n, call(n, raw, sizeof(raw), "padded QUERY", NULL), 0,
           "QUERY padded to the capsule size");

    /* A reply waits, in order, for the guest to post a receive. */
    n->auto_repost = false;
    while (n->recvs_out > 0) {
        hdr_init(&h, UET_ERNIC_OP_QUERY, ++n->next_cookie);
        (void)call(n, &h, sizeof(h), "QUERY", NULL);
    }
    uint64_t waiting = ++n->next_cookie;
    hdr_init(&h, UET_ERNIC_OP_QUERY, waiting);
    post_send(n, &h, sizeof(h));
    pump_for(n, 30.0);
    uet_svc_get_stats(n->dp->uet_svc, &st);
    if (take_reply(n, waiting, &r) || st.replies_pending != 1)
        fail(rep, "a reply did not wait for a posted receive");
    n->auto_repost = true;
    post_recv(n);
    if (!wait_reply(n, waiting, 5000.0, &r))
        fail(rep, "the waiting reply never arrived");
    while (n->recvs_out < RECVS)
        post_recv(n);
}

static void check_query(struct node *n, uint32_t ip)
{
    struct uet_ernic_reply r;
    static const uint8_t mac_prefix[2] = {0x02, 0x55};

    expect(n, query(n, &r), 0, "QUERY");
    if (le16toh(r.u.query.abi_version) != UET_ERNIC_ABI_VERSION ||
        le32toh(r.u.query.ipv4) != ip || le32toh(r.u.query.job_id) != 1 ||
        le16toh(r.u.query.pid_on_fep) != PEER_PID ||
        le16toh(r.u.query.resource_index) != PEER_INDEX ||
        le16toh(r.u.query.mtu) != 1500 ||
        memcmp(r.u.query.mac, mac_prefix, 2) != 0 ||
        r.u.query.mac[5] != (uint8_t)ip ||
        (le32toh(r.u.query.caps) & UET_ERNIC_CAP_RUDI) == 0 ||
        (le32toh(r.u.query.caps) & UET_ERNIC_CAP_ABORT) == 0 ||
        (le32toh(r.u.query.caps) & UET_ERNIC_CAP_REKEY) == 0)
        fail(n->rep, "QUERY reported the wrong identity");
}

/* ---- The two roles ------------------------------------------------------ */

#define CHURN_LKEY 0x00000a0au
#define REKEYS     10000u
#define CHURNS     2000u

/*
 * The target's last part, on a new service QP: a window is re-keyed
 * REKEYS times over the channel, which must take no table entry, then
 * closed and registered again CHURNS times the way a guest does it
 * (MR_DEREG, DESTROY_MR, CREATE_MR with a new key byte, MR_REG), which with
 * this test's 50 ms quarantine must hold no more than that quarantine's
 * worth of entries, and give them all back.
 */
static void rekey_churn(struct node *n)
{
    const uint32_t acc =
        UET_ERNIC_ACC_REMOTE_WRITE | UET_ERNIC_ACC_IDEMPOTENT_SAFE;
    struct report *rep = n->rep;
    struct uet_ernic_release q;
    struct uet_ernic_reply r;
    struct uet_engine_stats es;
    struct uet_svc_stats ss;
    struct region win;
    uint32_t h, lkey = CHURN_LKEY, mrs0;
    uint64_t key = 0, prev;
    int st;

    region_init(&win, TGT_OFF, TGT_LEN);
    region_register(n->dp, &win, lkey);
    expect(n, mr_reg(n, lkey, acc, &h, &key), 0, "MR_REG of a window");
    uet_engine_get_stats(n->e, &es);
    mrs0 = es.mrs;

    for (unsigned i = 0; i < REKEYS && rep->ok; i++) {
        prev = key;
        memset(&q, 0, sizeof(q));
        hdr_init(&q.hdr, UET_ERNIC_OP_MR_REKEY, ++n->next_cookie);
        q.handle = htole32(h);
        st = call(n, &q, sizeof(q), "MR_REKEY", &r);
        key = le64toh(r.u.mr_reg.rkey);
        if (st != 0 || le32toh(r.u.mr_reg.handle) != h || key == prev)
            fail(rep, "MR_REKEY %u: status %d, key %#" PRIx64, i, st, key);
    }
    uet_engine_get_stats(n->e, &es);
    if (es.mrs != mrs0 || es.mr_rekeys < REKEYS)
        fail(rep, "the re-keys left %u regions, not %u", es.mrs, mrs0);
    memset(&q, 0, sizeof(q));
    hdr_init(&q.hdr, UET_ERNIC_OP_MR_REKEY, ++n->next_cookie);
    q.handle = htole32(0x12345u);
    expect(n, call(n, &q, sizeof(q), "MR_REKEY", NULL), EBADF,
           "MR_REKEY of a handle never handed out");

    for (unsigned i = 0; i < CHURNS && rep->ok; i++) {
        expect(n, release(n, UET_ERNIC_OP_MR_DEREG, h), 0, "MR_DEREG");
        ionic_datapath_unregister_mr(n->dp, lkey);
        lkey = CHURN_LKEY | ((i + 1u) & 0xffu) << 24;
        region_register(n->dp, &win, lkey);
        expect(n, mr_reg(n, lkey, acc, &h, NULL), 0, "MR_REG again");
        uet_engine_get_stats(n->e, &es);
        if (es.mrs > rep->churn_peak)
            rep->churn_peak = es.mrs;
    }
    pump_for(n, 100.0);
    uet_engine_get_stats(n->e, &es);
    uet_svc_get_stats(n->dp->uet_svc, &ss);
    if (es.mrs != mrs0 || es.mrs_quarantined != 0 || es.mrs_held != 0 ||
        ss.mrs != 1 || ss.mrs_dead != 0)
        fail(rep,
             "after the churn the engine holds %u regions (%u quarantined, "
             "%u held), %u before, and the channel %u (%u dead)",
             es.mrs, es.mrs_quarantined, es.mrs_held, mrs0, ss.mrs,
             ss.mrs_dead);
    expect(n, release(n, UET_ERNIC_OP_MR_DEREG, h), 0, "MR_DEREG");
    ionic_datapath_unregister_mr(n->dp, lkey);
}

static void run_target(struct node *n)
{
    struct report *rep = n->rep;
    struct region tgt;
    struct ctl m;
    uint32_t h;
    uint64_t rkey;

    if (!node_start(n, IP_TARGET))
        return;
    check_query(n, IP_TARGET);

    region_init(&tgt, TGT_OFF, TGT_LEN);
    region_register(n->dp, &tgt, TGT_LKEY);
    expect(n,
           mr_reg(n, TGT_LKEY,
                  UET_ERNIC_ACC_REMOTE_READ | UET_ERNIC_ACC_REMOTE_WRITE |
                      UET_ERNIC_ACC_IDEMPOTENT_SAFE,
                  &h, &rkey),
           0, "MR_REG of the target window");
    ctl_send(n, CTL_KEY, 0, rkey);

    if (!ctl_wait(n, CTL_VERIFY, &m))
        return;
    for (uint64_t off = 0; off < tgt.len; off++) {
        uint8_t want = 0;

        if (off >= T1 && off < T1 + HALF)
            want = pattern(off - T1);
        else if (off >= T2 && off < T2 + HALF)
            want = pattern(HALF + (off - T2));
        if (*region_byte(&tgt, off) != want) {
            if (rep->wrong++ == 0)
                fail(rep, "target byte %" PRIu64 " is wrong", off);
        } else if (want != 0 || (off >= T1 && off < T2 + HALF)) {
            rep->compared++;
        }
    }
    ctl_send(n, CTL_VERIFIED, rep->wrong == 0 ? 0 : -1, 0);

    /* Drop the service QP: its window goes with it. */
    if (!ctl_wait(n, CTL_DROP, &m))
        return;
    ionic_datapath_unregister_qp(n->dp, SVC_QP);
    struct uet_svc_stats st;
    uet_svc_get_stats(n->dp->uet_svc, &st);
    if (st.mrs != 0)
        fail(rep, "the window outlived its service QP");
    ctl_send(n, CTL_DROPPED, 0, 0);

    (void)ctl_wait(n, CTL_DONE, &m);
    for (uint64_t off = T4; off < T4 + T4_LEN; off++) {
        if (*region_byte(&tgt, off) != 0) {
            fail(rep, "a WRITE landed in a withdrawn window");
            break;
        }
    }
    /* ABORT: nothing of the WRITE taken back, all of the other group's. */
    for (uint64_t off = T5; off < T5 + T5_LEN; off++) {
        if (*region_byte(&tgt, off) != 0) {
            fail(rep, "a WRITE taken back by ABORT landed at byte %" PRIu64,
                 off - T5);
            break;
        }
    }
    for (uint64_t off = 0; off < T6_LEN; off++) {
        if (*region_byte(&tgt, T6 + off) != pattern(T5_LEN + off)) {
            fail(rep,
                 "the WRITE of the group not taken back is wrong at "
                 "byte %" PRIu64,
                 off);
            break;
        }
        rep->compared++;
    }
    pump_for(n, 100.0);

    svc_qp_create(n);
    rekey_churn(n);
}

static void run_initiator(struct node *n)
{
    struct report *rep = n->rep;
    struct region src;
    struct ctl m;
    uint32_t hs, hr, hp, hs2, hp2, hs3;
    uint64_t moved, rkey;
    struct uet_svc_stats st;
    struct uet_engine_stats es;
    int status;

    if (!node_start(n, IP_INITIATOR))
        return;

    capsule_checks(n);
    check_query(n, IP_INITIATOR);

    region_init(&src, SRC_OFF, SRC_LEN);
    for (uint64_t off = 0; off < SRC_LEN; off++)
        *region_byte(&src, off) = pattern(off);
    region_register(n->dp, &src, SRC_LKEY);
    struct ionic_dp_buf_desc rd = {
        .dma_addr = GPA_BASE + OFF_READ, .map_count = 1, .page_size_log2 = 12};
    ionic_datapath_register_mr(n->dp, READ_LKEY, READ_VA, READ_LEN, &rd);

    expect(n, mr_reg(n, SRC_LKEY, 0, &hs, NULL), 0, "MR_REG of the source");
    expect(n, mr_reg(n, READ_LKEY, 0, &hr, NULL), 0,
           "MR_REG of the READ buffer");
    expect(n, peer_add(n, IP_TARGET, &hp), 0, "PEER_ADD");

    if (!ctl_wait(n, CTL_KEY, &m))
        return;
    rkey = m.rkey;

    /* One RUDI and one RUD WRITE in flight together; the first one also
     * waits on ARP inside the device. */
    double t0 = now_ms_f();
    uint64_t w1 =
        rma_post(n, UET_ERNIC_OP_WRITE, hp, hs, 0, HALF, T1, rkey, true);
    uint64_t w2 =
        rma_post(n, UET_ERNIC_OP_WRITE, hp, hs, HALF, HALF, T2, rkey, false);
    expect(n, rma_wait(n, w1, "RUDI WRITE", &moved), 0, "RUDI WRITE");
    if (moved != HALF)
        fail(rep, "RUDI WRITE reported %" PRIu64 " bytes", moved);
    expect(n, rma_wait(n, w2, "RUD WRITE", &moved), 0, "RUD WRITE");
    if (moved != HALF)
        fail(rep, "RUD WRITE reported %" PRIu64 " bytes", moved);
    rep->write_ms = now_ms_f() - t0;

    /* Read some of it back, once each way. */
    uint64_t r1 = rma_post(n, UET_ERNIC_OP_READ, hp, hr, 0, READ_LEN / 2, T1,
                           rkey, false);
    expect(n, rma_wait(n, r1, "RUD READ", NULL), 0, "RUD READ");
    uint64_t r2 = rma_post(n, UET_ERNIC_OP_READ, hp, hr, READ_LEN / 2,
                           READ_LEN / 2, T2 + 1000u, rkey, true);
    expect(n, rma_wait(n, r2, "RUDI READ", NULL), 0, "RUDI READ");
    const uint8_t *back = gpa_ptr(GPA_BASE + OFF_READ, READ_LEN);
    for (uint64_t i = 0; i < READ_LEN / 2; i++) {
        if (back[i] != pattern(i) ||
            back[READ_LEN / 2 + i] != pattern(HALF + 1000u + i)) {
            fail(rep, "READ brought back the wrong bytes at %" PRIu64, i);
            break;
        }
    }

    ctl_send(n, CTL_VERIFY, 0, 0);
    if (!ctl_wait(n, CTL_VERIFIED, &m))
        return;
    if (m.status != 0)
        fail(rep, "the target's compare failed");

    /* DESTROY_MR while a WRITE from it is in flight: the device must stop
     * reading the pages before the destroy returns. */
    uint64_t w3 =
        rma_post(n, UET_ERNIC_OP_WRITE, hp, hs, 0, SRC_LEN, T3, rkey, false);
    ionic_datapath_unregister_mr(n->dp, SRC_LKEY);
    rep->status_mr_gone = rma_wait(n, w3, "WRITE from a destroyed MR", NULL);
    expect(n, rep->status_mr_gone, ECANCELED, "WRITE from a destroyed MR");
    uint64_t w3b =
        rma_post(n, UET_ERNIC_OP_WRITE, hp, hs, 0, 64, T3, rkey, false);
    expect(n, rma_wait(n, w3b, "WRITE from a dead handle", NULL), ECANCELED,
           "WRITE from a dead handle");
    expect(n, release(n, UET_ERNIC_OP_MR_DEREG, hs), 0,
           "MR_DEREG of a dead handle");
    uet_engine_get_stats(n->e, &es);
    rep->revoked_hits = es.revoked_hits;
    if (es.revoked_hits == 0)
        fail(rep, "the destroyed MR's page list was never refused");

    /* The same pages under a new key. */
    region_register(n->dp, &src, SRC2_LKEY);
    expect(n, mr_reg(n, SRC2_LKEY, 0, &hs2, NULL), 0, "MR_REG of SRC2");

    /* DESTROY_QP of the service QP while a WRITE is in flight, then the
     * same QP number again: nothing of the old session may reach it. */
    uint64_t w4 =
        rma_post(n, UET_ERNIC_OP_WRITE, hp, hs2, 0, HALF / 2, T1, rkey, true);
    ionic_datapath_unregister_qp(n->dp, SVC_QP);
    svc_qp_create(n);
    pump_for(n, 300.0);
    struct uet_ernic_reply r;
    if (take_reply(n, w4, &r))
        fail(rep, "a reply for a destroyed QP reached its successor");
    uint64_t old =
        rma_post(n, UET_ERNIC_OP_WRITE, hp, hs2, 0, 64, T1, rkey, false);
    expect(n, rma_wait(n, old, "WRITE with the old QP's handles", NULL), EBADF,
           "WRITE with the old QP's handles");
    for (double end = now_ms_f() + 3000.0; now_ms_f() < end;) {
        uet_engine_get_stats(n->e, &es);
        if (es.ops_in_flight == 0)
            break;
        pump(n);
    }
    if (es.ops_in_flight != 0)
        fail(rep, "the orphaned WRITE never drained");

    /* ABORT: two RUDI WRITEs in two groups while the wire loses every
     * frame, then ABORT of the first group.  Its WRITE is answered,
     * ECANCELED, ahead of the ABORT; the wire comes back, the other WRITE
     * lands, and nothing of the first ever does (the target checks). */
    {
        uint32_t ha, hpa;
        struct uet_ernic_reply ar, wr;

        uet_svc_get_stats(n->dp->uet_svc, &st);
        uint64_t aborted0 = st.ops_aborted; /* the orphan above counts */
        expect(n, mr_reg(n, SRC2_LKEY, 0, &ha, NULL), 0, "MR_REG for ABORT");
        expect(n, peer_add(n, IP_TARGET, &hpa), 0, "PEER_ADD for ABORT");
        n->wire_down = true;
        uint64_t wa = rma_post_group(n, UET_ERNIC_OP_WRITE, hpa, ha, 0, T5_LEN,
                                     T5, rkey, true, 7);
        uint64_t wb = rma_post_group(n, UET_ERNIC_OP_WRITE, hpa, ha, T5_LEN,
                                     T6_LEN, T6, rkey, true, 8);
        /* Sent, lost and resent, within the retry budget (20 ms x 10). */
        pump_for(n, 60.0);
        expect(n, abort_group(n, 7, 0, &ar), 0, "ABORT of group 7");
        rep->abort_count = le32toh(ar.u.abort.count);
        if (rep->abort_count != 1)
            fail(rep, "ABORT took %u transfers back, not 1", rep->abort_count);
        /* Replies go out in order: the WRITE's is in already. */
        if (!take_reply(n, wa, &wr)) {
            fail(rep, "the WRITE taken back was not answered ahead of the "
                      "ABORT");
        } else {
            rep->status_aborted = (int32_t)le32toh((uint32_t)wr.status);
            expect(n, rep->status_aborted, ECANCELED, "WRITE taken back");
        }
        n->wire_down = false;
        expect(n, rma_wait(n, wb, "WRITE of the other group", NULL), 0,
               "WRITE of the other group");
        /* A retransmission of the first would land now. */
        pump_for(n, 300.0);
        uet_svc_get_stats(n->dp->uet_svc, &st);
        uet_engine_get_stats(n->e, &es);
        if (st.ops_aborted - aborted0 != 1 || es.ops_aborted < 1)
            fail(rep,
                 "%" PRIu64 " transfers taken back, %" PRIu64
                 " engine operations",
                 st.ops_aborted - aborted0, es.ops_aborted);
        /* The same peer at once, on a new group: it carries on. */
        uint64_t wc = rma_post_group(n, UET_ERNIC_OP_WRITE, hpa, ha, T5_LEN,
                                     T6_LEN, T6, rkey, true, 9);
        expect(n, rma_wait(n, wc, "WRITE on a new group", NULL), 0,
               "WRITE on a new group after ABORT");

        /* ABORT of every group: both answered ECANCELED, count 2. */
        n->wire_down = true;
        uint64_t w10 = rma_post_group(n, UET_ERNIC_OP_WRITE, hpa, ha, 0,
                                      T5_LEN / 2, T5, rkey, true, 10);
        uint64_t w11 =
            rma_post_group(n, UET_ERNIC_OP_WRITE, hpa, ha, 0, T5_LEN / 2,
                           T5 + T5_LEN / 2, rkey, false, 11);
        pump_for(n, 30.0);
        expect(n, abort_group(n, 0, UET_ERNIC_ABORT_ALL, &ar), 0,
               "ABORT of every group");
        if (le32toh(ar.u.abort.count) != 2)
            fail(rep, "ABORT of every group took %u back",
                 le32toh(ar.u.abort.count));
        if (!take_reply(n, w10, &wr) ||
            (int32_t)le32toh((uint32_t)wr.status) != ECANCELED ||
            !take_reply(n, w11, &wr) ||
            (int32_t)le32toh((uint32_t)wr.status) != ECANCELED)
            fail(rep, "a WRITE taken back by ABORT_ALL was not answered "
                      "ECANCELED ahead of it");
        n->wire_down = false;

        /* A WRITE still in the device, waiting for ARP of a peer that
         * never answers: taken back at once. */
        uint32_t hnobody;
        expect(n, peer_add(n, IP_NOBODY, &hnobody), 0, "PEER_ADD of nobody");
        uint64_t wn = rma_post_group(n, UET_ERNIC_OP_WRITE, hnobody, ha, 0,
                                     4096, T5, rkey, true, 12);
        pump_for(n, 50.0);
        double ta = now_ms_f();
        expect(n, abort_group(n, 12, 0, &ar), 0, "ABORT of a waiting WRITE");
        rep->abort_wait_ms = now_ms_f() - ta;
        if (le32toh(ar.u.abort.count) != 1 || !take_reply(n, wn, &wr) ||
            (int32_t)le32toh((uint32_t)wr.status) != ECANCELED)
            fail(rep, "the WRITE waiting for ARP was not taken back");
        expect(n, release(n, UET_ERNIC_OP_PEER_REMOVE, hnobody), 0,
               "PEER_REMOVE of nobody");

        /* No room for the answers: 15 replies wait for receives, so an
         * ABORT with one transfer to take back (2 answers) does not fit
         * the 16-reply queue.  It is answered EAGAIN and takes nothing
         * back; sent again with receives posted, it does. */
        n->auto_repost = false;
        while (n->recvs_out > 0) {
            struct uet_ernic_hdr qh;

            hdr_init(&qh, UET_ERNIC_OP_QUERY, ++n->next_cookie);
            (void)call(n, &qh, sizeof(qh), "QUERY", NULL);
        }
        uint64_t first_q = n->next_cookie + 1;
        for (int i = 0; i < 15; i++) {
            struct uet_ernic_hdr qh;

            hdr_init(&qh, UET_ERNIC_OP_QUERY, ++n->next_cookie);
            post_send(n, &qh, sizeof(qh));
        }
        n->wire_down = true;
        uint64_t wf = rma_post_group(n, UET_ERNIC_OP_WRITE, hpa, ha, 0, 4096,
                                     T5, rkey, true, 13);
        struct uet_ernic_abort aq;
        uint64_t a1 = ++n->next_cookie;
        memset(&aq, 0, sizeof(aq));
        hdr_init(&aq.hdr, UET_ERNIC_OP_ABORT, a1);
        aq.group = htole32(13);
        post_send(n, &aq, sizeof(aq));
        pump_for(n, 20.0);
        n->auto_repost = true;
        while (n->recvs_out < RECVS)
            post_recv(n);
        for (uint64_t c = first_q; c < first_q + 15; c++)
            if (!wait_reply(n, c, 5000.0, &wr))
                fail(rep, "a waiting QUERY reply never arrived");
        if (!wait_reply(n, a1, 5000.0, &ar) ||
            (int32_t)le32toh((uint32_t)ar.status) != EAGAIN)
            fail(rep, "an ABORT without room for its answers was not "
                      "answered EAGAIN");
        if (take_reply(n, wf, &wr))
            fail(rep, "an ABORT answered EAGAIN took a transfer back");
        expect(n, abort_group(n, 13, 0, &ar), 0, "ABORT sent again");
        if (le32toh(ar.u.abort.count) != 1 || !take_reply(n, wf, &wr) ||
            (int32_t)le32toh((uint32_t)wr.status) != ECANCELED)
            fail(rep, "the ABORT sent again did not take the WRITE back");
        n->wire_down = false;
        uet_svc_get_stats(n->dp->uet_svc, &st);
        rep->aborts_deferred = st.aborts_deferred;
        if (st.aborts_deferred != 1)
            fail(rep, "%" PRIu64 " ABORTs deferred, not 1", st.aborts_deferred);

        expect(n, release(n, UET_ERNIC_OP_MR_DEREG, ha), 0,
               "MR_DEREG after ABORT");
        expect(n, release(n, UET_ERNIC_OP_PEER_REMOVE, hpa), 0,
               "PEER_REMOVE after ABORT");
    }

    /* The target drops its service QP, and with it the window. */
    ctl_send(n, CTL_DROP, 0, 0);
    if (!ctl_wait(n, CTL_DROPPED, &m))
        return;
    expect(n, mr_reg(n, SRC2_LKEY, 0, &hs3, NULL), 0, "MR_REG again");
    expect(n, peer_add(n, IP_TARGET, &hp2), 0, "PEER_ADD again");
    uint64_t w5 =
        rma_post(n, UET_ERNIC_OP_WRITE, hp2, hs3, 0, T4_LEN, T4, rkey, false);
    status = rma_wait(n, w5, "WRITE into a withdrawn window", NULL);
    rep->status_window_gone = status;
    if (status <= 0)
        fail(rep, "a WRITE into a withdrawn window reported %d", status);

    expect(n, release(n, UET_ERNIC_OP_MR_DEREG, hs3), 0, "MR_DEREG");
    expect(n, release(n, UET_ERNIC_OP_PEER_REMOVE, hp2), 0, "PEER_REMOVE");
    ctl_send(n, CTL_DONE, 0, 0);

    /* Everything is handed back once the quarantine has passed. */
    pump_for(n, 300.0);
    uet_svc_get_stats(n->dp->uet_svc, &st);
    uet_engine_get_stats(n->e, &es);
    rep->replies_discarded = st.replies_discarded;
    if (st.mrs || st.peers || st.ops_queued || st.ops_posted ||
        st.replies_pending)
        fail(rep,
             "the command channel kept state: %u MRs %u peers %u ops "
             "%u replies",
             st.mrs, st.peers, st.ops_queued + st.ops_posted,
             st.replies_pending);
    if (es.mrs || es.peers || es.ops_in_flight)
        fail(rep, "the engine kept state: %u MRs %u peers %u ops", es.mrs,
             es.peers, es.ops_in_flight);
}

/* ---- Driver ------------------------------------------------------------- */

static pid_t spawn(bool target, int wire_fd, int ctl_fd, int rep_fd,
                   const int *others, size_t nothers, char *log, size_t loglen)
{
    const char *tmp = getenv("TMPDIR");

    snprintf(log, loglen, "%s/uet-datapath-%s-%d.log",
             tmp != NULL ? tmp : "/tmp", target ? "target" : "initiator",
             (int)getpid());
    fflush(NULL);
    pid_t pid = fork();
    if (pid != 0)
        return pid;

    struct node n;
    struct report rep;

    for (size_t i = 0; i < nothers; i++)
        close(others[i]);
    alarm(CASE_TIMEOUT_S);
    int fd = open(log, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd >= 0) {
        dup2(fd, STDOUT_FILENO);
        dup2(fd, STDERR_FILENO);
        close(fd);
    }

    memset(&n, 0, sizeof(n));
    memset(&rep, 0, sizeof(rep));
    rep.ok = 1;
    n.rep = &rep;
    n.wire_fd = wire_fd;
    n.ctl_fd = ctl_fd;
    n.next_cookie = target ? 0x7000000 : 0x1000000;

    if (target)
        run_target(&n);
    else
        run_initiator(&n);
    node_finish(&n);

    if (write(rep_fd, &rep, sizeof(rep)) != (ssize_t)sizeof(rep))
        rep.ok = 0;
    fflush(NULL);
    exit(rep.ok ? 0 : 1);
}

static bool read_report(int fd, struct report *rep)
{
    size_t got = 0;

    while (got < sizeof(*rep)) {
        ssize_t r = read(fd, (uint8_t *)rep + got, sizeof(*rep) - got);
        if (r <= 0)
            return false;
        got += (size_t)r;
    }
    return true;
}

static void dump_log(const char *log)
{
    char line[512];
    FILE *f = fopen(log, "r");

    if (f == NULL)
        return;
    printf("    --- %s ---\n", log);
    while (fgets(line, sizeof(line), f) != NULL)
        printf("    %s", line);
    fclose(f);
}

int main(void)
{
    int wire[2], ctl[2], rp_ini[2], rp_tgt[2];
    char log_ini[256], log_tgt[256];
    struct report ini, tgt;
    int st_ini = 0, st_tgt = 0;

    signal(SIGPIPE, SIG_IGN);
    printf("case svc-channel: capsules through ionic rings, two engines\n");
    fflush(stdout);

    if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, wire) != 0 ||
        socketpair(AF_UNIX, SOCK_SEQPACKET, 0, ctl) != 0 || pipe(rp_ini) != 0 ||
        pipe(rp_tgt) != 0) {
        printf("  FAIL: %s\n", strerror(errno));
        return 1;
    }
    for (int i = 0; i < 2; i++) {
        int sz = 4 * 1024 * 1024;
        (void)setsockopt(wire[i], SOL_SOCKET, SO_SNDBUF, &sz, sizeof(sz));
        (void)setsockopt(wire[i], SOL_SOCKET, SO_RCVBUF, &sz, sizeof(sz));
    }

    const int not_tgt[] = {wire[0], ctl[0], rp_tgt[0], rp_ini[0], rp_ini[1]};
    const int not_ini[] = {wire[1], ctl[1], rp_ini[0], rp_tgt[0], rp_tgt[1]};
    pid_t tgt_pid = spawn(true, wire[1], ctl[1], rp_tgt[1], not_tgt, 5, log_tgt,
                          sizeof(log_tgt));
    pid_t ini_pid = spawn(false, wire[0], ctl[0], rp_ini[1], not_ini, 5,
                          log_ini, sizeof(log_ini));
    close(wire[0]);
    close(wire[1]);
    close(ctl[0]);
    close(ctl[1]);
    close(rp_ini[1]);
    close(rp_tgt[1]);

    memset(&ini, 0, sizeof(ini));
    memset(&tgt, 0, sizeof(tgt));
    bool have_ini = read_report(rp_ini[0], &ini);
    bool have_tgt = read_report(rp_tgt[0], &tgt);
    (void)waitpid(ini_pid, &st_ini, 0);
    (void)waitpid(tgt_pid, &st_tgt, 0);

    bool ok = have_ini && have_tgt && ini.ok && tgt.ok && WIFEXITED(st_ini) &&
              WEXITSTATUS(st_ini) == 0 && WIFEXITED(st_tgt) &&
              WEXITSTATUS(st_tgt) == 0;

    if (have_ini && have_tgt) {
        printf("  2 x 512 KiB WRITE (RUDI + RUD) in %.1f ms, 2 x 32 KiB READ "
               "back; target compared %" PRIu64 " bytes, %" PRIu64 " wrong\n",
               ini.write_ms, tgt.compared, tgt.wrong);
        printf("  WRITE from an MR destroyed mid-flight: %s; page-list "
               "reads refused: %" PRIu64 "\n",
               ini.status_mr_gone > 0 ? strerror(ini.status_mr_gone) : "ok",
               ini.revoked_hits);
        printf("  WRITE into a window whose service QP was destroyed: %s\n",
               ini.status_window_gone > 0 ? strerror(ini.status_window_gone)
                                          : "ok");
        printf("  ABORT of one of two groups on a dead wire: %u taken back, "
               "answered %s; the other group landed; target compared "
               "%" PRIu64 " bytes in all\n",
               ini.abort_count,
               ini.status_aborted > 0 ? strerror(ini.status_aborted) : "ok",
               tgt.compared);
        printf("  then a WRITE on a new group, ABORT of every group, ABORT "
               "of a WRITE waiting for ARP (%.1f ms), and %" PRIu64
               " ABORT answered EAGAIN with a full reply queue\n",
               ini.abort_wait_ms, ini.aborts_deferred);
        printf("  %u MR_REKEY took no entry; %u MR_DEREG + DESTROY_MR + "
               "CREATE_MR + MR_REG held at most %u engine entries (50 ms "
               "quarantine) and gave them all back\n",
               REKEYS, CHURNS, tgt.churn_peak);
        printf("  initiator channel: %" PRIu64 " commands, %" PRIu64
               " replies, %" PRIu64 " waited for a receive, %" PRIu64
               " discarded, %" PRIu64 " dropped\n",
               ini.svc.commands, ini.svc.replies, ini.svc.replies_waited,
               ini.svc.replies_discarded, ini.svc.dropped);
        printf("  initiator engine: %" PRIu64 " ops posted, %" PRIu64
               " completed, %" PRIu64 " failed\n",
               ini.eng.ops_posted, ini.eng.ops_completed, ini.eng.ops_failed);
    }

    if (ok) {
        printf("  PASS\n\n1/1 cases passed\n");
        unlink(log_ini);
        unlink(log_tgt);
        return 0;
    }
    if (!have_ini || !have_tgt)
        printf("  FAIL: a process died without reporting (initiator %#x, "
               "target %#x)\n",
               (unsigned)st_ini, (unsigned)st_tgt);
    else if (!ini.ok)
        printf("  FAIL: initiator: %s\n", ini.why);
    else if (!tgt.ok)
        printf("  FAIL: target: %s\n", tgt.why);
    else
        printf("  FAIL: a process exited badly\n");
    dump_log(log_ini);
    dump_log(log_tgt);
    printf("\n0/1 cases passed\n");
    return 1;
}
