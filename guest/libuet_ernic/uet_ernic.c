/*
 * uet_ernic.c -- libuet_ernic: the UET API on an ernic engine
 *
 * Copyright (c) Advanced Micro Devices, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: MIT
 *
 * See uet_ernic.h for what this implements and uet_ernic_abi.h for the
 * command channel underneath it.
 *
 * One instance (uet_initialize) owns one RC queue pair on the ionic
 * device, connected to the engine's service QPN, and a registered buffer of
 * capsule slots: a send slot for every command in flight and a receive
 * slot, always posted, for every reply. Commands that the engine answers at
 * once are waited for; WRITE and READ are answered on completion, and the
 * answer becomes a completion queue entry of the endpoint that posted them.
 * Progress, and every verbs call, happens under one lock per instance.
 */

#include <endian.h>
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <infiniband/verbs.h>
#include <rdma/fi_errno.h>

#include "uet_ernic.h"
#include "uet_ernic_abi.h"

#define SLOTS        64u /* commands in flight per instance */
#define AUTO_MRS     16u /* local buffers registered on demand */
#define AUTO_WINDOW  (2u * 1024u * 1024u)
#define CQ_DEPTH     (2u * SLOTS)
#define SEND_TAG     (UINT64_C(1) << 63)
#define SYNC_WAIT_MS 10000u
#define PENDING      (2u * SLOTS)

enum pend_kind {
    PEND_FREE = 0,
    PEND_SYNC, /* a caller is waiting for the reply */
    PEND_RMA,  /* the reply is a completion for an endpoint */
};

/*
 * A local buffer registered on demand, for a uet_write() or uet_read()
 * given no memory region: the engine moves only registered memory, and the
 * reference API lets the caller pass none.  Kept and reused, so a buffer
 * written in segments is registered once.
 */
struct auto_mr {
    bool used;
    uintptr_t start;
    size_t len;
    struct ibv_mr *ibmr;
    uint32_t handle;
    unsigned refs; /* transfers in flight from it */
    uint64_t last_use;
};

struct pending {
    enum pend_kind kind;
    uint8_t gen;
    bool done;
    struct uet_ernic_reply reply; /* PEND_SYNC */
    struct uet_ernic_ep *ep;      /* PEND_RMA */
    void *context;
    uint64_t len;
    uint64_t flags;          /* FI_RMA | FI_WRITE or FI_READ */
    struct auto_mr *auto_mr; /* PEND_RMA from an unregistered buffer */
};

struct uet_ernic_dev {
    pthread_mutex_t lock;
    struct ibv_context *ctx;
    struct ibv_pd *pd;
    struct ibv_cq *cq;
    struct ibv_qp *qp;
    uint8_t *slots; /* SLOTS send capsules, then SLOTS receive capsules */
    struct ibv_mr *slots_mr;
    uint64_t send_busy; /* bit per send slot */
    struct pending pend[PENDING];
    struct auto_mr auto_mrs[AUTO_MRS];
    uint64_t use_clock;
    bool auto_cache; /* keep on-demand registrations (UET_ERNIC_MR_CACHE) */

    /* From QUERY. */
    uint32_t ipv4;
    uint16_t pid_on_fep;
    uint16_t resource_index;
    uint32_t job_id;
    uint32_t initiator_id;
    uint32_t caps;

    bool broken; /* the service QP failed; nothing more will complete */
};

struct uet_ernic_dom {
    struct uet_ernic_dev *dev;
    unsigned refs; /* MRs, endpoints and addresses */
};

struct uet_ernic_cq {
    struct uet_ernic_ep *ep;
    enum fi_cq_format format;
    size_t entry_size;
    /* A ring of completions; err[] holds the error entry of a failed
     * one, which is reported in its turn, as the reference does. */
    uint8_t *ring;
    struct fi_cq_err_entry *err;
    bool *is_err;
    size_t size;
    size_t head;
    size_t count;
};

struct uet_ernic_ep {
    struct uet_ernic_dom *dom;
    struct uet_ernic_cq *tx_cq;
    struct uet_ernic_cq *rx_cq;
    bool enabled;
    bool rudi;
    unsigned in_flight;
};

struct uet_ernic_mr {
    struct uet_ernic_dom *dom;
    struct ibv_mr *ibmr;
    uint32_t handle; /* the engine's */
    uint64_t rkey;   /* what peers name it by */
    const uint8_t *buf;
    size_t len;
    struct uet_ernic_ep *ep;
    bool enabled;
};

struct uet_ernic_av {
    struct uet_ernic_dom *dom;
    uint32_t handle;
};

static int errno_to_fi(int status)
{
    /* Fabric errnos are Linux errnos for every value the device sends. */
    return status > 0 ? -status : -FI_EIO;
}

static uint64_t now_ms(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

/* ------------------------------------------------------------------ */
/* Completion queues                                                  */
/* ------------------------------------------------------------------ */

static size_t cq_entry_size(enum fi_cq_format format)
{
    switch (format) {
    case FI_CQ_FORMAT_UNSPEC:
    case FI_CQ_FORMAT_CONTEXT:
        return sizeof(struct fi_cq_entry);
    case FI_CQ_FORMAT_MSG:
        return sizeof(struct fi_cq_msg_entry);
    case FI_CQ_FORMAT_DATA:
        return sizeof(struct fi_cq_data_entry);
    case FI_CQ_FORMAT_TAGGED:
        return sizeof(struct fi_cq_tagged_entry);
    default:
        return 0;
    }
}

static void cq_push(struct uet_ernic_cq *cq, void *context, uint64_t flags,
                    uint64_t len, int status)
{
    size_t slot;
    struct fi_cq_tagged_entry e; /* the largest; the others are prefixes */

    if (cq == NULL || cq->count == cq->size)
        return; /* sized for every operation the endpoint can have */
    slot = (cq->head + cq->count) % cq->size;

    memset(&e, 0, sizeof(e));
    e.op_context = context;
    e.flags = flags;
    e.len = status == 0 ? (size_t)len : 0;
    memcpy(cq->ring + slot * cq->entry_size, &e, cq->entry_size);

    cq->is_err[slot] = status != 0;
    if (status != 0) {
        memset(&cq->err[slot], 0, sizeof(cq->err[slot]));
        cq->err[slot].op_context = context;
        cq->err[slot].flags = flags;
        cq->err[slot].err = status;
        cq->err[slot].prov_errno = status;
    }
    cq->count++;
}

/* ------------------------------------------------------------------ */
/* The service QP                                                     */
/* ------------------------------------------------------------------ */

static uint8_t *send_slot(struct uet_ernic_dev *d, unsigned i)
{
    return d->slots + (size_t)i * UET_ERNIC_CAPSULE_SIZE;
}

static uint8_t *recv_slot(struct uet_ernic_dev *d, unsigned i)
{
    return d->slots + (size_t)(SLOTS + i) * UET_ERNIC_CAPSULE_SIZE;
}

static int post_recv(struct uet_ernic_dev *d, unsigned i)
{
    uint8_t *buf = recv_slot(d, i);
    struct ibv_sge sge = {
        .addr = (uintptr_t)buf,
        .length = UET_ERNIC_CAPSULE_SIZE,
        .lkey = d->slots_mr->lkey,
    };
    struct ibv_recv_wr wr = {.wr_id = i, .sg_list = &sge, .num_sge = 1};
    struct ibv_recv_wr *bad = NULL;

    return ibv_post_recv(d->qp, &wr, &bad);
}

/* A reply has arrived: hand it to whoever is waiting for it. */
static void dispatch(struct uet_ernic_dev *d, const uint8_t *capsule)
{
    struct uet_ernic_reply r;
    struct pending *p;
    uint64_t cookie;

    memcpy(&r, capsule, sizeof(r));
    if (le32toh(r.hdr.magic) != UET_ERNIC_MAGIC ||
        (r.hdr.flags & UET_ERNIC_F_REPLY) == 0)
        return;

    cookie = le64toh(r.hdr.cookie);
    if ((cookie & 0xffu) >= PENDING)
        return;
    p = &d->pend[cookie & 0xffu];
    if (p->kind == PEND_FREE || p->gen != (uint8_t)(cookie >> 8))
        return;

    if (p->kind == PEND_SYNC) {
        p->reply = r;
        p->done = true;
        return;
    }

    int status = (int32_t)le32toh((uint32_t)r.status);
    cq_push(p->ep->tx_cq, p->context, p->flags, p->len, status);
    p->ep->in_flight--;
    if (p->auto_mr != NULL)
        p->auto_mr->refs--;
    p->auto_mr = NULL;
    p->kind = PEND_FREE;
}

/* Reap the service QP's completions.  Called with the lock held. */
static void progress(struct uet_ernic_dev *d)
{
    struct ibv_wc wc[16];
    int n;

    while ((n = ibv_poll_cq(d->cq, 16, wc)) > 0) {
        for (int i = 0; i < n; i++) {
            if (wc[i].status != IBV_WC_SUCCESS) {
                /* A failed service QP is a dead device. */
                d->broken = true;
                continue;
            }
            if (wc[i].wr_id & SEND_TAG) {
                d->send_busy &= ~(UINT64_C(1) << (wc[i].wr_id & 63u));
                continue;
            }
            unsigned slot = (unsigned)(wc[i].wr_id % SLOTS);
            dispatch(d, recv_slot(d, slot));
            if (post_recv(d, slot) != 0)
                d->broken = true;
        }
    }
    if (n < 0)
        d->broken = true;
}

static struct pending *pend_alloc(struct uet_ernic_dev *d, uint64_t *cookie)
{
    for (unsigned i = 0; i < PENDING; i++) {
        if (d->pend[i].kind == PEND_FREE) {
            d->pend[i].gen++;
            d->pend[i].done = false;
            *cookie = ((uint64_t)d->pend[i].gen << 8) | i;
            return &d->pend[i];
        }
    }
    return NULL;
}

/*
 * Send one capsule.  Needs a free send slot and a free reply slot; there is
 * one receive posted per reply slot, so a command may only go out while
 * fewer than SLOTS are unanswered.  Called with the lock held.
 */
static int send_capsule(struct uet_ernic_dev *d, const void *capsule,
                        size_t len)
{
    unsigned slot, unanswered = 0;

    if (d->broken)
        return -FI_EIO;
    for (unsigned i = 0; i < PENDING; i++)
        unanswered += d->pend[i].kind != PEND_FREE ? 1u : 0u;
    if (unanswered > SLOTS)
        return -FI_EAGAIN;

    for (slot = 0; slot < SLOTS; slot++) {
        if ((d->send_busy & (UINT64_C(1) << slot)) == 0)
            break;
    }
    if (slot == SLOTS) {
        progress(d);
        return -FI_EAGAIN;
    }

    uint8_t *buf = send_slot(d, slot);

    memset(buf, 0, UET_ERNIC_CAPSULE_SIZE);
    memcpy(buf, capsule, len);

    struct ibv_sge sge = {
        .addr = (uintptr_t)buf,
        .length = (uint32_t)len,
        .lkey = d->slots_mr->lkey,
    };
    struct ibv_send_wr wr = {
        .wr_id = SEND_TAG | slot,
        .sg_list = &sge,
        .num_sge = 1,
        .opcode = IBV_WR_SEND,
        .send_flags = IBV_SEND_SIGNALED,
    };
    struct ibv_send_wr *bad = NULL;

    if (ibv_post_send(d->qp, &wr, &bad) != 0)
        return -FI_EIO;
    d->send_busy |= UINT64_C(1) << slot;
    return 0;
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
 * Send a command and wait for its reply.  @capsule starts with a header
 * whose cookie this fills in.  Returns 0 or a negative fabric errno, the
 * reply in @out.  Called with the lock held.
 */
static int call(struct uet_ernic_dev *d, void *capsule, size_t len,
                struct uet_ernic_reply *out)
{
    struct uet_ernic_hdr h;
    struct pending *p;
    uint64_t cookie, deadline;
    int rc;

    p = pend_alloc(d, &cookie);
    if (p == NULL)
        return -FI_EAGAIN;
    p->kind = PEND_SYNC;

    memcpy(&h, capsule, sizeof(h));
    h.cookie = htole64(cookie);
    memcpy(capsule, &h, sizeof(h));

    deadline = now_ms() + SYNC_WAIT_MS;
    while ((rc = send_capsule(d, capsule, len)) == -FI_EAGAIN) {
        if (now_ms() > deadline)
            break;
        progress(d);
    }
    if (rc != 0) {
        p->kind = PEND_FREE;
        return rc;
    }

    while (!p->done && !d->broken) {
        if (now_ms() > deadline) {
            /* The reply may still come; it will find nobody waiting. */
            p->kind = PEND_FREE;
            return -FI_ETIMEDOUT;
        }
        progress(d);
    }
    p->kind = PEND_FREE;
    if (!p->done)
        return -FI_EIO;

    *out = p->reply;
    rc = (int32_t)le32toh((uint32_t)p->reply.status);
    return rc == 0 ? 0 : errno_to_fi(rc);
}

/* ------------------------------------------------------------------ */
/* Local buffers registered on demand                                 */
/* ------------------------------------------------------------------ */

/*
 * The mapping containing @addr, from /proc/self/maps.  A registration may
 * grow past the buffer it is for, but never past the mapping, which is the
 * memory ibv_reg_mr() is sure to accept.
 */
static bool vma_of(uintptr_t addr, uintptr_t *lo, uintptr_t *hi)
{
    char line[512];
    FILE *f = fopen("/proc/self/maps", "r");
    bool found = false;

    if (f == NULL)
        return false;
    while (!found && fgets(line, sizeof(line), f) != NULL) {
        unsigned long a, b;

        if (sscanf(line, "%lx-%lx", &a, &b) == 2 && addr >= a && addr < b) {
            *lo = a;
            *hi = b;
            found = true;
        }
    }
    fclose(f);
    return found;
}

static int auto_mr_drop(struct uet_ernic_dev *d, struct auto_mr *a)
{
    struct uet_ernic_release q;
    struct uet_ernic_reply r;
    int rc;

    memset(&q, 0, sizeof(q));
    hdr_init(&q.hdr, UET_ERNIC_OP_MR_DEREG, 0);
    q.handle = htole32(a->handle);
    rc = call(d, &q, sizeof(q), &r);
    (void)ibv_dereg_mr(a->ibmr);
    memset(a, 0, sizeof(*a));
    return rc;
}

/*
 * A registration covering [@buf, @buf + @len): an existing one, or a new
 * one over the 2 MiB-aligned window around it, clipped to its mapping, so
 * the segments of one buffer share it.  Called with the lock held.
 */
static int auto_mr_get(struct uet_ernic_dev *d, const uint8_t *buf, size_t len,
                       struct auto_mr **out)
{
    uintptr_t b = (uintptr_t)buf, lo, hi, start, end;
    struct auto_mr *a = NULL, *victim = NULL;
    struct uet_ernic_mr_reg q;
    struct uet_ernic_reply r;
    int rc;

    for (unsigned i = 0; i < AUTO_MRS; i++) {
        struct auto_mr *m = &d->auto_mrs[i];

        if (m->used && b >= m->start && len <= m->len &&
            b - m->start <= m->len - len) {
            m->last_use = ++d->use_clock;
            *out = m;
            return 0;
        }
        if (!m->used && a == NULL)
            a = m;
        else if (m->used && m->refs == 0 &&
                 (victim == NULL || m->last_use < victim->last_use))
            victim = m;
    }
    if (a == NULL) {
        if (victim == NULL)
            return -FI_EAGAIN; /* every one is in use; try again */
        rc = auto_mr_drop(d, victim);
        if (rc != 0 && rc != -FI_EBADF)
            return rc;
        a = victim;
    }

    start = b & ~(uintptr_t)4095u;
    end = (b + len + 4095u) & ~(uintptr_t)4095u;
    if (d->auto_cache && vma_of(b, &lo, &hi) && b + len <= hi) {
        uintptr_t wlo = b & ~(uintptr_t)(AUTO_WINDOW - 1u);
        uintptr_t whi =
            (b + len + AUTO_WINDOW - 1u) & ~(uintptr_t)(AUTO_WINDOW - 1u);

        start = wlo > lo ? wlo : lo;
        end = whi < hi ? whi : hi;
    }

    a->ibmr =
        ibv_reg_mr(d->pd, (void *)start, end - start, IBV_ACCESS_LOCAL_WRITE);
    if (a->ibmr == NULL)
        return -FI_ENOMEM;

    memset(&q, 0, sizeof(q));
    hdr_init(&q.hdr, UET_ERNIC_OP_MR_REG, 0);
    q.lkey = htole32(a->ibmr->lkey);
    rc = call(d, &q, sizeof(q), &r);
    if (rc != 0) {
        (void)ibv_dereg_mr(a->ibmr);
        a->ibmr = NULL;
        return rc;
    }
    a->used = true;
    a->start = start;
    a->len = end - start;
    a->handle = le32toh(r.u.mr_reg.handle);
    a->refs = 0;
    a->last_use = ++d->use_clock;
    *out = a;
    return 0;
}

/* Without the cache, a registration goes once its transfers are done. */
static void auto_mr_release(struct uet_ernic_dev *d)
{
    if (d->auto_cache)
        return;
    for (unsigned i = 0; i < AUTO_MRS; i++) {
        if (d->auto_mrs[i].used && d->auto_mrs[i].refs == 0)
            (void)auto_mr_drop(d, &d->auto_mrs[i]);
    }
}

/* ------------------------------------------------------------------ */
/* Instance                                                           */
/* ------------------------------------------------------------------ */

bool uet_ernic_device_match(const char *name)
{
    char path[256], vendor[16] = "";
    FILE *f;

    if (name == NULL)
        return false;
    if (strncmp(name, "ionic", 5) == 0)
        return true;
    /* Renamed by udev (rocm-ernic's rule calls it rocm-rdma-ernic0):
     * recognise it by the PCI function behind it. */
    if (strchr(name, '/') != NULL ||
        snprintf(path, sizeof(path), "/sys/class/infiniband/%s/device/vendor",
                 name) >= (int)sizeof(path))
        return false;
    f = fopen(path, "r");
    if (f == NULL)
        return false;
    if (fgets(vendor, sizeof(vendor), f) == NULL)
        vendor[0] = '\0';
    fclose(f);
    return strtoul(vendor, NULL, 16) == UET_ERNIC_PCI_VENDOR;
}

/* The named device, or else the first ionic one: no other kind of device
 * has an engine behind it. */
static struct ibv_device *pick_device(struct ibv_device **list, int n)
{
    const char *want = getenv("UET_ERNIC_DEVICE");

    for (int i = 0; i < n; i++) {
        const char *name = ibv_get_device_name(list[i]);

        if (want != NULL ? strcmp(name, want) == 0
                         : uet_ernic_device_match(name))
            return list[i];
    }
    return NULL;
}

/* INIT, RTR, RTS, aimed at the engine's service QPN on this device. */
static int connect_svc_qp(struct uet_ernic_dev *d)
{
    const char *env = getenv("UET_ERNIC_GID_INDEX");
    int gid_index = env != NULL ? atoi(env) : 0;
    union ibv_gid gid;
    struct ibv_qp_attr a;

    if (gid_index < 0 || gid_index > 255 ||
        ibv_query_gid(d->ctx, 1, gid_index, &gid) != 0)
        return -FI_ENODEV;

    memset(&a, 0, sizeof(a));
    a.qp_state = IBV_QPS_INIT;
    a.port_num = 1;
    if (ibv_modify_qp(d->qp, &a,
                      IBV_QP_STATE | IBV_QP_PKEY_INDEX | IBV_QP_PORT |
                          IBV_QP_ACCESS_FLAGS) != 0)
        return -FI_EIO;

    memset(&a, 0, sizeof(a));
    a.qp_state = IBV_QPS_RTR;
    a.path_mtu = IBV_MTU_1024;
    a.dest_qp_num = UET_ERNIC_SVC_QPN;
    a.min_rnr_timer = 12;
    a.ah_attr.is_global = 1;
    a.ah_attr.grh.dgid = gid; /* the engine lives in this device */
    a.ah_attr.grh.sgid_index = (uint8_t)gid_index;
    a.ah_attr.grh.hop_limit = 64;
    a.ah_attr.port_num = 1;
    if (ibv_modify_qp(d->qp, &a,
                      IBV_QP_STATE | IBV_QP_AV | IBV_QP_PATH_MTU |
                          IBV_QP_DEST_QPN | IBV_QP_RQ_PSN |
                          IBV_QP_MAX_DEST_RD_ATOMIC | IBV_QP_MIN_RNR_TIMER) !=
        0)
        return -FI_EIO;

    memset(&a, 0, sizeof(a));
    a.qp_state = IBV_QPS_RTS;
    a.timeout = 14;
    a.retry_cnt = 7;
    a.rnr_retry = 7;
    if (ibv_modify_qp(d->qp, &a,
                      IBV_QP_STATE | IBV_QP_TIMEOUT | IBV_QP_RETRY_CNT |
                          IBV_QP_RNR_RETRY | IBV_QP_SQ_PSN |
                          IBV_QP_MAX_QP_RD_ATOMIC) != 0)
        return -FI_EIO;
    return 0;
}

static void dev_free(struct uet_ernic_dev *d)
{
    for (unsigned i = 0; i < AUTO_MRS; i++) {
        /* The service QP's destruction below releases the engine's
         * handles; only the ionic registrations are left to undo. */
        if (d->auto_mrs[i].used)
            (void)ibv_dereg_mr(d->auto_mrs[i].ibmr);
    }
    if (d->qp != NULL)
        (void)ibv_destroy_qp(d->qp);
    if (d->slots_mr != NULL)
        (void)ibv_dereg_mr(d->slots_mr);
    if (d->cq != NULL)
        (void)ibv_destroy_cq(d->cq);
    if (d->pd != NULL)
        (void)ibv_dealloc_pd(d->pd);
    if (d->ctx != NULL)
        (void)ibv_close_device(d->ctx);
    free(d->slots);
    pthread_mutex_destroy(&d->lock);
    free(d);
}

int uet_initialize(uet_handle_t *handle)
{
    struct uet_ernic_dev *d;
    struct ibv_device **list;
    struct ibv_device *dev;
    struct uet_ernic_hdr h;
    struct uet_ernic_reply r;
    int n = 0, rc;

    if (handle == NULL)
        return -FI_EINVAL;

    d = calloc(1, sizeof(*d));
    if (d == NULL)
        return -FI_ENOMEM;
    pthread_mutex_init(&d->lock, NULL);
    {
        const char *cache = getenv("UET_ERNIC_MR_CACHE");

        d->auto_cache = cache == NULL || strcmp(cache, "0") != 0;
    }

    list = ibv_get_device_list(&n);
    dev = list != NULL ? pick_device(list, n) : NULL;
    d->ctx = dev != NULL ? ibv_open_device(dev) : NULL;
    if (list != NULL)
        ibv_free_device_list(list);
    if (d->ctx == NULL) {
        dev_free(d);
        return -FI_ENODEV;
    }

    d->pd = ibv_alloc_pd(d->ctx);
    d->cq =
        d->pd != NULL ? ibv_create_cq(d->ctx, CQ_DEPTH, NULL, NULL, 0) : NULL;
    d->slots = aligned_alloc(4096, 2u * SLOTS * UET_ERNIC_CAPSULE_SIZE);
    if (d->cq == NULL || d->slots == NULL) {
        dev_free(d);
        return -FI_ENOMEM;
    }
    memset(d->slots, 0, 2u * SLOTS * UET_ERNIC_CAPSULE_SIZE);
    d->slots_mr =
        ibv_reg_mr(d->pd, d->slots, 2u * SLOTS * UET_ERNIC_CAPSULE_SIZE,
                   IBV_ACCESS_LOCAL_WRITE);

    struct ibv_qp_init_attr qa = {
        .send_cq = d->cq,
        .recv_cq = d->cq,
        .cap = {.max_send_wr = SLOTS,
                .max_recv_wr = SLOTS,
                .max_send_sge = 1,
                .max_recv_sge = 1},
        .qp_type = IBV_QPT_RC,
    };
    d->qp = d->slots_mr != NULL ? ibv_create_qp(d->pd, &qa) : NULL;
    if (d->qp == NULL) {
        dev_free(d);
        return -FI_ENOMEM;
    }

    rc = connect_svc_qp(d);
    for (unsigned i = 0; rc == 0 && i < SLOTS; i++)
        rc = post_recv(d, i) == 0 ? 0 : -FI_EIO;
    if (rc != 0) {
        dev_free(d);
        return rc;
    }

    hdr_init(&h, UET_ERNIC_OP_QUERY, 0);
    rc = call(d, &h, sizeof(h), &r);
    if (rc == 0 && le16toh(r.u.query.abi_version) < UET_ERNIC_ABI_VERSION)
        rc = -FI_ENOSYS;
    if (rc != 0) {
        dev_free(d);
        return rc;
    }
    d->ipv4 = le32toh(r.u.query.ipv4);
    d->pid_on_fep = le16toh(r.u.query.pid_on_fep);
    d->resource_index = le16toh(r.u.query.resource_index);
    d->job_id = le32toh(r.u.query.job_id);
    d->initiator_id = le32toh(r.u.query.initiator_id);
    d->caps = le32toh(r.u.query.caps);

    *handle = d;
    return 0;
}

int uet_finalize(uet_handle_t handle)
{
    if (handle == NULL)
        return -FI_EINVAL;
    /* Destroying the service QP releases every handle the engine holds
     * for this instance. */
    dev_free(handle);
    return 0;
}

/* ------------------------------------------------------------------ */
/* Domain, regions, addresses                                         */
/* ------------------------------------------------------------------ */

int uet_domain(uet_handle_t handle, struct fid_fabric *fabric,
               struct fi_info *info, struct fid_domain *domain, void *context,
               uet_eq_callback_t eq_callback,
               uet_eq_err_callback_t eq_err_callback,
               uet_domain_handle_t *domain_handle)
{
    struct uet_ernic_dom *dom;

    (void)fabric;
    (void)info;
    (void)domain;
    (void)context;
    (void)eq_callback;
    (void)eq_err_callback;
    if (handle == NULL || domain_handle == NULL)
        return -FI_EINVAL;
    dom = calloc(1, sizeof(*dom));
    if (dom == NULL)
        return -FI_ENOMEM;
    dom->dev = handle;
    *domain_handle = dom;
    return 0;
}

int uet_domain_close(uet_domain_handle_t domain_handle)
{
    struct uet_ernic_dom *dom = domain_handle;

    if (dom == NULL)
        return -FI_EINVAL;
    if (dom->refs != 0)
        return -FI_EBUSY;
    free(dom);
    return 0;
}

int uet_mr_reg(uet_domain_handle_t domain_handle, const void *buf, size_t len,
               uint64_t access, uint64_t requested_key, uint64_t flags,
               void *context, uet_mr_handle_t *mr_handle)
{
    struct uet_ernic_dom *dom = domain_handle;
    struct uet_ernic_dev *d;
    struct uet_ernic_mr *mr;
    struct uet_ernic_mr_reg q;
    struct uet_ernic_reply r;
    uint32_t acc = 0;
    unsigned int ib_access = IBV_ACCESS_LOCAL_WRITE;
    int rc;

    (void)flags;
    (void)context;
    if (dom == NULL || buf == NULL || len == 0 || mr_handle == NULL)
        return -FI_EINVAL;
    d = dom->dev;

    if (access & FI_REMOTE_READ) {
        acc |= UET_ERNIC_ACC_REMOTE_READ;
        ib_access |= IBV_ACCESS_REMOTE_READ;
    }
    if (access & FI_REMOTE_WRITE) {
        acc |= UET_ERNIC_ACC_REMOTE_WRITE;
        ib_access |= IBV_ACCESS_REMOTE_WRITE;
    }
    if (requested_key & UET_MR_KEY_IDEMPOTENT_SAFE)
        acc |= UET_ERNIC_ACC_IDEMPOTENT_SAFE;

    mr = calloc(1, sizeof(*mr));
    if (mr == NULL)
        return -FI_ENOMEM;

    pthread_mutex_lock(&d->lock);
    /* The device learns the pages from the ionic registration; the engine
     * takes its own copy of them by lkey. */
    mr->ibmr = ibv_reg_mr(d->pd, (void *)(uintptr_t)buf, len, ib_access);
    if (mr->ibmr == NULL) {
        pthread_mutex_unlock(&d->lock);
        free(mr);
        return -FI_ENOMEM;
    }

    memset(&q, 0, sizeof(q));
    hdr_init(&q.hdr, UET_ERNIC_OP_MR_REG, 0);
    q.lkey = htole32(mr->ibmr->lkey);
    q.access = htole32(acc);
    rc = call(d, &q, sizeof(q), &r);
    if (rc != 0) {
        (void)ibv_dereg_mr(mr->ibmr);
        pthread_mutex_unlock(&d->lock);
        free(mr);
        return rc;
    }
    pthread_mutex_unlock(&d->lock);

    mr->dom = dom;
    mr->handle = le32toh(r.u.mr_reg.handle);
    mr->rkey = le64toh(r.u.mr_reg.rkey);
    mr->buf = buf;
    mr->len = len;
    dom->refs++;
    *mr_handle = mr;
    return 0;
}

uint64_t uet_mr_key(uet_mr_handle_t mr_handle)
{
    struct uet_ernic_mr *mr = mr_handle;

    return mr != NULL ? mr->rkey : FI_KEY_NOTAVAIL;
}

int uet_ep_bind_mr(uet_ep_handle_t ep_handle, uet_mr_handle_t mr_handle,
                   uint64_t flags)
{
    struct uet_ernic_ep *ep = ep_handle;
    struct uet_ernic_mr *mr = mr_handle;

    (void)flags;
    if (ep == NULL || mr == NULL || ep->dom->dev != mr->dom->dev)
        return -FI_EINVAL;
    if (mr->ep != NULL && mr->ep != ep)
        return -FI_EBUSY;
    mr->ep = ep;
    return 0;
}

int uet_mr_enable(uet_mr_handle_t mr_handle)
{
    struct uet_ernic_mr *mr = mr_handle;

    if (mr == NULL)
        return -FI_EINVAL;
    mr->enabled = true;
    return 0;
}

int uet_mr_disable(uet_mr_handle_t mr_handle)
{
    struct uet_ernic_mr *mr = mr_handle;

    if (mr == NULL || !mr->enabled)
        return -FI_EINVAL;
    /* Peers keep their access until uet_mr_close(): the engine would hand
     * out a new key on re-registration, and callers keep the old one. */
    mr->enabled = false;
    mr->ep = NULL;
    return 0;
}

int uet_mr_close(uet_mr_handle_t mr_handle)
{
    struct uet_ernic_mr *mr = mr_handle;
    struct uet_ernic_dev *d;
    struct uet_ernic_release q;
    struct uet_ernic_reply r;
    int rc;

    if (mr == NULL)
        return -FI_EINVAL;
    d = mr->dom->dev;

    pthread_mutex_lock(&d->lock);
    memset(&q, 0, sizeof(q));
    hdr_init(&q.hdr, UET_ERNIC_OP_MR_DEREG, 0);
    q.handle = htole32(mr->handle);
    rc = call(d, &q, sizeof(q), &r);
    /* Destroying the ionic region revokes the engine's copy as well, so
     * even a failed deregistration leaves nothing reachable. */
    (void)ibv_dereg_mr(mr->ibmr);
    pthread_mutex_unlock(&d->lock);

    mr->dom->refs--;
    free(mr);
    return rc == -FI_EBADF ? 0 : rc;
}

int uet_av_insert(uet_domain_handle_t domain_handle, struct uet_addr *uet_addr,
                  uet_addr_handle_t *addr_handle)
{
    struct uet_ernic_dom *dom = domain_handle;
    struct uet_ernic_av *av;
    struct uet_ernic_peer_add q;
    struct uet_ernic_reply r;
    int rc;

    if (dom == NULL || uet_addr == NULL || addr_handle == NULL)
        return -FI_EINVAL;
    if (uet_addr_is_ipv6(uet_addr))
        return -FI_EADDRNOTAVAIL;

    av = calloc(1, sizeof(*av));
    if (av == NULL)
        return -FI_ENOMEM;

    memset(&q, 0, sizeof(q));
    hdr_init(&q.hdr, UET_ERNIC_OP_PEER_ADD, 0);
    q.ipv4 = htole32(uet_addr->fa.v4);
    q.pid_on_fep = htole16(uet_addr->pid_on_fep);
    q.resource_index = htole16(uet_addr->start_index);

    pthread_mutex_lock(&dom->dev->lock);
    rc = call(dom->dev, &q, sizeof(q), &r);
    pthread_mutex_unlock(&dom->dev->lock);
    if (rc != 0) {
        free(av);
        return rc;
    }

    av->dom = dom;
    av->handle = le32toh(r.u.peer_add.handle);
    dom->refs++;
    *addr_handle = av;
    return 0;
}

int uet_av_remove(uet_addr_handle_t addr_handle)
{
    struct uet_ernic_av *av = addr_handle;
    struct uet_ernic_release q;
    struct uet_ernic_reply r;
    int rc;

    if (av == NULL)
        return -FI_EINVAL;

    memset(&q, 0, sizeof(q));
    hdr_init(&q.hdr, UET_ERNIC_OP_PEER_REMOVE, 0);
    q.handle = htole32(av->handle);
    pthread_mutex_lock(&av->dom->dev->lock);
    rc = call(av->dom->dev, &q, sizeof(q), &r);
    pthread_mutex_unlock(&av->dom->dev->lock);
    if (rc != 0 && rc != -FI_EBADF)
        return rc;

    av->dom->refs--;
    free(av);
    return 0;
}

/* ------------------------------------------------------------------ */
/* Endpoints and completion queues                                    */
/* ------------------------------------------------------------------ */

int uet_endpoint(uet_domain_handle_t domain_handle, struct fi_info *info,
                 struct fid_ep *ep_fid, void *context,
                 uet_ep_handle_t *ep_handle)
{
    struct uet_ernic_dom *dom = domain_handle;
    struct uet_ernic_ep *ep;

    (void)info;
    (void)ep_fid;
    (void)context;
    if (dom == NULL || ep_handle == NULL)
        return -FI_EINVAL;
    ep = calloc(1, sizeof(*ep));
    if (ep == NULL)
        return -FI_ENOMEM;
    ep->dom = dom;
    /* As in the reference library, the environment sets the default. */
    ep->rudi = getenv("UET_FORCE_RUDI") != NULL;
    dom->refs++;
    *ep_handle = ep;
    return 0;
}

int uet_getname(uet_ep_handle_t ep_handle, struct uet_addr *uet_addr)
{
    struct uet_ernic_ep *ep = ep_handle;
    struct uet_ernic_dev *d;

    if (ep == NULL || uet_addr == NULL)
        return -FI_EINVAL;
    d = ep->dom->dev;

    memset(uet_addr, 0, sizeof(*uet_addr));
    uet_addr->ver = UET_ADDR_VERSION;
    uet_addr->flags = UET_ADDR_FEP_CAP_V | UET_ADDR_FA_V |
                      UET_ADDR_PID_ON_FEP_V | UET_ADDR_INDEX_V |
                      UET_ADDR_INITIATOR_V | UET_ADDR_RELATIVE_MODE |
                      UET_ADDR_IPV4 | UET_ADDR_BIG_MSG_SIZE;
    uet_addr->fep_cap = UET_FEP_CAP_AI_FULL;
    if (d->caps & UET_ERNIC_CAP_RUDI)
        uet_addr->fep_cap |= UET_FEP_CAP_HPC;
    uet_addr->fa.v4 = d->ipv4;
    uet_addr->pid_on_fep = d->pid_on_fep;
    uet_addr->start_index = d->resource_index;
    uet_addr->num_indices = 1;
    uet_addr->initiator_id = d->initiator_id;
    return 0;
}

int uet_ep_bind_cq(uet_ep_handle_t ep_handle, struct fi_cq_attr *attr,
                   struct fid_cq *cq_fid, uint64_t flags, void *context,
                   uet_cq_handle_t *cq_handle)
{
    struct uet_ernic_ep *ep = ep_handle;
    struct uet_ernic_cq *cq;
    size_t size;

    (void)cq_fid;
    (void)context;
    if (ep == NULL || attr == NULL || cq_handle == NULL ||
        cq_entry_size(attr->format) == 0)
        return -FI_EINVAL;
    if ((flags & (FI_SEND | FI_RECV)) == 0 ||
        (flags & (FI_SEND | FI_RECV)) == (FI_SEND | FI_RECV))
        return -FI_EINVAL;
    if ((flags & FI_SEND) ? ep->tx_cq != NULL : ep->rx_cq != NULL)
        return -FI_EINVAL;

    /* Room for every operation that can be in flight. */
    size = attr->size > PENDING ? attr->size : PENDING;
    cq = calloc(1, sizeof(*cq));
    if (cq == NULL)
        return -FI_ENOMEM;
    cq->ep = ep;
    cq->format = attr->format;
    cq->entry_size = cq_entry_size(attr->format);
    cq->size = size;
    cq->ring = calloc(size, cq->entry_size);
    cq->err = calloc(size, sizeof(*cq->err));
    cq->is_err = calloc(size, sizeof(*cq->is_err));
    if (cq->ring == NULL || cq->err == NULL || cq->is_err == NULL) {
        free(cq->ring);
        free(cq->err);
        free(cq->is_err);
        free(cq);
        return -FI_ENOMEM;
    }

    if (flags & FI_SEND)
        ep->tx_cq = cq;
    else
        ep->rx_cq = cq; /* there are no target-side events to put in it */
    *cq_handle = cq;
    return 0;
}

int uet_ep_enable(uet_ep_handle_t ep_handle)
{
    struct uet_ernic_ep *ep = ep_handle;

    if (ep == NULL || ep->tx_cq == NULL)
        return -FI_ENOCQ;
    ep->enabled = true;
    return 0;
}

int uet_ep_setopt(uet_ep_handle_t ep_handle, int level, int optname,
                  const void *optval, size_t optlen)
{
    struct uet_ernic_ep *ep = ep_handle;

    if (ep == NULL || level != FI_OPT_ENDPOINT)
        return -FI_ENOSYS;
    if (optname != UET_OPT_FORCE_RUDI)
        return -FI_ENOSYS;
    if (optval == NULL || optlen != sizeof(bool))
        return -FI_EINVAL;
    ep->rudi = *(const bool *)optval;
    return 0;
}

static void cq_free(struct uet_ernic_cq *cq)
{
    if (cq == NULL)
        return;
    free(cq->ring);
    free(cq->err);
    free(cq->is_err);
    free(cq);
}

/*
 * The command channel has no way yet to take back a WRITE or READ the
 * device has accepted: one that waits in the device is posted when it can
 * be, and one in the engine runs to its end.  Say so, as the reference's
 * stop-and-go PDS does, so a caller waits for them instead.
 */
int uet_ep_abort(uet_ep_handle_t ep_handle)
{
    return ep_handle != NULL ? -FI_ENOSYS : -FI_EINVAL;
}

int uet_ep_close(uet_ep_handle_t ep_handle)
{
    struct uet_ernic_ep *ep = ep_handle;

    if (ep == NULL)
        return -FI_EINVAL;
    if (ep->in_flight != 0)
        return -FI_EBUSY;
    /* Completion queues are part of the endpoint, as in the reference. */
    cq_free(ep->tx_cq);
    cq_free(ep->rx_cq);
    ep->dom->refs--;
    free(ep);
    return 0;
}

int uet_ep_progress(uet_ep_handle_t ep_handle)
{
    struct uet_ernic_ep *ep = ep_handle;
    struct uet_ernic_dev *d;

    if (ep == NULL)
        return -FI_EINVAL;
    d = ep->dom->dev;
    pthread_mutex_lock(&d->lock);
    progress(d);
    pthread_mutex_unlock(&d->lock);
    return d->broken ? -FI_EIO : 0;
}

ssize_t uet_cq_read(uet_cq_handle_t cq_handle, void *buf, size_t count)
{
    struct uet_ernic_cq *cq = cq_handle;
    struct uet_ernic_dev *d;
    size_t n = 0;

    if (cq == NULL || buf == NULL)
        return -FI_EINVAL;
    d = cq->ep->dom->dev;

    pthread_mutex_lock(&d->lock);
    progress(d);
    while (n < count && cq->count > 0) {
        if (cq->is_err[cq->head]) {
            if (n == 0) {
                pthread_mutex_unlock(&d->lock);
                return -FI_EAVAIL;
            }
            break;
        }
        memcpy((uint8_t *)buf + n * cq->entry_size,
               cq->ring + cq->head * cq->entry_size, cq->entry_size);
        cq->head = (cq->head + 1) % cq->size;
        cq->count--;
        n++;
    }
    pthread_mutex_unlock(&d->lock);
    return (ssize_t)n;
}

ssize_t uet_cq_readerr(uet_cq_handle_t cq_handle, struct fi_cq_err_entry *buf)
{
    struct uet_ernic_cq *cq = cq_handle;
    struct uet_ernic_dev *d;

    if (cq == NULL || buf == NULL)
        return -FI_EINVAL;
    d = cq->ep->dom->dev;

    pthread_mutex_lock(&d->lock);
    if (cq->count == 0 || !cq->is_err[cq->head]) {
        pthread_mutex_unlock(&d->lock);
        return -FI_EAGAIN;
    }
    *buf = cq->err[cq->head];
    cq->is_err[cq->head] = false;
    cq->head = (cq->head + 1) % cq->size;
    cq->count--;
    pthread_mutex_unlock(&d->lock);
    return 1;
}

int uet_cq_close(uet_cq_handle_t cq_handle)
{
    /* Freed with the endpoint it is bound to, as in the reference. */
    return cq_handle != NULL ? 0 : -FI_EINVAL;
}

/* ------------------------------------------------------------------ */
/* RMA                                                                */
/* ------------------------------------------------------------------ */

static ssize_t post_rma(struct uet_ernic_ep *ep, uint8_t op, uint32_t job_id,
                        const void *buf, size_t len, struct uet_ernic_mr *mr,
                        struct uet_ernic_av *av, uint64_t remote_mem_addr,
                        uint64_t remote_key, void *context)
{
    struct uet_ernic_dev *d;
    struct uet_ernic_rma q;
    struct pending *p;
    uint64_t cookie;
    const uint8_t *b = buf;
    int rc;

    if (ep == NULL || av == NULL || buf == NULL || len == 0)
        return -FI_EINVAL;
    d = ep->dom->dev;
    if (!ep->enabled || ep->tx_cq == NULL)
        return -FI_EOPBADSTATE;
    /* The JobID is the device's, not the caller's to choose. */
    if (job_id != d->job_id && job_id != UET_JOB_ID_ANY)
        return -FI_EINVAL;
    /* The engine moves registered memory only, named within its region. */
    if (mr != NULL &&
        (b < mr->buf || len > mr->len || (size_t)(b - mr->buf) > mr->len - len))
        return -FI_EINVAL;

    memset(&q, 0, sizeof(q));
    q.peer = htole32(av->handle);
    q.length = htole64(len);
    q.remote_offset = htole64(remote_mem_addr);
    q.rkey = htole64(remote_key);
    q.flags = htole32(ep->rudi ? UET_ERNIC_RMA_RUDI : 0u);

    pthread_mutex_lock(&d->lock);
    auto_mr_release(d);

    struct auto_mr *am = NULL;
    if (mr != NULL) {
        q.mr = htole32(mr->handle);
        q.local_offset = htole64((uint64_t)(b - mr->buf));
    } else {
        rc = auto_mr_get(d, b, len, &am);
        if (rc != 0) {
            progress(d);
            pthread_mutex_unlock(&d->lock);
            return rc;
        }
        q.mr = htole32(am->handle);
        q.local_offset = htole64((uint64_t)((uintptr_t)b - am->start));
    }

    p = pend_alloc(d, &cookie);
    if (p == NULL) {
        progress(d);
        pthread_mutex_unlock(&d->lock);
        return -FI_EAGAIN;
    }
    hdr_init(&q.hdr, op, cookie);
    p->kind = PEND_RMA;
    p->ep = ep;
    p->context = context;
    p->len = len;
    p->flags = FI_RMA | (op == UET_ERNIC_OP_WRITE ? FI_WRITE : FI_READ);
    p->auto_mr = am;
    rc = send_capsule(d, &q, sizeof(q));
    if (rc != 0) {
        p->kind = PEND_FREE;
        p->auto_mr = NULL;
    } else {
        ep->in_flight++;
        if (am != NULL)
            am->refs++;
    }
    pthread_mutex_unlock(&d->lock);
    return rc;
}

ssize_t uet_write(uet_ep_handle_t ep_handle, uint32_t job_id, void *buf,
                  size_t len, uint64_t *data, uet_mr_handle_t mr_handle,
                  uet_addr_handle_t dst_addr_handle, uint64_t remote_mem_addr,
                  uint64_t remote_key, void *context)
{
    if (data != NULL)
        return -FI_ENOSYS; /* no immediate data on this path */
    return post_rma(ep_handle, UET_ERNIC_OP_WRITE, job_id, buf, len, mr_handle,
                    dst_addr_handle, remote_mem_addr, remote_key, context);
}

ssize_t uet_read(uet_ep_handle_t ep_handle, uint32_t job_id, void *buf,
                 size_t len, uet_mr_handle_t mr_handle,
                 uet_addr_handle_t uet_addr_handle, uint64_t remote_mem_addr,
                 uint64_t remote_key, void *context)
{
    return post_rma(ep_handle, UET_ERNIC_OP_READ, job_id, buf, len, mr_handle,
                    uet_addr_handle, remote_mem_addr, remote_key, context);
}
