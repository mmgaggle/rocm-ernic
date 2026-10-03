/*
 * test_libuet_ernic.c -- libuet_ernic between two fake guests
 *
 * Copyright (c) Advanced Micro Devices, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: MIT
 *
 * Two guests and their two devices, four processes. Each guest runs
 * libuet_ernic over the fake libibverbs in fake_ibverbs.c; each device is
 * tests/uet_fake_device.c, which runs the real UET command channel and
 * engine; the two engines exchange real UET frames over a socketpair. A
 * guest's memory is a memfd its device maps too, as a VM's is.
 *
 * The guests use the library the way the libfabric "uet" provider does:
 * initialize, domain, endpoint, completion queues, register, bind, enable,
 * getname, av_insert, then RMA, reaping completions with uet_cq_read().
 * The initiator WRITEs to the target's window over RUDI and RUD, READs
 * some of it back and checks the calls the library refuses. Then a
 * command whose reply comes after the caller gave up: the reply must not
 * be taken for a later command that reused the slot. Then
 * uet_ep_abort(): two endpoints each write while the wire loses every
 * frame, the first is aborted, and only the second's write may land. The
 * target compares its window byte for byte. Then it gives the window a new
 * key with uet_mr_rekey(): a write with the old key must fail and land
 * nothing, one with the new key must land. Then both tear everything
 * down, and each device must be left holding nothing.
 *
 * A second case runs the initiator on a device of ABI version 1, which
 * cannot take transfers back: UET_OPT_ABORT is false, writes still work,
 * and uet_ep_abort() with a write in flight returns -FI_ENOSYS and tears
 * the instance down, after which everything closes.
 *
 * Only libibverbs is faked. Nothing here runs on an ionic device or the
 * kernel driver; that needs a VM.
 *
 * Usage: test_libuet_ernic PATH_TO_uet_fake_device
 */

#include <errno.h>
#include <inttypes.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <rdma/fi_errno.h>

#include "fake_ibverbs.h"
#include "uet_ernic.h"
#include "uet_ernic_abi.h"

#define MEM_LEN (8u * 1024u * 1024u)
#define SYNC_MS "1000"      /* UET_ERNIC_SYNC_WAIT_MS for the guests */
#define IP_A    0xc0a8c865u /* 192.168.200.101 */
#define IP_B    0xc0a8c866u /* 192.168.200.102 */

#define HALF        (512u * 1024u)
#define SRC_LEN     (2u * HALF)
#define WIN_LEN     (2u * 1024u * 1024u)
#define RD_LEN      (32u * 1024u)
#define W1          (4096u + 5u)
#define W2          (W1 + HALF + 9u)
#define QTR         (128u * 1024u)
#define W3          (1280u * 1024u)      /* aborted: stays zero */
#define W4          (1536u * 1024u + 3u) /* the other endpoint's: lands */
#define W5          (1792u * 1024u)      /* after the re-key: the old key's */
#define RK_LEN      (32u * 1024u)        /* and then the new key's, after it */
#define REKEY_TIMED 1000u

struct report {
    int ok;
    char why[240];
    double write_ms;
    double rekey_us, rereg_us; /* the target's window, each on average */
    struct fake_ibv_stats fake;
};

struct guest {
    uint8_t *mem;
    int ctl;
    struct report *rep;
};

struct hello {
    struct uet_addr addr;
    uint64_t key;
};

/* the case being run: the initiator's device is an ABI version 1 one */
static bool g_v1;
#define V1_LEN (64u * 1024u)

static void fail(struct report *rep, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));

static void fail(struct report *rep, const char *fmt, ...)
{
    va_list ap;

    if (!rep->ok)
        return;
    rep->ok = 0;
    va_start(ap, fmt);
    vsnprintf(rep->why, sizeof(rep->why), fmt, ap);
    va_end(ap);
}

#define CHECK(g, cond)                                              \
    do {                                                            \
        if (!(cond)) {                                              \
            fail((g)->rep, "%s:%d: %s", __FILE__, __LINE__, #cond); \
            return;                                                 \
        }                                                           \
    } while (0)

static double now_ms(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1000.0 + (double)ts.tv_nsec / 1e6;
}

static uint8_t pattern(size_t off)
{
    uint64_t z = (uint64_t)(off / 8) + UINT64_C(0x9e3779b97f4a7c15);

    z = (z ^ (z >> 30)) * UINT64_C(0xbf58476d1ce4e5b9);
    z = (z ^ (z >> 27)) * UINT64_C(0x94d049bb133111eb);
    z ^= z >> 31;
    return (uint8_t)(z >> ((off % 8) * 8));
}

/* What a libfabric provider does to get one endpoint going. */
static bool open_ep(struct guest *g, uet_handle_t *h, uet_domain_handle_t *dom,
                    uet_ep_handle_t *ep, uet_cq_handle_t *txcq)
{
    struct fi_cq_attr attr = {.format = FI_CQ_FORMAT_DATA, .size = 64};
    uet_cq_handle_t rxcq;
    int rc;

    if ((rc = uet_initialize(h)) != 0 ||
        (rc = uet_domain(*h, NULL, NULL, NULL, NULL, NULL, NULL, dom)) != 0 ||
        (rc = uet_endpoint(*dom, NULL, NULL, NULL, ep)) != 0 ||
        (rc = uet_ep_bind_cq(*ep, &attr, NULL, FI_SEND, NULL, txcq)) != 0 ||
        (rc = uet_ep_bind_cq(*ep, &attr, NULL, FI_RECV, NULL, &rxcq)) != 0) {
        fail(g->rep, "opening the endpoint: %s", strerror(-rc));
        return false;
    }
    return true;
}

static bool reg(struct guest *g, uet_domain_handle_t dom, uet_ep_handle_t ep,
                void *buf, size_t len, uint64_t access, uint64_t key,
                uet_mr_handle_t *mr)
{
    int rc;

    if ((rc = uet_mr_reg(dom, buf, len, access, key, 0, NULL, mr)) != 0 ||
        (rc = uet_ep_bind_mr(ep, *mr, 0)) != 0 ||
        (rc = uet_mr_enable(*mr)) != 0) {
        fail(g->rep, "registering %zu bytes: %s", len, strerror(-rc));
        return false;
    }
    return true;
}

/* Wait for one completion: 0 with its entry, or the error's errno. */
static int reap(struct guest *g, uet_ep_handle_t ep, uet_cq_handle_t cq,
                struct fi_cq_data_entry *out)
{
    double end = now_ms() + 30000.0;

    for (;;) {
        ssize_t n = uet_cq_read(cq, out, 1);

        if (n == 1)
            return 0;
        if (n == -FI_EAVAIL) {
            struct fi_cq_err_entry e;

            memset(&e, 0, sizeof(e));
            if (uet_cq_readerr(cq, &e) != 1)
                return -1;
            memset(out, 0, sizeof(*out));
            out->op_context = e.op_context;
            return e.err != 0 ? e.err : -1;
        }
        if (n < 0 || now_ms() > end) {
            fail(g->rep, "no completion (%zd)", n);
            return -1;
        }
        (void)uet_ep_progress(ep);
    }
}

static ssize_t write_retry(uet_ep_handle_t ep, void *buf, size_t len,
                           uet_mr_handle_t mr, uet_addr_handle_t ah,
                           uint64_t remote, uint64_t key, void *ctx)
{
    ssize_t rc;

    while ((rc = uet_write(ep, UET_DEF_JOB_ID, buf, len, NULL, mr, ah, remote,
                           key, ctx)) == -FI_EAGAIN)
        (void)uet_ep_progress(ep);
    return rc;
}

static void close_all(struct guest *g, uet_handle_t h, uet_domain_handle_t dom,
                      uet_ep_handle_t ep, uet_mr_handle_t *mrs, unsigned nmrs)
{
    for (unsigned i = 0; i < nmrs; i++) {
        CHECK(g, uet_mr_disable(mrs[i]) == 0);
        CHECK(g, uet_mr_close(mrs[i]) == 0);
    }
    /* Nothing left to take back: the device answers at once. */
    CHECK(g, uet_ep_abort(ep) == 0);
    CHECK(g, uet_ep_close(ep) == 0);
    CHECK(g, uet_domain_close(dom) == 0);
    CHECK(g, uet_finalize(h) == 0);
}

static void run_target(struct guest *g)
{
    uet_handle_t h;
    uet_domain_handle_t dom;
    uet_ep_handle_t ep;
    uet_cq_handle_t txcq;
    uet_mr_handle_t mr;
    struct hello hi;
    uint8_t *win = g->mem + 1024u * 1024u;
    char done;

    if (!open_ep(g, &h, &dom, &ep, &txcq))
        return;
    memset(win, 0, WIN_LEN);
    if (!reg(g, dom, ep, win, WIN_LEN, FI_REMOTE_READ | FI_REMOTE_WRITE,
             UET_MR_KEY_IDEMPOTENT_SAFE, &mr))
        return;
    CHECK(g, uet_ep_enable(ep) == 0);

    memset(&hi, 0, sizeof(hi));
    CHECK(g, uet_getname(ep, &hi.addr) == 0);
    CHECK(g, hi.addr.fa.v4 == IP_B && hi.addr.start_index == 15 &&
                 (hi.addr.fep_cap & UET_FEP_CAP_HPC) != 0);
    hi.key = uet_mr_key(mr);
    CHECK(g, (hi.key & UET_MR_KEY_IDEMPOTENT_SAFE) != 0);
    CHECK(g, send(g->ctl, &hi, sizeof(hi), 0) == (ssize_t)sizeof(hi));

    /* Nothing to do while the peer writes: the engine is in the device. */
    CHECK(g, recv(g->ctl, &done, 1, 0) == 1);
    for (size_t off = 0; off < WIN_LEN; off++) {
        uint8_t want = 0;

        if (g_v1) {
            /* only the write before the teardown is sure to land */
            if (off >= W1 && off < W1 + V1_LEN)
                want = pattern(off - W1);
            else if (off >= W3)
                continue;
        } else if (off >= W1 && off < W1 + HALF)
            want = pattern(off - W1);
        else if (off >= W2 && off < W2 + HALF)
            want = pattern(HALF + (off - W2));
        else if (off >= W4 && off < W4 + QTR)
            want = pattern(QTR + (off - W4));
        if (win[off] != want) {
            fail(g->rep, "window byte %zu is wrong", off);
            break;
        }
    }
    done = g->rep->ok ? 'y' : 'n';
    CHECK(g, send(g->ctl, &done, 1, 0) == 1);

    if (!g_v1) {
        /* A new key: the initiator writes with the old one, which must
         * fail, and then with the new one. */
        uint64_t key = 0;

        CHECK(g, uet_mr_rekey(mr, &key) == 0);
        CHECK(g, key != hi.key && uet_mr_key(mr) == key &&
                     (key & UET_MR_KEY_IDEMPOTENT_SAFE) != 0);
        CHECK(g, send(g->ctl, &key, sizeof(key), 0) == (ssize_t)sizeof(key));
        CHECK(g, recv(g->ctl, &done, 1, 0) == 1);
        for (size_t off = 0; off < RK_LEN; off++) {
            if (win[W5 + off] != 0) {
                fail(g->rep, "a write with the old key landed at %zu", off);
                break;
            }
            if (win[W5 + RK_LEN + off] != pattern(off)) {
                fail(g->rep, "the write with the new key is wrong at %zu", off);
                break;
            }
        }
        done = g->rep->ok ? 'y' : 'n';
        CHECK(g, send(g->ctl, &done, 1, 0) == 1);

        /* what each costs the guest, through the channel */
        double t0 = now_ms();
        for (unsigned i = 0; i < REKEY_TIMED && g->rep->ok; i++)
            CHECK(g, uet_mr_rekey(mr, &key) == 0);
        g->rep->rekey_us = (now_ms() - t0) * 1000.0 / REKEY_TIMED;
        t0 = now_ms();
        for (unsigned i = 0; i < REKEY_TIMED && g->rep->ok; i++) {
            CHECK(g, uet_mr_disable(mr) == 0 && uet_mr_close(mr) == 0);
            if (!reg(g, dom, ep, win, WIN_LEN, FI_REMOTE_READ | FI_REMOTE_WRITE,
                     UET_MR_KEY_IDEMPOTENT_SAFE, &mr))
                return;
        }
        g->rep->rereg_us = (now_ms() - t0) * 1000.0 / REKEY_TIMED;
    }

    close_all(g, h, dom, ep, &mr, 1);
}

static void run_initiator(struct guest *g)
{
    uet_handle_t h;
    uet_domain_handle_t dom;
    uet_ep_handle_t ep;
    uet_cq_handle_t txcq;
    uet_mr_handle_t mrs[2];
    uet_addr_handle_t ah;
    struct uet_addr me;
    struct hello peer;
    struct fi_cq_data_entry c;
    uint8_t *src = g->mem + 1024u * 1024u;
    uint8_t *rd = g->mem + 3u * 1024u * 1024u;
    int ctx[5];
    uint64_t imm = 7;
    bool on;
    char done;

    if (!open_ep(g, &h, &dom, &ep, &txcq))
        return;
    for (size_t i = 0; i < SRC_LEN; i++)
        src[i] = pattern(i);
    memset(rd, 0, RD_LEN);
    if (!reg(g, dom, ep, src, SRC_LEN, 0, UET_MR_KEY_NONE, &mrs[0]) ||
        !reg(g, dom, ep, rd, RD_LEN, 0, UET_MR_KEY_NONE, &mrs[1]))
        return;
    CHECK(g, uet_ep_enable(ep) == 0);

    CHECK(g, uet_getname(ep, &me) == 0);
    CHECK(g, me.fa.v4 == IP_A && me.pid_on_fep == 0 && me.start_index == 15);

    CHECK(g, recv(g->ctl, &peer, sizeof(peer), 0) == (ssize_t)sizeof(peer));
    CHECK(g, uet_av_insert(dom, &peer.addr, &ah) == 0);

    /* RUDI for the first half, RUD for the second, both in flight. */
    double t0 = now_ms();
    on = true;
    CHECK(g, uet_ep_setopt(ep, FI_OPT_ENDPOINT, UET_OPT_FORCE_RUDI, &on,
                           sizeof(on)) == 0);
    CHECK(g,
          write_retry(ep, src, HALF, mrs[0], ah, W1, peer.key, &ctx[0]) == 0);
    on = false;
    CHECK(g, uet_ep_setopt(ep, FI_OPT_ENDPOINT, UET_OPT_FORCE_RUDI, &on,
                           sizeof(on)) == 0);
    CHECK(g, write_retry(ep, src + HALF, HALF, mrs[0], ah, W2, peer.key,
                         &ctx[1]) == 0);
    bool seen0 = false, seen1 = false;
    for (int i = 0; i < 2; i++) {
        CHECK(g, reap(g, ep, txcq, &c) == 0);
        CHECK(g, (c.flags & (FI_RMA | FI_WRITE)) == (FI_RMA | FI_WRITE) &&
                     c.len == HALF);
        seen0 = seen0 || c.op_context == &ctx[0];
        seen1 = seen1 || c.op_context == &ctx[1];
    }
    CHECK(g, seen0 && seen1);
    g->rep->write_ms = now_ms() - t0;

    /* No region, as the libfabric provider writes: the library registers
     * the buffer itself, once for both of these, and the bytes are the
     * ones already there. */
    struct fake_ibv_stats before, after;
    fake_ibv_get_stats(&before);
    for (int i = 0; i < 2; i++) {
        size_t off = (size_t)i * 128u * 1024u;
        ssize_t w;

        while ((w = uet_write(ep, UET_DEF_JOB_ID, src + off, 64u * 1024u, NULL,
                              NULL, ah, W1 + off, peer.key, &ctx[0])) ==
               -FI_EAGAIN)
            (void)uet_ep_progress(ep);
        CHECK(g, w == 0);
        CHECK(g, reap(g, ep, txcq, &c) == 0 && c.op_context == &ctx[0]);
    }
    fake_ibv_get_stats(&after);
    CHECK(g, after.mr_regs == before.mr_regs + 1);

    /* Read some of it back. */
    ssize_t rc;
    while ((rc = uet_read(ep, UET_DEF_JOB_ID, rd, RD_LEN, mrs[1], ah, W1,
                          peer.key, &ctx[2])) == -FI_EAGAIN)
        (void)uet_ep_progress(ep);
    CHECK(g, rc == 0);
    CHECK(g, reap(g, ep, txcq, &c) == 0 && c.op_context == &ctx[2] &&
                 (c.flags & FI_READ) != 0 && c.len == RD_LEN);
    for (size_t i = 0; i < RD_LEN; i++)
        CHECK(g, rd[i] == pattern(i));

    /* What the library refuses before anything reaches the device. */
    CHECK(g, uet_write(ep, UET_DEF_JOB_ID, src, 64, &imm, mrs[0], ah, W1,
                       peer.key, &ctx[3]) == -FI_ENOSYS);
    CHECK(g, uet_write(ep, UET_DEF_JOB_ID, src + SRC_LEN - 10, 20, NULL, mrs[0],
                       ah, W1, peer.key, &ctx[3]) == -FI_EINVAL);
    CHECK(g, uet_write(ep, 7, src, 64, NULL, mrs[0], ah, W1, peer.key,
                       &ctx[3]) == -FI_EINVAL);

    /* A key the target never handed out: an error completion. */
    CHECK(g, write_retry(ep, src, 4096, mrs[0], ah, W1, peer.key ^ 1u,
                         &ctx[4]) == 0);
    int err = reap(g, ep, txcq, &c);
    CHECK(g, err > 0 && c.op_context == &ctx[4]);

    /* A late reply.  The device keeps its answer to an MR_REG until the
     * 256th command after it, so the call gives up (SYNC_MS); then 256
     * writes, one at a time, the last to a key the target never handed
     * out.  With the slot freed on the time-out and an 8-bit generation,
     * that last write would have had the MR_REG's slot and generation,
     * and the late reply, sent just before it, would have completed it
     * as a success.  It must fail. */
    uet_mr_handle_t lost;
    fake_ibv_hold_reply(UET_ERNIC_OP_MR_REG, 256);
    CHECK(g, uet_mr_reg(dom, g->mem + 5u * 1024u * 1024u, 4096, 0,
                        UET_MR_KEY_NONE, 0, NULL, &lost) == -FI_ETIMEDOUT);
    for (int i = 0; i < 256; i++) {
        bool last = i == 255;

        CHECK(g, write_retry(ep, src, 4096, mrs[0], ah, W1,
                             last ? peer.key ^ 1u : peer.key, &ctx[3]) == 0);
        err = reap(g, ep, txcq, &c);
        CHECK(g, c.op_context == &ctx[3]);
        if (last)
            CHECK(g, err > 0);
        else
            CHECK(g, err == 0);
    }
    /* and nothing more completes */
    for (double end = now_ms() + 100.0; now_ms() < end;)
        CHECK(g, uet_cq_read(txcq, &c, 1) == 0);

    /* A late MR_DEREG: the close gives up and keeps the region, which a
     * second close, after the answer came, releases. */
    uet_mr_handle_t keep;
    CHECK(g, uet_mr_reg(dom, g->mem + 5u * 1024u * 1024u, 4096, 0,
                        UET_MR_KEY_NONE, 0, NULL, &keep) == 0);
    fake_ibv_hold_reply(UET_ERNIC_OP_MR_DEREG, 2);
    CHECK(g, uet_mr_close(keep) == -FI_ETIMEDOUT);
    for (int i = 0; i < 2; i++) {
        CHECK(g, write_retry(ep, src, 4096, mrs[0], ah, W1, peer.key,
                             &ctx[3]) == 0);
        CHECK(g, reap(g, ep, txcq, &c) == 0);
    }
    CHECK(g, uet_mr_close(keep) == 0);

    /* uet_ep_abort(): a second endpoint, then one write each while the
     * wire loses every frame. The first endpoint is aborted: its write
     * reports nothing and never lands, even once the wire is back; the
     * second endpoint's carries on. */
    uet_ep_handle_t ep2;
    uet_cq_handle_t txcq2, rxcq2;
    struct fi_cq_attr attr2 = {.format = FI_CQ_FORMAT_DATA, .size = 64};
    CHECK(g, uet_endpoint(dom, NULL, NULL, NULL, &ep2) == 0);
    CHECK(g, uet_ep_bind_cq(ep2, &attr2, NULL, FI_SEND, NULL, &txcq2) == 0);
    CHECK(g, uet_ep_bind_cq(ep2, &attr2, NULL, FI_RECV, NULL, &rxcq2) == 0);
    CHECK(g, uet_ep_enable(ep2) == 0);
    on = true;
    CHECK(g, uet_ep_setopt(ep, FI_OPT_ENDPOINT, UET_OPT_FORCE_RUDI, &on,
                           sizeof(on)) == 0);
    CHECK(g, uet_ep_setopt(ep2, FI_OPT_ENDPOINT, UET_OPT_FORCE_RUDI, &on,
                           sizeof(on)) == 0);
    fake_ibv_wire_down(1);
    CHECK(g, write_retry(ep, src, QTR, mrs[0], ah, W3, peer.key, &ctx[0]) == 0);
    /* No region: the library registers the buffer for this one. */
    CHECK(g, write_retry(ep2, src + QTR, QTR, NULL, ah, W4, peer.key,
                         &ctx[1]) == 0);
    /* Sent, lost and resent, within the device's retry budget. */
    for (double end = now_ms() + 60.0; now_ms() < end;)
        (void)uet_ep_progress(ep);
    CHECK(g, uet_ep_abort(ep) == 0);
    CHECK(g, uet_cq_read(txcq, &c, 1) == 0);
    fake_ibv_wire_down(0);
    CHECK(g, reap(g, ep2, txcq2, &c) == 0 && c.op_context == &ctx[1] &&
                 c.len == QTR);
    /* A retransmission of the aborted write would land now. */
    for (double end = now_ms() + 300.0; now_ms() < end;)
        (void)uet_ep_progress(ep2);
    CHECK(g, uet_cq_read(txcq, &c, 1) == 0);
    CHECK(g, uet_ep_abort(ep2) == 0);
    CHECK(g, uet_ep_close(ep2) == 0);

    done = 'd';
    CHECK(g, send(g->ctl, &done, 1, 0) == 1);
    CHECK(g, recv(g->ctl, &done, 1, 0) == 1);
    if (done != 'y')
        fail(g->rep, "the target's compare failed");

    /* The target re-keyed its window: the old key fails at once, the new
     * one works.  The first endpoint was aborted, so a third one. */
    uint64_t key = 0;
    uet_ep_handle_t ep3;
    uet_cq_handle_t txcq3, rxcq3;
    int stale;
    CHECK(g, recv(g->ctl, &key, sizeof(key), 0) == (ssize_t)sizeof(key));
    CHECK(g, key != peer.key);
    CHECK(g, uet_endpoint(dom, NULL, NULL, NULL, &ep3) == 0);
    CHECK(g, uet_ep_bind_cq(ep3, &attr2, NULL, FI_SEND, NULL, &txcq3) == 0);
    CHECK(g, uet_ep_bind_cq(ep3, &attr2, NULL, FI_RECV, NULL, &rxcq3) == 0);
    CHECK(g, uet_ep_enable(ep3) == 0);
    CHECK(g, uet_ep_setopt(ep3, FI_OPT_ENDPOINT, UET_OPT_FORCE_RUDI, &on,
                           sizeof(on)) == 0);
    CHECK(g, write_retry(ep3, src, RK_LEN, mrs[0], ah, W5, peer.key, &ctx[2]) ==
                 0);
    stale = reap(g, ep3, txcq3, &c);
    CHECK(g, stale > 0 && c.op_context == &ctx[2]);
    CHECK(g, write_retry(ep3, src, RK_LEN, mrs[0], ah, W5 + RK_LEN, key,
                         &ctx[3]) == 0);
    CHECK(g, reap(g, ep3, txcq3, &c) == 0 && c.op_context == &ctx[3]);
    done = 'r';
    CHECK(g, send(g->ctl, &done, 1, 0) == 1);
    CHECK(g, recv(g->ctl, &done, 1, 0) == 1);
    if (done != 'y')
        fail(g->rep, "the target's compare after the re-key failed");
    printf("rekey: a write with the old key failed with %s\n", strerror(stale));
    CHECK(g, uet_ep_abort(ep3) == 0);
    CHECK(g, uet_ep_close(ep3) == 0);

    CHECK(g, uet_av_remove(ah) == 0);
    close_all(g, h, dom, ep, mrs, 2);
}

/* On a device of ABI version 1: no ABORT, so a close tears down. */
static void run_initiator_v1(struct guest *g)
{
    uet_handle_t h;
    uet_domain_handle_t dom;
    uet_ep_handle_t ep;
    uet_cq_handle_t txcq;
    uet_mr_handle_t mr;
    uet_addr_handle_t ah;
    struct hello peer;
    struct fi_cq_data_entry c;
    uint8_t *src = g->mem + 1024u * 1024u;
    int ctx[2];
    bool can = true, on = true;
    size_t len = sizeof(can);
    char done;

    if (!open_ep(g, &h, &dom, &ep, &txcq))
        return;
    for (size_t i = 0; i < SRC_LEN; i++)
        src[i] = pattern(i);
    if (!reg(g, dom, ep, src, SRC_LEN, 0, UET_MR_KEY_NONE, &mr))
        return;
    CHECK(g, uet_ep_enable(ep) == 0);
    CHECK(g,
          uet_ep_getopt(ep, FI_OPT_ENDPOINT, UET_OPT_ABORT, &can, &len) == 0 &&
              !can);
    CHECK(g, recv(g->ctl, &peer, sizeof(peer), 0) == (ssize_t)sizeof(peer));
    CHECK(g, uet_av_insert(dom, &peer.addr, &ah) == 0);
    CHECK(g, uet_ep_setopt(ep, FI_OPT_ENDPOINT, UET_OPT_FORCE_RUDI, &on,
                           sizeof(on)) == 0);

    /* version 1 capsules, without a group, work as before */
    CHECK(g, write_retry(ep, src, V1_LEN, mr, ah, W1, peer.key, &ctx[0]) == 0);
    CHECK(g, reap(g, ep, txcq, &c) == 0 && c.op_context == &ctx[0]);

    /* a write the device cannot take back: the instance goes */
    fake_ibv_wire_down(1);
    CHECK(g, write_retry(ep, src, QTR, mr, ah, W3, peer.key, &ctx[1]) == 0);
    for (double end = now_ms() + 60.0; now_ms() < end;)
        (void)uet_ep_progress(ep);
    CHECK(g, uet_ep_abort(ep) == -FI_ENOSYS);
    CHECK(g, uet_cq_read(txcq, &c, 1) == 0);
    CHECK(g, uet_write(ep, UET_DEF_JOB_ID, src, 4096, NULL, mr, ah, W1,
                       peer.key, &ctx[0]) == -FI_EIO);
    fake_ibv_wire_down(0);

    done = 'd';
    CHECK(g, send(g->ctl, &done, 1, 0) == 1);
    CHECK(g, recv(g->ctl, &done, 1, 0) == 1);
    if (done != 'y')
        fail(g->rep, "the target's compare failed");

    /* and everything closes: the device's handles went with its QP */
    CHECK(g, uet_av_remove(ah) == 0);
    close_all(g, h, dom, ep, &mr, 1);
}

/* ---- Driver ------------------------------------------------------------- */

static pid_t start_device(const char *path, uint32_t ip, int mem_fd, int chan,
                          int wire, const char *log, bool v1)
{
    char a_ip[16], a_mem[16], a_len[16], a_chan[16], a_wire[16];

    fflush(NULL);
    pid_t pid = fork();
    if (pid != 0)
        return pid;

    FILE *f = freopen(log, "w", stdout);
    if (f != NULL)
        (void)dup2(fileno(stdout), STDERR_FILENO);
    snprintf(a_ip, sizeof(a_ip), "%u", ip);
    snprintf(a_mem, sizeof(a_mem), "%d", mem_fd);
    snprintf(a_len, sizeof(a_len), "%u", MEM_LEN);
    snprintf(a_chan, sizeof(a_chan), "%d", chan);
    snprintf(a_wire, sizeof(a_wire), "%d", wire);
    execl(path, path, a_ip, a_mem, a_len, a_chan, a_wire,
          v1 ? "v1" : (char *)NULL, (char *)NULL);
    perror(path);
    _exit(2);
}

static pid_t start_guest(bool target, int mem_fd, int chan, int ctl, int rep_fd,
                         const char *log)
{
    fflush(NULL);
    pid_t pid = fork();
    if (pid != 0)
        return pid;

    struct report rep;
    struct guest g;

    alarm(90);
    FILE *f = freopen(log, "w", stdout);
    if (f != NULL)
        (void)dup2(fileno(stdout), STDERR_FILENO);
    memset(&rep, 0, sizeof(rep));
    rep.ok = 1;
    g.rep = &rep;
    g.ctl = ctl;
    g.mem = mmap(NULL, MEM_LEN, PROT_READ | PROT_WRITE, MAP_SHARED, mem_fd, 0);
    if (g.mem == MAP_FAILED) {
        fail(&rep, "mmap: %s", strerror(errno));
    } else {
        fake_ibv_attach(chan, g.mem, MEM_LEN);
        if (target)
            run_target(&g);
        else if (g_v1)
            run_initiator_v1(&g);
        else
            run_initiator(&g);
        fake_ibv_get_stats(&rep.fake);
        if (rep.fake.bad_sends != 0 || rep.fake.qp_destroys != 1 ||
            rep.fake.mr_regs != rep.fake.mr_deregs)
            fail(&rep,
                 "verbs left behind: %" PRIu64 " regs, %" PRIu64
                 " deregs, %" PRIu64 " QPs destroyed, %" PRIu64 " bad sends",
                 rep.fake.mr_regs, rep.fake.mr_deregs, rep.fake.qp_destroys,
                 rep.fake.bad_sends);
    }
    if (write(rep_fd, &rep, sizeof(rep)) != (ssize_t)sizeof(rep))
        rep.ok = 0;
    fflush(NULL);
    _exit(rep.ok ? 0 : 1);
}

/* A log, or only its lines that start with @only. */
static void show(const char *log, const char *prefix, const char *only)
{
    char line[512];
    FILE *f = fopen(log, "r");

    if (f == NULL)
        return;
    while (fgets(line, sizeof(line), f) != NULL) {
        if (only == NULL || strncmp(line, only, strlen(only)) == 0)
            printf("%s%s", prefix, line);
    }
    fclose(f);
}

static bool run_case(const char *device, bool v1)
{
    int wire[2], chan_a[2], chan_b[2], ctl[2], rep_a[2], rep_b[2];
    int mem_a, mem_b;
    char logs[4][256];
    const char *tmp = getenv("TMPDIR");
    struct report ra, rb;
    int st[4];

    g_v1 = v1;
    for (int i = 0; i < 4; i++)
        snprintf(logs[i], sizeof(logs[i]), "%s/uet-guestlib-%d-%d.log",
                 tmp != NULL ? tmp : "/tmp", i, (int)getpid());

    mem_a = memfd_create("guest-a", 0);
    mem_b = memfd_create("guest-b", 0);
    if (mem_a < 0 || mem_b < 0 || ftruncate(mem_a, MEM_LEN) != 0 ||
        ftruncate(mem_b, MEM_LEN) != 0 ||
        socketpair(AF_UNIX, SOCK_SEQPACKET, 0, wire) != 0 ||
        socketpair(AF_UNIX, SOCK_SEQPACKET, 0, chan_a) != 0 ||
        socketpair(AF_UNIX, SOCK_SEQPACKET, 0, chan_b) != 0 ||
        socketpair(AF_UNIX, SOCK_SEQPACKET, 0, ctl) != 0 || pipe(rep_a) != 0 ||
        pipe(rep_b) != 0) {
        perror("setup");
        return false;
    }
    for (int i = 0; i < 2; i++) {
        int sz = 4 * 1024 * 1024;
        (void)setsockopt(wire[i], SOL_SOCKET, SO_SNDBUF, &sz, sizeof(sz));
        (void)setsockopt(wire[i], SOL_SOCKET, SO_RCVBUF, &sz, sizeof(sz));
    }

    if (v1)
        printf("case guest-lib-v1: the initiator's device speaks ABI "
               "version 1 and cannot take transfers back\n");
    else
        printf("case guest-lib: libuet_ernic over fake verbs, real channel "
               "and engines\n");
    fflush(stdout);

    pid_t pids[4];
    pids[0] =
        start_device(device, IP_A, mem_a, chan_a[1], wire[0], logs[0], v1);
    pids[1] =
        start_device(device, IP_B, mem_b, chan_b[1], wire[1], logs[1], false);
    pids[2] = start_guest(false, mem_a, chan_a[0], ctl[0], rep_a[1], logs[2]);
    pids[3] = start_guest(true, mem_b, chan_b[0], ctl[1], rep_b[1], logs[3]);
    close(rep_a[1]);
    close(rep_b[1]);
    close(wire[0]);
    close(wire[1]);
    close(chan_a[0]);
    close(chan_a[1]);
    close(chan_b[0]);
    close(chan_b[1]);
    close(ctl[0]);
    close(ctl[1]);
    close(mem_a);
    close(mem_b);

    memset(&ra, 0, sizeof(ra));
    memset(&rb, 0, sizeof(rb));
    bool have_a = read(rep_a[0], &ra, sizeof(ra)) == (ssize_t)sizeof(ra);
    bool have_b = read(rep_b[0], &rb, sizeof(rb)) == (ssize_t)sizeof(rb);
    close(rep_a[0]);
    close(rep_b[0]);
    for (int i = 0; i < 4; i++)
        (void)waitpid(pids[i], &st[i], 0);

    bool ok = have_a && have_b && ra.ok && rb.ok;
    for (int i = 0; i < 4; i++)
        ok = ok && WIFEXITED(st[i]) && WEXITSTATUS(st[i]) == 0;

    if (have_a && have_b && v1)
        printf("  a write on version 1 capsules, then uet_ep_abort() with "
               "one in flight: -FI_ENOSYS, torn down; guest A sent %" PRIu64
               " capsules, got %" PRIu64 " replies\n",
               ra.fake.sends, ra.fake.replies);
    else if (have_a && have_b)
        printf("  2 x 512 KiB uet_write (RUDI + RUD) in %.1f ms, 32 KiB "
               "uet_read back, 1 error completion; guest A sent %" PRIu64
               " capsules, got %" PRIu64 " replies\n",
               ra.write_ms, ra.fake.sends, ra.fake.replies);
    if (have_a && have_b && !v1)
        printf("  uet_mr_rekey() of the 2 MiB window: %.1f us; "
               "uet_mr_close() and uet_mr_reg() again: %.1f us (fake "
               "verbs, so without pinning)\n",
               rb.rekey_us, rb.rereg_us);
    show(logs[0], "  device A: ", ok ? "fake-device:" : NULL);
    show(logs[1], "  device B: ", ok ? "fake-device:" : NULL);

    if (ok) {
        printf("  PASS\n\n");
        for (int i = 0; i < 4; i++)
            unlink(logs[i]);
        return true;
    }
    if (have_a && !ra.ok)
        printf("  FAIL: initiator: %s\n", ra.why);
    if (have_b && !rb.ok)
        printf("  FAIL: target: %s\n", rb.why);
    for (int i = 0; i < 4; i++)
        printf("  process %d exit status %#x\n", i, (unsigned)st[i]);
    show(logs[2], "  guest A: ", NULL);
    show(logs[3], "  guest B: ", NULL);
    printf("\n");
    return false;
}

int main(int argc, char **argv)
{
    unsigned passed = 0;

    if (argc != 2) {
        fprintf(stderr, "usage: %s PATH_TO_uet_fake_device\n", argv[0]);
        return 2;
    }
    signal(SIGPIPE, SIG_IGN);
    setenv("UET_ERNIC_SYNC_WAIT_MS", SYNC_MS, 1);
    passed += run_case(argv[1], false) ? 1u : 0u;
    passed += run_case(argv[1], true) ? 1u : 0u;
    printf("%u/2 cases passed\n", passed);
    return passed == 2 ? 0 : 1;
}
