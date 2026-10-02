/*
 * test_uet_dpdk.c -- two UET engines on DPDK ports joined by net_memif
 *
 * The engine's DPDK wire (src/uet_wire_dpdk.c) end to end, without a VM
 * and without privileges: two processes, each with its own EAL, engine and
 * net_memif port, one the memif server and one the client, sharing memory
 * through a unix socket.  As in test_uet_engine, it has to be two
 * processes because the reference provider keeps its state in globals;
 * the EAL is once per process too.
 *
 * In each case the initiator writes UET_DPDK_TEST_LEN bytes (default
 * 4 MiB) from a region into the target's, and the target compares every
 * byte.  The regions are plain process memory, registered as contiguous
 * page lists, so the engine reaches them without a translator.  Each case
 * checks, besides the data, that the frames took the paths the backend
 * claims: RUDI payloads attached to mbufs as external buffers (memif takes
 * multi-segment frames), received frames kept in their mbufs until the
 * provider read them, and with "dma" the payload placed by the skeleton
 * dmadev.
 *
 * Copyright (C) Advanced Micro Devices, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
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
#include <sys/socket.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "uet_engine.h"
#include "uet_wire_dpdk.h"

#define PAGE           4096u
#define LEN_DEFAULT    (4u * 1024u * 1024u)
#define LEN_MAX        (64u * 1024u * 1024u)
#define IP_INITIATOR   0xc0a8c865u /* 192.168.200.101 */
#define IP_TARGET      0xc0a8c866u /* 192.168.200.102 */
#define PEER_PID       0u
#define PEER_INDEX     15u
#define CASE_TIMEOUT_S 120

struct test_case {
    const char *name;
    const char *what;
    bool rudi;
    uint16_t mtu;
    enum uet_engine_encap encap;
    bool dma;    /* the target places payload with dma_skeleton */
    uint16_t nq; /* queue pairs (memif has no RSS: always 1 in effect) */
    /* Retransmit timeout.  The skeleton dmadev copies on a thread of its
     * own and the target waits for every copy, so on a busy host a whole
     * RUDI message (512 packets, no window) takes longer than 50 ms. */
    uint32_t rto_ms;
};

static const struct test_case cases[] = {
    {"rudi-jumbo", "RUDI at mtu 9000 over UDP", true, 9000,
     UET_ENGINE_ENCAP_UDP, false, 1, 50},
    {"rud-jumbo", "RUD at mtu 9000 over UDP", false, 9000, UET_ENGINE_ENCAP_UDP,
     false, 1, 50},
    {"rudi-jumbo-dma", "RUDI at mtu 9000, placed by dma_skeleton", true, 9000,
     UET_ENGINE_ENCAP_UDP, true, 1, 2000},
    {"rudi-1500-ip", "RUDI at mtu 1500 over IP protocol 253", true, 1500,
     UET_ENGINE_ENCAP_IP, false, 1, 50},
    {"rud-1500", "RUD at mtu 1500 over UDP", false, 1500, UET_ENGINE_ENCAP_UDP,
     false, 1, 50},
};

static size_t xfer_len = LEN_DEFAULT;

struct report {
    int ok;
    char why[256];
    double xfer_ms;
    uint64_t wrong;
    struct uet_engine_stats st;
    struct uet_wire_dpdk_stats ws;
    char wire[512];
};

struct ctl {
    uint32_t type;
    uint64_t rkey;
};

enum { CTL_READY = 1, CTL_KEY, CTL_DONE, CTL_VERIFIED, CTL_BYE };

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

/* ------------------------------------------------------------------ */
/* One side                                                           */
/* ------------------------------------------------------------------ */

struct node {
    const struct test_case *tc;
    struct uet_engine *e;
    struct uet_wire_dpdk *w;
    int ctl;
    uint8_t *mem;
};

static int w_tx(void *ctx, const void *frame, size_t len)
{
    return uet_wire_dpdk_tx(ctx, frame, len);
}

static int w_tx_iov(void *ctx, const struct iovec *iov, unsigned n, size_t len)
{
    return uet_wire_dpdk_tx_iov(ctx, iov, n, len);
}

static void w_flush(void *ctx)
{
    uet_wire_dpdk_flush(ctx);
}

static struct uet_wire_dpdk *g_w;

static int w_copy(void *ctx, void *dst, const void *src, size_t len)
{
    (void)ctx;
    return uet_wire_dpdk_dma_copy(g_w, dst, src, len);
}

static bool w_rx(void *ctx, const struct uet_wire_dpdk_frame *f)
{
    struct node *n = ctx;

    return uet_engine_rx_frame_ext(n->e, f->data, f->len, f->csum_ok,
                                   uet_wire_dpdk_release, f->cookie);
}

static void pump(struct node *n)
{
    (void)uet_wire_dpdk_poll(n->w, w_rx, n, 64);
    uet_engine_poll(n->e);
}

static bool node_start(struct node *n, uint32_t ip, const char *sock,
                       bool server, struct report *rep)
{
    struct uet_engine_cfg cfg;
    struct uet_wire_dpdk_cfg dc;
    char dev[256];
    char err[256] = "";

    n->mem = aligned_alloc(PAGE, xfer_len);
    if (n->mem == NULL) {
        fail(rep, "out of memory");
        return false;
    }
    memset(n->mem, 0, xfer_len);

    uet_engine_cfg_defaults(&cfg);
    cfg.ip = ip;
    cfg.mtu = n->tc->mtu;
    cfg.encap = n->tc->encap;
    cfg.rto_ms = n->tc->rto_ms;
    cfg.max_retries = 20;

    /* Jumbo frames take two memif buffers (a memif buffer larger than
     * an mbuf crashes its receive path in DPDK 24.11), and the ring holds
     * a whole 4 MiB message of 1 KiB packets. */
    snprintf(
        dev, sizeof(dev),
        "net_memif0,role=%s,socket=%s,socket-abstract=no,bsize=8192,rsize=12",
        server ? "server" : "client", sock);
    memset(&dc, 0, sizeof(dc));
    dc.dev = dev;
    dc.dma = (n->tc->dma && ip == IP_TARGET) ? "dma_skeleton" : NULL;
    dc.queues = n->tc->nq;
    dc.mtu = cfg.mtu;
    dc.ip = ip;
    dc.udp_port = cfg.udp_port;
    dc.ipproto = cfg.ipproto;
    uet_engine_cfg_mac(&cfg, dc.mac);
    n->w = uet_wire_dpdk_open(&dc, err, sizeof(err));
    if (n->w == NULL) {
        fail(rep, "uet_wire_dpdk_open: %s", err);
        return false;
    }
    g_w = n->w;
    uet_wire_dpdk_describe(n->w, rep->wire, sizeof(rep->wire));

    /* The memif server's socket exists now: let the client connect. */
    if (server) {
        struct ctl m;

        memset(&m, 0, sizeof(m));
        m.type = CTL_READY;
        if (send(n->ctl, &m, sizeof(m), 0) != (ssize_t)sizeof(m)) {
            fail(rep, "cannot say ready");
            return false;
        }
    }

    struct uet_engine_wire wire = {.tx = w_tx,
                                   .tx_iov = w_tx_iov,
                                   .flush = w_flush,
                                   .ctx = n->w,
                                   .tx_ipv4_csum = true};
    struct uet_engine_dma dma = {
        .map = NULL, .copy = uet_wire_dpdk_has_dma(n->w) ? w_copy : NULL};

    n->e = uet_engine_create(&cfg, &wire, &dma, err, sizeof(err));
    if (n->e == NULL) {
        fail(rep, "uet_engine_create: %s", err);
        return false;
    }

    /* memif's link comes up once the client has connected. */
    double deadline = now_ms() + 10000.0;
    while (!uet_wire_dpdk_link_up(n->w)) {
        if (now_ms() > deadline) {
            fail(rep, "the memif link never came up");
            return false;
        }
        pump(n);
        usleep(1000);
    }
    return true;
}

static void node_finish(struct node *n, struct report *rep)
{
    if (n->e != NULL) {
        uet_engine_get_stats(n->e, &rep->st);
        uet_engine_destroy(n->e);
        n->e = NULL;
    }
    if (n->w != NULL) {
        uet_wire_dpdk_get_stats(n->w, &rep->ws);
        uet_wire_dpdk_close(n->w);
        n->w = NULL;
    }
    free(n->mem);
    n->mem = NULL;
}

static bool region(struct node *n, bool remote_write, uint32_t *mr,
                   uint64_t *key, struct report *rep)
{
    struct uet_engine_mr_desc d;

    memset(&d, 0, sizeof(d));
    d.root = (uint64_t)(uintptr_t)n->mem;
    d.page_size = PAGE;
    d.level = 0;
    d.len = xfer_len;
    d.remote_write = remote_write;
    d.idempotent_safe = remote_write;
    int rc = uet_engine_mr_reg(n->e, &d, mr, key);
    if (rc != 0) {
        fail(rep, "mr_reg: %s", strerror(-rc));
        return false;
    }
    return true;
}

static void run_target(struct node *n, const char *sock, struct report *rep)
{
    struct ctl m;
    uint32_t mr;
    uint64_t rkey;

    if (!node_start(n, IP_TARGET, sock, true, rep) ||
        !region(n, true, &mr, &rkey, rep))
        return;
    memset(&m, 0, sizeof(m));
    m.type = CTL_KEY;
    m.rkey = rkey;
    if (send(n->ctl, &m, sizeof(m), 0) != (ssize_t)sizeof(m)) {
        fail(rep, "cannot send the key");
        return;
    }

    double deadline = now_ms() + (CASE_TIMEOUT_S - 20) * 1000.0;
    for (;;) {
        pump(n);
        if (recv(n->ctl, &m, sizeof(m), MSG_DONTWAIT) == (ssize_t)sizeof(m) &&
            m.type == CTL_DONE)
            break;
        if (now_ms() > deadline) {
            fail(rep, "no word from the initiator");
            return;
        }
    }

    for (size_t off = 0; off < xfer_len; off++)
        rep->wrong += n->mem[off] != pattern(off) ? 1u : 0u;
    if (rep->wrong != 0)
        fail(rep, "%" PRIu64 " bytes wrong", rep->wrong);

    memset(&m, 0, sizeof(m));
    m.type = CTL_VERIFIED;
    (void)send(n->ctl, &m, sizeof(m), 0);

    /* Keep answering until the initiator is done.  Then this side, the
     * memif server, closes first: a memif peer that disconnects while the
     * other side polls its rings can pull the shared memory away under
     * it (the disconnect is handled on the EAL's interrupt thread). */
    deadline = now_ms() + 10000.0;
    while (now_ms() < deadline) {
        pump(n);
        if (recv(n->ctl, &m, sizeof(m), MSG_DONTWAIT) == (ssize_t)sizeof(m) &&
            m.type == CTL_BYE)
            break;
    }
    (void)uet_engine_mr_dereg(n->e, mr);
    node_finish(n, rep);
    memset(&m, 0, sizeof(m));
    m.type = CTL_BYE;
    (void)send(n->ctl, &m, sizeof(m), 0);
}

static void run_initiator(struct node *n, const char *sock, struct report *rep)
{
    struct uet_engine_rma w;
    struct uet_engine_comp c;
    struct ctl m;
    uint32_t mr, peer;
    uint64_t lkey;
    double t0, deadline;
    int rc;

    /* The client connects once the server's socket is there. */
    deadline = now_ms() + 60000.0;
    while (recv(n->ctl, &m, sizeof(m), 0) != (ssize_t)sizeof(m) ||
           m.type != CTL_READY) {
        if (now_ms() > deadline) {
            fail(rep, "the target never got ready");
            return;
        }
    }
    if (!node_start(n, IP_INITIATOR, sock, false, rep) ||
        !region(n, false, &mr, &lkey, rep))
        return;
    for (size_t off = 0; off < xfer_len; off++)
        n->mem[off] = pattern(off);

    deadline = now_ms() + 10000.0;
    while (recv(n->ctl, &m, sizeof(m), MSG_DONTWAIT) != (ssize_t)sizeof(m) ||
           m.type != CTL_KEY) {
        if (now_ms() > deadline) {
            fail(rep, "no key from the target");
            return;
        }
        pump(n);
    }

    rc = uet_engine_peer_add(n->e, IP_TARGET, PEER_PID, PEER_INDEX, &peer);
    if (rc != 0) {
        fail(rep, "peer_add: %s", strerror(-rc));
        return;
    }
    memset(&w, 0, sizeof(w));
    w.peer = peer;
    w.mr = mr;
    w.len = xfer_len;
    w.rkey = m.rkey;
    w.rudi = n->tc->rudi;
    w.cookie = 0x5eed;

    deadline = now_ms() + 10000.0;
    for (;;) {
        t0 = now_ms();
        rc = uet_engine_post_write(n->e, &w);
        if (rc != -EAGAIN || t0 > deadline)
            break;
        pump(n);
    }
    if (rc != 0) {
        fail(rep, "post_write: %s", strerror(-rc));
        return;
    }
    deadline = t0 + (CASE_TIMEOUT_S - 30) * 1000.0;
    for (;;) {
        pump(n);
        if (uet_engine_poll_comp(n->e, &c, 1) == 1)
            break;
        if (now_ms() > deadline) {
            fail(rep, "the write never completed");
            return;
        }
    }
    rep->xfer_ms = now_ms() - t0;
    if (c.status != 0)
        fail(rep, "the write failed: %s", strerror(-c.status));

    memset(&m, 0, sizeof(m));
    m.type = CTL_DONE;
    (void)send(n->ctl, &m, sizeof(m), 0);
    deadline = now_ms() + 30000.0;
    for (;;) {
        pump(n);
        if (recv(n->ctl, &m, sizeof(m), MSG_DONTWAIT) == (ssize_t)sizeof(m) &&
            m.type == CTL_VERIFIED)
            break;
        if (now_ms() > deadline) {
            fail(rep, "the target never reported its compare");
            return;
        }
    }
    deadline = now_ms() + 200.0;
    while (now_ms() < deadline)
        pump(n);
    (void)uet_engine_peer_remove(n->e, peer);
    (void)uet_engine_mr_dereg(n->e, mr);

    /* The target closes its port first, and says so; this side stops
     * polling meanwhile. */
    memset(&m, 0, sizeof(m));
    m.type = CTL_BYE;
    (void)send(n->ctl, &m, sizeof(m), 0);
    deadline = now_ms() + 10000.0;
    while (now_ms() < deadline) {
        if (recv(n->ctl, &m, sizeof(m), MSG_DONTWAIT) == (ssize_t)sizeof(m) &&
            m.type == CTL_BYE)
            break;
        usleep(1000);
    }
}

/* ------------------------------------------------------------------ */
/* Driver                                                             */
/* ------------------------------------------------------------------ */

static pid_t spawn(const struct test_case *tc, bool target, int ctl, int out,
                   const char *sock, const int *others, size_t nothers)
{
    fflush(NULL);
    pid_t pid = fork();
    if (pid != 0)
        return pid;

    struct node n;
    struct report rep;

    for (size_t i = 0; i < nothers; i++)
        close(others[i]);
    alarm(CASE_TIMEOUT_S);
    memset(&n, 0, sizeof(n));
    memset(&rep, 0, sizeof(rep));
    rep.ok = 1;
    n.tc = tc;
    n.ctl = ctl;
    if (target)
        run_target(&n, sock, &rep);
    else
        run_initiator(&n, sock, &rep);
    node_finish(&n, &rep);
    if (write(out, &rep, sizeof(rep)) != (ssize_t)sizeof(rep))
        rep.ok = 0;
    _exit(rep.ok ? 0 : 1);
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

static bool run_case(const struct test_case *tc)
{
    int ctl[2], pt[2], pi[2];
    char sock[108];
    struct report ini, tgt;
    int st_i = 0, st_t = 0;
    bool ok = true;

    printf("case %s: %s, %zu bytes\n", tc->name, tc->what, xfer_len);
    fflush(stdout);
    snprintf(sock, sizeof(sock), "%s/uet-memif-%d-%s.sock",
             getenv("TMPDIR") != NULL ? getenv("TMPDIR") : "/tmp",
             (int)getpid(), tc->name);
    unlink(sock);

    if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, ctl) != 0 || pipe(pt) != 0 ||
        pipe(pi) != 0) {
        printf("  FAIL: %s\n", strerror(errno));
        return false;
    }
    const int not_t[] = {ctl[0], pi[0], pi[1], pt[0]};
    const int not_i[] = {ctl[1], pt[0], pt[1], pi[0]};
    pid_t tp = spawn(tc, true, ctl[1], pt[1], sock, not_t, 4);
    pid_t ip = spawn(tc, false, ctl[0], pi[1], sock, not_i, 4);
    close(ctl[0]);
    close(ctl[1]);
    close(pt[1]);
    close(pi[1]);

    memset(&ini, 0, sizeof(ini));
    memset(&tgt, 0, sizeof(tgt));
    bool have_i = read_report(pi[0], &ini);
    bool have_t = read_report(pt[0], &tgt);
    close(pi[0]);
    close(pt[0]);
    (void)waitpid(ip, &st_i, 0);
    (void)waitpid(tp, &st_t, 0);
    unlink(sock);

    if (!have_i || !have_t) {
        printf("  FAIL: a process died (initiator %#x, target %#x)\n",
               (unsigned)st_i, (unsigned)st_t);
        return false;
    }
    printf("  initiator wire: %s\n", ini.wire);
    printf("  target wire:    %s\n", tgt.wire);
    if (!ini.ok || !tgt.ok) {
        printf("  FAIL: %s%s\n", !ini.ok ? "initiator: " : "target: ",
               !ini.ok ? ini.why : tgt.why);
        return false;
    }

    double mib_s = ini.xfer_ms > 0
                       ? ((double)xfer_len / 1048576.0) / (ini.xfer_ms / 1000.0)
                       : 0.0;
    printf("  %zu bytes in %.1f ms (%.1f MiB/s), target compared, 0 wrong\n",
           xfer_len, ini.xfer_ms, mib_s);
    printf("  initiator: engine tx %" PRIu64 " (%" PRIu64
           " payload in place), wire tx %" PRIu64 " (%" PRIu64
           " extbuf, %" PRIu64 " copied, %" PRIu64 " dropped)\n",
           ini.st.tx_frames, ini.st.tx_frames_iov, ini.ws.tx_frames,
           ini.ws.tx_extbuf_frames, ini.ws.tx_copied_frames, ini.ws.tx_dropped);
    printf("  target:    engine rx %" PRIu64 " (%" PRIu64
           " left in mbufs), wire rx %" PRIu64 " (%" PRIu64
           " gathered); dma %" PRIu64 " copies, %" PRIu64 " bytes, %" PRIu64
           " fallbacks\n",
           tgt.st.rx_frames, tgt.st.rx_frames_ext, tgt.ws.rx_frames,
           tgt.ws.rx_multiseg, tgt.ws.dma_copies, tgt.ws.dma_bytes,
           tgt.ws.dma_fallbacks);

    /* The paths the backend claims: payloads of 2 KiB and more attached
     * where they are, smaller ones copied. */
    if (tc->rudi && tc->mtu >= 9000 && ini.ws.tx_extbuf_frames == 0) {
        printf("  FAIL: no RUDI payload went out as an external buffer\n");
        ok = false;
    }
    if (tgt.st.rx_frames_ext == 0 || tgt.st.rx_frames_ext != tgt.st.rx_frames) {
        printf("  FAIL: received frames were copied out of their mbufs\n");
        ok = false;
    }
    if (tc->dma && tgt.ws.dma_copies == 0) {
        printf("  FAIL: the dmadev placed nothing\n");
        ok = false;
    }
    if (ini.ws.tx_dropped != 0 || tgt.ws.tx_dropped != 0) {
        printf("  FAIL: the port dropped frames\n");
        ok = false;
    }
    printf("  %s\n\n", ok ? "PASS" : "FAIL");
    return ok;
}

int main(int argc, char **argv)
{
    unsigned run = 0, passed = 0;
    const char *len = getenv("UET_DPDK_TEST_LEN");

    signal(SIGPIPE, SIG_IGN);
    if (len != NULL && *len != '\0') {
        char *end = NULL;
        unsigned long long v = strtoull(len, &end, 0);

        if (end == len || *end != '\0' || v < PAGE || v > LEN_MAX) {
            fprintf(stderr, "UET_DPDK_TEST_LEN must be %u..%u\n", PAGE,
                    LEN_MAX);
            return 2;
        }
        xfer_len = (size_t)v;
    }

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        if (argc > 1) {
            bool want = false;
            for (int a = 1; a < argc; a++)
                want = want || strcmp(argv[a], cases[i].name) == 0;
            if (!want)
                continue;
        }
        run++;
        passed += run_case(&cases[i]) ? 1u : 0u;
    }
    printf("%u/%u cases passed\n", passed, run);
    return (run > 0 && passed == run) ? 0 : 1;
}
