/*
 * test_uet_engine.c -- two UET engines on a socketpair wire
 *
 * Runs the engine the server runs, end to end, without a VM: two processes,
 * each with its own engine, joined by a SOCK_SEQPACKET socketpair that
 * carries their Ethernet frames.  It has to be two processes because the
 * reference provider keeps its PDS, RUDI, TSS and impairment state in
 * globals and reads its configuration from the environment.
 *
 * Each process has a window of "guest memory" at guest physical address
 * 4 GiB, mapped identically (GPA - 4 GiB is the offset into the window), and
 * registers its region the way a driver would: a level 1 page list whose
 * pages are laid out in reverse order, with the list itself in guest memory
 * too.  The 4 GiB base means a provider that dereferenced a DMA address
 * instead of translating it would fault rather than pass by accident.
 *
 * In each case the initiator writes 1 MiB into the target's region at an
 * unaligned offset, and the target compares every byte of the region with
 * what should be there, including the untouched bytes on either side.
 *
 * Every frame either side transmits is also dissected here, independently
 * of the provider, so each case can check what actually crossed the wire:
 * ARP, RUD or RUDI requests, retransmissions, ACKs, and whether security
 * headers wrap every UET frame and the payload is no longer readable.
 *
 * Copyright (C) Advanced Micro Devices, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <poll.h>
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
#include "uet_nic_ernic.h"

#define PAGE      4096u
#define GPA_BASE  UINT64_C(0x100000000)
#define XFER_LEN  (1024u * 1024u) /* bytes written in every case */
#define DST_OFF   1000u           /* where they land in the target region */
#define DST_LEN   (XFER_LEN + 2u * PAGE)
#define SRC_PGOFF 0u
#define DST_PGOFF 100u /* the target region starts mid-page */

#define IP_INITIATOR 0xc0a8c865u /* 192.168.200.101 */
#define IP_TARGET    0xc0a8c866u /* 192.168.200.102 */
#define PEER_PID     0u
#define PEER_INDEX   15u

#define CASE_TIMEOUT_S 90
#define PROBE_LEN      32u

/* PDS types, from the UET specification, decoded here independently. */
#define PDS_SECURITY  0x01u
#define PDS_RUD_REQ   0x02u
#define PDS_ROD_REQ   0x03u
#define PDS_RUDI_REQ  0x04u
#define PDS_RUDI_RESP 0x05u
#define PDS_ACK       0x07u
#define PDS_ACK_CC    0x08u
#define PDS_ACK_CCX   0x09u
#define PDS_NACK      0x0au
#define PDS_CTRL      0x0bu
#define PDS_NACK_CCX  0x0cu
#define PDS_RUD_CC    0x0du
#define PDS_ROD_CC    0x0eu
#define PDS_FLAG_RETX 0x10u

struct test_case {
    const char *name;
    const char *what;
    bool rudi;
    enum uet_engine_sec sec;
    uint32_t drop_thresh;  /* UET_PKT_DROP_THRESH */
    unsigned wire_loss_pm; /* frames this test's wire loses, per mille */
    uint32_t rto_ms;
    uint32_t retries;
    /* what must be seen on the wire */
    bool want_rudi;
    bool want_retx;
    bool want_tss;
};

static const struct test_case cases[] = {
    {"rudi-1MiB", "RUDI write into an IDEMPOTENT_SAFE window", true,
     UET_ENGINE_SEC_NONE, 0, 0, 20, 10, true, false, false},
    {"rud-1MiB", "the same write over RUD", false, UET_ENGINE_SEC_NONE, 0, 0,
     20, 10, false, false, false},
    {"rud-drop500", "RUD with UET_PKT_DROP_THRESH=500 (5% of PDS transmits)",
     false, UET_ENGINE_SEC_NONE, 500, 0, 20, 30, false, true, false},
    {"tss-cluster-rud", "RUD with UET_SEC_MODE=cluster", false,
     UET_ENGINE_SEC_CLUSTER, 0, 0, 50, 10, false, false, true},
    /* RUDI has no window: the whole megabyte (1024 packets) is encrypted
     * and sent when the write is posted.  The provider's AES-GCM and
     * per-packet CMAC KDF run in software (at -O0, as its Makefile builds
     * them), about a quarter of a millisecond a packet, so the timeout has
     * to outlast a full window or the initiator re-encrypts everything
     * before it ever reads a response. */
    {"tss-cluster-rudi", "RUDI with UET_SEC_MODE=cluster", true,
     UET_ENGINE_SEC_CLUSTER, 0, 0, 1000, 10, true, false, true},
    {"rudi-wireloss2pct",
     "RUDI with 2% loss on the wire (UET_PKT_DROP_THRESH does not reach "
     "RUDI)",
     true, UET_ENGINE_SEC_NONE, 0, 20, 20, 30, true, true, false},
};

/* ------------------------------------------------------------------ */
/* Guest memory and page lists                                        */
/* ------------------------------------------------------------------ */

struct guest {
    uint8_t *mem;
    size_t size;
    uint64_t maps_read;
    uint64_t maps_write;
};

struct region {
    uint64_t root; /* GPA of the page directory */
    size_t npages;
    size_t len;
    uint32_t page_offset;
};

static void *guest_map(void *ctx, uint64_t addr, size_t len, bool write)
{
    struct guest *g = ctx;

    if (addr < GPA_BASE || len > g->size || addr - GPA_BASE > g->size - len)
        return NULL;
    if (write)
        g->maps_write++;
    else
        g->maps_read++;
    return g->mem + (addr - GPA_BASE);
}

static uint8_t *gpa_ptr(struct guest *g, uint64_t gpa)
{
    return g->mem + (gpa - GPA_BASE);
}

/* Page 0 holds the directory; region page i is guest page npages - i. */
static bool region_init(struct guest *g, struct region *r, size_t len,
                        uint32_t page_offset)
{
    r->len = len;
    r->page_offset = page_offset;
    r->npages = (page_offset + len + PAGE - 1) / PAGE;
    if (r->npages * sizeof(uint64_t) > PAGE)
        return false;

    g->size = (r->npages + 1) * PAGE;
    g->mem = aligned_alloc(PAGE, g->size);
    if (g->mem == NULL)
        return false;
    memset(g->mem, 0, g->size);

    r->root = GPA_BASE;
    for (size_t i = 0; i < r->npages; i++) {
        uint64_t page_gpa = GPA_BASE + (uint64_t)(r->npages - i) * PAGE;
        memcpy(gpa_ptr(g, r->root) + i * sizeof(uint64_t), &page_gpa,
               sizeof(page_gpa));
    }
    return true;
}

static uint8_t *region_byte(struct guest *g, const struct region *r, size_t off)
{
    size_t abs = r->page_offset + off;
    uint64_t page_gpa;

    memcpy(&page_gpa, gpa_ptr(g, r->root) + (abs / PAGE) * sizeof(uint64_t),
           sizeof(page_gpa));
    return gpa_ptr(g, page_gpa + abs % PAGE);
}

/* The bytes being written: splitmix64 of the 8-byte word index. */
static uint8_t pattern(size_t off)
{
    uint64_t z = (uint64_t)(off / 8) + UINT64_C(0x9e3779b97f4a7c15);

    z = (z ^ (z >> 30)) * UINT64_C(0xbf58476d1ce4e5b9);
    z = (z ^ (z >> 27)) * UINT64_C(0x94d049bb133111eb);
    z ^= z >> 31;
    return (uint8_t)(z >> ((off % 8) * 8));
}

/* ------------------------------------------------------------------ */
/* The wire, and what crossed it                                      */
/* ------------------------------------------------------------------ */

struct wire_count {
    uint64_t frames;
    uint64_t arp;
    uint64_t uet;
    uint64_t secured; /* UET frames whose first header is TSS */
    uint64_t rud_req;
    uint64_t rod_req;
    uint64_t rudi_req;
    uint64_t rudi_resp;
    uint64_t ack;
    uint64_t nack;
    uint64_t ctrl;
    uint64_t retx; /* requests flagged as retransmissions */
    uint64_t other;
};

struct node {
    const struct test_case *tc;
    struct uet_engine *e;
    struct guest g;
    struct region r;
    int wire_fd;
    int ctl_fd;
    struct wire_count tx;
    uint64_t wire_full; /* frames the socket would not take */
    uint64_t wire_lost; /* frames this test dropped on purpose */
    uint64_t rx_unclaimed;
    uint64_t rng;
    uint8_t probe[PROBE_LEN];
    bool probe_set;
    uint64_t probe_hits; /* frames carrying the payload in the clear */
};

static uint16_t rd16(const uint8_t *p)
{
    return (uint16_t)(((unsigned)p[0] << 8) | p[1]);
}

/* True when @needle occurs anywhere in @hay. */
static bool contains(const uint8_t *hay, size_t hay_len, const uint8_t *needle,
                     size_t needle_len)
{
    if (needle_len == 0 || hay_len < needle_len)
        return false;
    for (size_t i = 0; i + needle_len <= hay_len; i++) {
        if (hay[i] == needle[0] && memcmp(hay + i, needle, needle_len) == 0)
            return true;
    }
    return false;
}

static void classify(struct node *n, const uint8_t *f, size_t len)
{
    struct wire_count *c = &n->tx;

    c->frames++;
    if (len < 14)
        return;
    if (rd16(f + 12) == 0x0806) {
        c->arp++;
        return;
    }
    if (rd16(f + 12) != 0x0800 || len < 34 || f[14 + 9] != 253) {
        c->other++;
        return;
    }

    c->uet++;
    size_t ihl = (size_t)(f[14] & 0x0fu) * 4u;
    size_t o = 14 + ihl + 4; /* past the entropy header */
    if (len < o + 2) {
        c->other++;
        return;
    }

    unsigned type = rd16(f + o) >> 11;
    unsigned flags = rd16(f + o) & 0x7fu;
    switch (type) {
    case PDS_SECURITY:
        c->secured++;
        break;
    case PDS_RUD_REQ:
    case PDS_RUD_CC:
        c->rud_req++;
        c->retx += (flags & PDS_FLAG_RETX) ? 1u : 0u;
        break;
    case PDS_ROD_REQ:
    case PDS_ROD_CC:
        c->rod_req++;
        c->retx += (flags & PDS_FLAG_RETX) ? 1u : 0u;
        break;
    case PDS_RUDI_REQ:
        c->rudi_req++;
        c->retx += (flags & PDS_FLAG_RETX) ? 1u : 0u;
        break;
    case PDS_RUDI_RESP:
        c->rudi_resp++;
        break;
    case PDS_ACK:
    case PDS_ACK_CC:
    case PDS_ACK_CCX:
        c->ack++;
        break;
    case PDS_NACK:
    case PDS_NACK_CCX:
        c->nack++;
        break;
    case PDS_CTRL:
        c->ctrl++;
        break;
    default:
        c->other++;
        break;
    }

    if (n->probe_set && contains(f, len, n->probe, PROBE_LEN))
        n->probe_hits++;
}

static uint64_t xorshift(uint64_t *s)
{
    *s ^= *s << 13;
    *s ^= *s >> 7;
    *s ^= *s << 17;
    return *s;
}

static int wire_tx(void *ctx, const void *frame, size_t len)
{
    struct node *n = ctx;
    const uint8_t *f = frame;

    classify(n, f, len);

    /* ARP is never lost here, so loss only ever exercises the transport. */
    if (n->tc->wire_loss_pm != 0 && len >= 14 && rd16(f + 12) == 0x0800 &&
        xorshift(&n->rng) % 1000u < n->tc->wire_loss_pm) {
        n->wire_lost++;
        return 0;
    }

    if (send(n->wire_fd, frame, len, MSG_DONTWAIT) < 0) {
        if (errno == EAGAIN || errno == ENOBUFS) {
            n->wire_full++;
            return -EAGAIN;
        }
        return -errno;
    }
    return 0;
}

static double now_ms(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1000.0 + (double)ts.tv_nsec / 1e6;
}

/* Move frames off the wire into the engine and run it. */
static void pump(struct node *n)
{
    uint8_t buf[9216];

    if (!uet_engine_has_work(n->e)) {
        struct pollfd p = {.fd = n->wire_fd, .events = POLLIN};
        (void)poll(&p, 1, 1);
    }

    for (unsigned round = 0; round < 16; round++) {
        unsigned got = 0;

        for (; got < 64; got++) {
            ssize_t r = recv(n->wire_fd, buf, sizeof(buf), MSG_DONTWAIT);
            if (r <= 0)
                break;
            if (!uet_engine_rx_frame(n->e, buf, (size_t)r))
                n->rx_unclaimed++;
        }
        uet_engine_poll(n->e);
        if (got == 0)
            break;
    }
}

/* ------------------------------------------------------------------ */
/* Control channel and reports                                        */
/* ------------------------------------------------------------------ */

enum { CTL_KEY = 1, CTL_DONE, CTL_VERIFIED };

struct ctl {
    uint32_t type;
    int32_t status;
    uint64_t rkey;
    uint64_t a;
    uint64_t b;
};

struct report {
    int ok;
    char why[200];
    double resolve_ms; /* first post attempt until the post was taken */
    double xfer_ms;    /* post until completion */
    struct uet_engine_stats st;
    struct wire_count tx;
    uint64_t wire_full;
    uint64_t wire_lost;
    uint64_t rx_unclaimed;
    uint64_t probe_hits;
    uint64_t maps_read;
    uint64_t maps_write;
    uint64_t compared;
    uint64_t mismatches;
    uint64_t guard_bad;
};

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

static bool ctl_send(int fd, const struct ctl *m)
{
    return send(fd, m, sizeof(*m), 0) == (ssize_t)sizeof(*m);
}

static bool ctl_poll(int fd, struct ctl *m)
{
    return recv(fd, m, sizeof(*m), MSG_DONTWAIT) == (ssize_t)sizeof(*m);
}

/* ------------------------------------------------------------------ */
/* The two roles                                                      */
/* ------------------------------------------------------------------ */

static bool node_start(struct node *n, uint32_t ip, size_t len,
                       uint32_t page_offset, struct report *rep)
{
    struct uet_engine_cfg cfg;
    char err[256] = "";

    if (!region_init(&n->g, &n->r, len, page_offset)) {
        fail(rep, "cannot set up guest memory");
        return false;
    }

    uet_engine_cfg_defaults(&cfg);
    cfg.ip = ip;
    cfg.sec = n->tc->sec;
    cfg.rto_ms = n->tc->rto_ms;
    cfg.max_retries = n->tc->retries;
    cfg.drop_thresh = n->tc->drop_thresh;

    struct uet_engine_wire wire = {.tx = wire_tx, .ctx = n};
    struct uet_engine_dma dma = {.map = guest_map, .ctx = &n->g};

    n->e = uet_engine_create(&cfg, &wire, &dma, err, sizeof(err));
    if (n->e == NULL) {
        fail(rep, "uet_engine_create: %s", err);
        return false;
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
    rep->tx = n->tx;
    rep->wire_full = n->wire_full;
    rep->wire_lost = n->wire_lost;
    rep->rx_unclaimed = n->rx_unclaimed;
    rep->probe_hits = n->probe_hits;
    rep->maps_read = n->g.maps_read;
    rep->maps_write = n->g.maps_write;
    free(n->g.mem);
}

static void run_target(struct node *n, struct report *rep)
{
    struct uet_engine_mr_desc d;
    struct ctl m;
    uint32_t mr;
    uint64_t rkey;
    int rc;
    double deadline;

    if (!node_start(n, IP_TARGET, DST_LEN, DST_PGOFF, rep))
        return;

    memset(&d, 0, sizeof(d));
    d.root = n->r.root;
    d.page_size = PAGE;
    d.level = 1;
    d.page_offset = n->r.page_offset;
    d.len = n->r.len;
    d.remote_write = true;
    d.idempotent_safe = true;
    rc = uet_engine_mr_reg(n->e, &d, &mr, &rkey);
    if (rc != 0) {
        fail(rep, "mr_reg: %s", strerror(-rc));
        return;
    }

    memset(&m, 0, sizeof(m));
    m.type = CTL_KEY;
    m.rkey = rkey;
    m.a = n->r.len;
    if (!ctl_send(n->ctl_fd, &m)) {
        fail(rep, "cannot send the key");
        return;
    }

    /* Serve until the initiator says its write completed. */
    deadline = now_ms() + (CASE_TIMEOUT_S - 10) * 1000.0;
    for (;;) {
        pump(n);
        if (ctl_poll(n->ctl_fd, &m) && m.type == CTL_DONE)
            break;
        if (now_ms() > deadline) {
            fail(rep, "no word from the initiator");
            return;
        }
    }

    /* Every byte of the region: the write, and the untouched edges. */
    for (size_t off = 0; off < n->r.len; off++) {
        uint8_t got = *region_byte(&n->g, &n->r, off);
        bool inside = off >= DST_OFF && off < DST_OFF + XFER_LEN;
        uint8_t want = inside ? pattern(off - DST_OFF) : 0;

        if (got == want) {
            rep->compared += inside ? 1u : 0u;
            continue;
        }
        if (inside) {
            if (rep->mismatches++ == 0)
                fail(rep, "byte %zu of the write is %#x, not %#x",
                     off - DST_OFF, got, want);
        } else {
            if (rep->guard_bad++ == 0)
                fail(rep, "byte %zu outside the write was changed", off);
        }
    }

    memset(&m, 0, sizeof(m));
    m.type = CTL_VERIFIED;
    m.status = (rep->mismatches == 0 && rep->guard_bad == 0) ? 0 : -1;
    (void)ctl_send(n->ctl_fd, &m);

    /* Keep answering until the initiator hangs up, so its last ACKs and
     * close handshakes are not cut off. */
    deadline = now_ms() + 3000.0;
    while (now_ms() < deadline) {
        pump(n);
        if (recv(n->ctl_fd, &m, sizeof(m), MSG_DONTWAIT) == 0)
            break;
    }

    (void)uet_engine_mr_dereg(n->e, mr);
}

static void run_initiator(struct node *n, struct report *rep)
{
    struct uet_engine_mr_desc d;
    struct uet_engine_rma w;
    struct uet_engine_comp c;
    struct ctl m;
    uint32_t mr, peer;
    int rc;
    double t0, t1, deadline;

    if (!node_start(n, IP_INITIATOR, XFER_LEN, SRC_PGOFF, rep))
        return;

    for (size_t off = 0; off < XFER_LEN; off++)
        *region_byte(&n->g, &n->r, off) = pattern(off);
    for (unsigned i = 0; i < PROBE_LEN; i++)
        n->probe[i] = pattern(i);
    n->probe_set = true;

    memset(&d, 0, sizeof(d));
    d.root = n->r.root;
    d.page_size = PAGE;
    d.level = 1;
    d.page_offset = n->r.page_offset;
    d.len = n->r.len;
    uint64_t lkey;
    rc = uet_engine_mr_reg(n->e, &d, &mr, &lkey);
    if (rc != 0) {
        fail(rep, "mr_reg: %s", strerror(-rc));
        return;
    }

    deadline = now_ms() + 10000.0;
    while (!ctl_poll(n->ctl_fd, &m) || m.type != CTL_KEY) {
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
    w.local_addr = 0;
    w.len = XFER_LEN;
    w.remote_addr = DST_OFF;
    w.rkey = m.rkey;
    w.rudi = n->tc->rudi;
    w.cookie = 0x5eed;

    /* The first attempts find the target's MAC unresolved and start ARP.
     * The attempt that is taken already transmits the message's first
     * window, so the transfer is timed from the start of that call. */
    t0 = now_ms();
    deadline = t0 + 10000.0;
    for (;;) {
        t1 = now_ms();
        rc = uet_engine_post_write(n->e, &w);
        if (rc != -EAGAIN || t1 > deadline)
            break;
        pump(n);
    }
    if (rc != 0) {
        fail(rep, "post_write: %s", strerror(-rc));
        return;
    }
    rep->resolve_ms = t1 - t0;

    deadline = t1 + (CASE_TIMEOUT_S - 20) * 1000.0;
    for (;;) {
        pump(n);
        if (uet_engine_poll_comp(n->e, &c, 1) == 1)
            break;
        if (now_ms() > deadline) {
            fail(rep, "the write never completed");
            return;
        }
    }
    rep->xfer_ms = now_ms() - t1;
    if (c.cookie != w.cookie)
        fail(rep, "completion for cookie %#" PRIx64, c.cookie);
    if (c.status != 0)
        fail(rep, "the write failed: %s", strerror(-c.status));

    memset(&m, 0, sizeof(m));
    m.type = CTL_DONE;
    (void)ctl_send(n->ctl_fd, &m);

    deadline = now_ms() + 30000.0;
    for (;;) {
        pump(n);
        if (ctl_poll(n->ctl_fd, &m) && m.type == CTL_VERIFIED)
            break;
        if (now_ms() > deadline) {
            fail(rep, "the target never reported its compare");
            return;
        }
    }
    if (m.status != 0)
        fail(rep, "the target's compare failed");

    /* Let the last ACKs drain before the peer goes away. */
    deadline = now_ms() + 200.0;
    while (now_ms() < deadline)
        pump(n);

    (void)uet_engine_peer_remove(n->e, peer);
    (void)uet_engine_mr_dereg(n->e, mr);
}

/* ------------------------------------------------------------------ */
/* Driver                                                             */
/* ------------------------------------------------------------------ */

static pid_t spawn(const struct test_case *tc, const char *role, int wire_fd,
                   int ctl_fd, int report_fd, char *log, size_t loglen,
                   const int *others, size_t nothers)
{
    const char *tmp = getenv("TMPDIR");

    snprintf(log, loglen, "%s/uet-engine-%s-%s-%d.log",
             tmp != NULL ? tmp : "/tmp", tc->name, role, (int)getpid());

    fflush(NULL);
    pid_t pid = fork();
    if (pid != 0)
        return pid;

    /* child */
    struct node n;
    struct report rep;

    /* Only this side's ends, or a dead peer would never read as EOF. */
    for (size_t i = 0; i < nothers; i++)
        close(others[i]);
    alarm(CASE_TIMEOUT_S);

    /* The provider logs to stdout; keep it out of the summary. */
    int fd = open(log, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd >= 0) {
        dup2(fd, STDOUT_FILENO);
        dup2(fd, STDERR_FILENO);
        close(fd);
    }

    memset(&n, 0, sizeof(n));
    memset(&rep, 0, sizeof(rep));
    rep.ok = 1;
    n.tc = tc;
    n.wire_fd = wire_fd;
    n.ctl_fd = ctl_fd;
    n.rng = UINT64_C(0x2545f4914f6cdd1d) ^ (uint64_t)(uint32_t)getpid();

    if (strcmp(role, "target") == 0)
        run_target(&n, &rep);
    else
        run_initiator(&n, &rep);
    node_finish(&n, &rep);

    if (write(report_fd, &rep, sizeof(rep)) != (ssize_t)sizeof(rep))
        rep.ok = 0;
    close(report_fd);
    close(wire_fd);
    close(ctl_fd);
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

static void print_side(const char *role, const struct report *r)
{
    const struct wire_count *t = &r->tx;

    printf("  %-9s tx %" PRIu64 " frames: %" PRIu64 " ARP, %" PRIu64
           " UET (%" PRIu64 " TSS-wrapped)",
           role, t->frames, t->arp, t->uet, t->secured);
    if (t->secured < t->uet)
        printf(", %" PRIu64 " RUD req, %" PRIu64 " RUDI req, %" PRIu64
               " RUDI resp, %" PRIu64 " ACK, %" PRIu64 " NACK, %" PRIu64
               " CTRL, %" PRIu64 " flagged RETX",
               t->rud_req, t->rudi_req, t->rudi_resp, t->ack, t->nack, t->ctrl,
               t->retx);
    printf("\n");
    printf("            engine rx %" PRIu64 " tx %" PRIu64
           " (wire full %" PRIu64 ", test loss %" PRIu64 "), ARP req %" PRIu64
           " rep %" PRIu64 "; DMA maps read %" PRIu64 " write %" PRIu64
           " faults %" PRIu64 "\n",
           r->st.rx_frames, r->st.tx_frames, r->wire_full, r->wire_lost,
           r->st.arp_requests, r->st.arp_replies, r->st.dma_read_maps,
           r->st.dma_write_maps, r->st.dma_faults);
}

/* What the wire has to show for the case to count. */
static void check_wire(const struct test_case *tc, const struct report *ini,
                       const struct report *tgt, struct report *verdict)
{
    const struct wire_count *i = &ini->tx;
    const struct wire_count *t = &tgt->tx;
    uint64_t data_pkts = XFER_LEN / 1024u;

    if (i->arp == 0 || tgt->st.arp_replies == 0)
        fail(verdict, "the target's MAC was not resolved by ARP");
    if (ini->st.dma_read_maps == 0 || tgt->st.dma_write_maps == 0)
        fail(verdict, "region memory was not reached through the DMA hook");
    if (ini->st.dma_faults != 0 || tgt->st.dma_faults != 0)
        fail(verdict, "DMA translation faults");

    if (tc->want_tss) {
        if (i->uet == 0 || i->secured != i->uet || t->secured != t->uet)
            fail(verdict, "UET frames left the engine without a TSS header");
        if (ini->probe_hits != 0)
            fail(verdict, "the payload crossed the wire in the clear");
        if (i->uet < data_pkts)
            fail(verdict, "fewer frames than the data needs");
        return;
    }

    if (ini->probe_hits == 0)
        fail(verdict, "the payload was not found on the wire");
    if (tc->want_rudi) {
        if (i->rudi_req < data_pkts || i->rud_req != 0)
            fail(verdict,
                 "the write did not go RUDI (%" PRIu64 " RUDI, %" PRIu64
                 " RUD requests)",
                 i->rudi_req, i->rud_req);
        if (t->rudi_resp < data_pkts)
            fail(verdict, "the target did not answer every RUDI request");
    } else {
        if (i->rud_req < data_pkts || i->rudi_req != 0)
            fail(verdict,
                 "the write did not go RUD (%" PRIu64 " RUD, %" PRIu64
                 " RUDI requests)",
                 i->rud_req, i->rudi_req);
        if (t->ack == 0)
            fail(verdict, "the target never acknowledged");
    }
    /* A RUD retransmission carries the RETX flag.  The provider does not
     * flag RUDI ones, so for RUDI they show up only as more requests than
     * data packets. */
    if (tc->want_retx && i->retx == 0 && i->rud_req + i->rudi_req <= data_pkts)
        fail(verdict, "no retransmission was needed");
}

static bool run_case(const struct test_case *tc)
{
    int wire[2], ctl[2], rp_ini[2], rp_tgt[2];
    char log_ini[256], log_tgt[256];
    struct report ini, tgt, verdict;
    int st_ini = 0, st_tgt = 0;

    printf("case %s: %s\n", tc->name, tc->what);
    fflush(stdout);

    if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, wire) != 0 ||
        socketpair(AF_UNIX, SOCK_SEQPACKET, 0, ctl) != 0 || pipe(rp_ini) != 0 ||
        pipe(rp_tgt) != 0) {
        printf("  FAIL: %s\n", strerror(errno));
        return false;
    }
    for (int i = 0; i < 2; i++) {
        int sz = 4 * 1024 * 1024;
        (void)setsockopt(wire[i], SOL_SOCKET, SO_SNDBUF, &sz, sizeof(sz));
        (void)setsockopt(wire[i], SOL_SOCKET, SO_RCVBUF, &sz, sizeof(sz));
    }

    const int not_tgt[] = {wire[0], ctl[0], rp_tgt[0], rp_ini[0], rp_ini[1]};
    const int not_ini[] = {wire[1], ctl[1], rp_ini[0], rp_tgt[0], rp_tgt[1]};
    pid_t tgt_pid =
        spawn(tc, "target", wire[1], ctl[1], rp_tgt[1], log_tgt,
              sizeof(log_tgt), not_tgt, sizeof(not_tgt) / sizeof(not_tgt[0]));
    pid_t ini_pid =
        spawn(tc, "initiator", wire[0], ctl[0], rp_ini[1], log_ini,
              sizeof(log_ini), not_ini, sizeof(not_ini) / sizeof(not_ini[0]));
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
    close(rp_ini[0]);
    close(rp_tgt[0]);
    (void)waitpid(ini_pid, &st_ini, 0);
    (void)waitpid(tgt_pid, &st_tgt, 0);

    memset(&verdict, 0, sizeof(verdict));
    verdict.ok = 1;
    if (!have_ini || !have_tgt)
        fail(&verdict,
             "a process died without reporting (initiator %#x, "
             "target %#x)",
             (unsigned)st_ini, (unsigned)st_tgt);
    else if (!ini.ok)
        fail(&verdict, "initiator: %s", ini.why);
    else if (!tgt.ok)
        fail(&verdict, "target: %s", tgt.why);
    else if (!WIFEXITED(st_ini) || WEXITSTATUS(st_ini) != 0 ||
             !WIFEXITED(st_tgt) || WEXITSTATUS(st_tgt) != 0)
        fail(&verdict, "a process exited badly (initiator %#x, target %#x)",
             (unsigned)st_ini, (unsigned)st_tgt);
    else
        check_wire(tc, &ini, &tgt, &verdict);

    if (have_ini && have_tgt) {
        double mib_s = ini.xfer_ms > 0
                           ? ((double)XFER_LEN / (1024.0 * 1024.0)) /
                                 (ini.xfer_ms / 1000.0)
                           : 0.0;
        uint64_t sent = ini.tx.rud_req + ini.tx.rudi_req;
        printf("  %u bytes in %.1f ms (%.1f MiB/s) after %.0f us of ARP; "
               "target compared %" PRIu64 " bytes, %" PRIu64 " wrong, %" PRIu64
               " guard bytes changed\n",
               XFER_LEN, ini.xfer_ms, mib_s, ini.resolve_ms * 1000.0,
               tgt.compared, tgt.mismatches, tgt.guard_bad);
        if (ini.tx.secured < ini.tx.uet)
            printf("  %" PRIu64 " requests on the wire for %u data packets, "
                   "%" PRIu64 " flagged RETX\n",
                   sent, XFER_LEN / 1024u, ini.tx.retx);
        print_side("initiator", &ini);
        print_side("target", &tgt);
    }

    if (verdict.ok) {
        printf("  PASS\n\n");
        unlink(log_ini);
        unlink(log_tgt);
        return true;
    }
    printf("  FAIL: %s\n", verdict.why);
    dump_log(log_ini);
    dump_log(log_tgt);
    printf("\n");
    return false;
}

/* ------------------------------------------------------------------ */
/* The wire-side filter on its own                                    */
/* ------------------------------------------------------------------ */

struct filter_tx {
    uint8_t frame[128];
    size_t len;
    unsigned count;
};

static int filter_tx(void *ctx, const void *frame, size_t len)
{
    struct filter_tx *t = ctx;

    t->count++;
    t->len = len < sizeof(t->frame) ? len : sizeof(t->frame);
    memcpy(t->frame, frame, t->len);
    return 0;
}

static void put16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)v;
}

static void put32(uint8_t *p, uint32_t v)
{
    put16(p, (uint16_t)(v >> 16));
    put16(p + 2, (uint16_t)v);
}

static const uint8_t filter_mac[6] = {0x02, 0x55, 0xc0, 0xa8, 0xc8, 0x65};
static const uint8_t peer_mac[6] = {0x02, 0x55, 0xc0, 0xa8, 0xc8, 0x66};

static size_t build_arp(uint8_t *f, uint16_t op, uint32_t target_ip)
{
    memset(f, 0, 60);
    memset(f, 0xff, 6);
    memcpy(f + 6, peer_mac, 6);
    put16(f + 12, 0x0806);
    put16(f + 14, 1);
    put16(f + 16, 0x0800);
    f[18] = 6;
    f[19] = 4;
    put16(f + 20, op);
    memcpy(f + 22, peer_mac, 6);
    put32(f + 28, IP_TARGET);
    put32(f + 38, target_ip);
    return 60;
}

/* An Ethernet frame holding an IPv4 datagram of @payload bytes, padded with
 * @pad trailing bytes the way a short Ethernet frame is. */
static size_t build_ipv4(uint8_t *f, uint8_t proto, uint32_t dst_ip,
                         const uint8_t *dst_mac, size_t payload, size_t pad)
{
    size_t tot = 20 + payload;
    uint32_t sum = 0;

    memset(f, 0, 14 + tot + pad);
    memcpy(f, dst_mac, 6);
    memcpy(f + 6, peer_mac, 6);
    put16(f + 12, 0x0800);
    f[14] = 0x45;
    put16(f + 16, (uint16_t)tot);
    put16(f + 20, 0x4000); /* DF */
    f[22] = 64;
    f[23] = proto;
    put32(f + 26, IP_TARGET);
    put32(f + 30, dst_ip);
    for (unsigned i = 0; i < 20; i += 2)
        sum += rd16(f + 14 + i);
    while (sum >> 16)
        sum = (sum & 0xffffu) + (sum >> 16);
    put16(f + 24, (uint16_t)~sum);
    return 14 + tot + pad;
}

static bool test_wire_filter(void)
{
    struct filter_tx tx;
    struct uet_nic_ernic_cfg cfg = {
        .ip = IP_INITIATOR,
        .mtu = 1500,
        .name = "test",
        .tx = filter_tx,
        .tx_ctx = &tx,
    };
    struct uet_nic_ernic_stats st;
    uint8_t f[256];
    size_t len;
    bool ok = true;

    memset(&tx, 0, sizeof(tx));
    memcpy(cfg.mac, filter_mac, 6);
    struct uet_nic_ernic *n = uet_nic_ernic_create(&cfg);
    if (n == NULL) {
        printf("  FAIL: cannot create the port\n");
        return false;
    }

#define EXPECT(cond, what)                \
    do {                                  \
        if (!(cond)) {                    \
            printf("  FAIL: %s\n", what); \
            ok = false;                   \
        }                                 \
    } while (0)

    printf("case wire-filter: what the engine takes off the wire\n");

    /* ARP for the engine is answered, unicast, with its MAC. */
    len = build_arp(f, 1, IP_INITIATOR);
    EXPECT(uet_nic_ernic_rx_frame(n, f, len), "ARP for the engine not taken");
    EXPECT(tx.count == 1 && tx.len >= 42 && rd16(tx.frame + 20) == 2 &&
               memcmp(tx.frame, peer_mac, 6) == 0 &&
               memcmp(tx.frame + 22, filter_mac, 6) == 0,
           "no correct ARP reply");

    /* ARP for anyone else is the guest's, and is not answered. */
    len = build_arp(f, 1, IP_INITIATOR + 1);
    EXPECT(!uet_nic_ernic_rx_frame(n, f, len), "ARP for another host taken");
    EXPECT(tx.count == 1, "ARP for another host answered");

    /* A UET datagram for the engine is queued without its padding. */
    len = build_ipv4(f, 253, IP_INITIATOR, filter_mac, 30, 10);
    EXPECT(uet_nic_ernic_rx_frame(n, f, len), "UET frame not taken");
    EXPECT(uet_nic_ernic_rx_pending(n), "UET frame not queued");

    /* Not UET, or not the engine's: left for the guest. */
    len = build_ipv4(f, 6, IP_INITIATOR, filter_mac, 30, 0);
    EXPECT(!uet_nic_ernic_rx_frame(n, f, len), "TCP to the engine taken");
    len = build_ipv4(f, 253, IP_INITIATOR + 1, filter_mac, 30, 0);
    EXPECT(!uet_nic_ernic_rx_frame(n, f, len), "UET for another host taken");
    len = build_ipv4(f, 253, IP_INITIATOR, peer_mac, 30, 0);
    EXPECT(!uet_nic_ernic_rx_frame(n, f, len), "UET to another MAC taken");

    /* Malformed UET for the engine: taken off the wire, and dropped. */
    uet_nic_ernic_get_stats(n, &st);
    uint64_t dropped = st.rx_dropped;

    len = build_ipv4(f, 253, IP_INITIATOR, filter_mac, 30, 0);
    f[24] ^= 0x55; /* header checksum */
    EXPECT(uet_nic_ernic_rx_frame(n, f, len), "bad checksum not taken");
    len = build_ipv4(f, 253, IP_INITIATOR, filter_mac, 30, 0);
    put16(f + 16, 1400); /* longer than what arrived */
    put16(f + 24, 0);
    {
        uint32_t sum = 0;
        for (unsigned i = 0; i < 20; i += 2)
            sum += rd16(f + 14 + i);
        while (sum >> 16)
            sum = (sum & 0xffffu) + (sum >> 16);
        put16(f + 24, (uint16_t)~sum);
    }
    EXPECT(uet_nic_ernic_rx_frame(n, f, len), "overlong datagram not taken");
    len = build_ipv4(f, 253, IP_INITIATOR, filter_mac, 30, 0);
    f[14] = 0x46; /* options */
    EXPECT(uet_nic_ernic_rx_frame(n, f, len), "IP options not taken");
    len = build_ipv4(f, 253, IP_INITIATOR, filter_mac, 30, 0);
    /* Too short to hold the IP header: not recognisably the engine's. */
    EXPECT(!uet_nic_ernic_rx_frame(n, f, 30), "truncated frame taken");

    uet_nic_ernic_get_stats(n, &st);
    EXPECT(st.rx_dropped == dropped + 3,
           "malformed datagrams were not dropped");
    EXPECT(st.rx_frames == 1, "a malformed datagram was queued");
#undef EXPECT

    uet_nic_ernic_destroy(n);
    printf("  %" PRIu64 " queued, %" PRIu64 " dropped, %" PRIu64
           " ARP replies\n",
           st.rx_frames, st.rx_dropped, st.arp_replies);
    printf("  %s\n\n", ok ? "PASS" : "FAIL");
    return ok;
}

int main(int argc, char **argv)
{
    unsigned passed = 0, run = 0;

    /* A child that dies must not take the driver with it. */
    signal(SIGPIPE, SIG_IGN);

    if (argc == 1 || (argc > 1 && strcmp(argv[1], "wire-filter") == 0)) {
        run++;
        passed += test_wire_filter() ? 1u : 0u;
    }

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        /* Optional filter: run only the cases named on the command line. */
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
