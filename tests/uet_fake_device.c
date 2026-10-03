/*
 * uet_fake_device.c -- the device half of the guest library's test
 *
 * One ernic device reduced to what libuet_ernic reaches: the UET command
 * channel (uet_svc.c) and the engine, the real ones, behind the socket
 * protocol in guest/tests/fake_device_proto.h instead of ionic rings.  The
 * guest's memory is a memfd this process maps too, as a vfio-user server
 * maps a VM's; guest physical addresses are offsets into it from
 * FDEV_GPA_BASE.  The engine's frames go over the wire socket it is given.
 *
 * It has to be a separate executable: the guest side links libuet_ernic,
 * which defines the same uet_* functions as the reference library linked
 * here.
 *
 * Usage: uet_fake_device IPV4 MEM_FD MEM_LEN CHAN_FD WIRE_FD [v1]
 *
 * With v1 it plays a device of ABI version 1: QUERY reports version 1 and
 * no ABORT, and a capsule of a later version is refused with EPROTO.
 *
 * It runs until the guest closes the device, waits for the engine to hand
 * everything back, prints one line of statistics and exits 0 when the
 * channel and the engine kept nothing, 1 otherwise.
 *
 * Copyright (C) Advanced Micro Devices, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <endian.h>
#include <errno.h>
#include <inttypes.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "fake_device_proto.h"
#include "uet_engine.h"
#include "uet_ernic_abi.h"
#include "uet_svc.h"

#define MAX_MRS 64u

struct dev {
    uint8_t *mem;
    size_t mem_len;
    int chan;
    int wire;
    struct uet_engine *e;
    struct uet_svc *svc;
    struct {
        bool used;
        uint32_t lkey;
        uint64_t offset;
        uint64_t length;
    } mrs[MAX_MRS];
    bool bye;
    bool wire_down; /* lose every IP frame (FDEV_WIRE) */
    bool v1;        /* play an ABI version 1 device */
    /* FDEV_HOLD: a reply kept back, and when to let it go */
    int hold_op;         /* opcode to keep, or -1 */
    bool held;           /* one is kept */
    uint64_t hold_after; /* commands after it, before it goes */
    struct fdev_msg held_msg;
};

static bool parse_u64(const char *s, uint64_t *out)
{
    char *end = NULL;

    errno = 0;
    *out = strtoull(s, &end, 0);
    return errno == 0 && end != s && *end == '\0';
}

static double now_ms(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1000.0 + (double)ts.tv_nsec / 1e6;
}

static void *mem_map(void *ctx, uint64_t addr, size_t len, bool write)
{
    struct dev *d = ctx;

    (void)write;
    if (addr < FDEV_GPA_BASE || len > d->mem_len ||
        addr - FDEV_GPA_BASE > d->mem_len - len)
        return NULL;
    return d->mem + (addr - FDEV_GPA_BASE);
}

static int wire_tx(void *ctx, const void *frame, size_t len)
{
    struct dev *d = ctx;
    const uint8_t *f = frame;

    if (d->wire_down && len >= 14 && f[12] == 0x08 && f[13] == 0x00)
        return 0;
    if (send(d->wire, frame, len, MSG_DONTWAIT) < 0)
        return (errno == EAGAIN || errno == ENOBUFS) ? -EAGAIN : -errno;
    return 0;
}

static bool svc_mr_view(void *ctx, uint32_t lkey, struct uet_svc_mr_view *out)
{
    struct dev *d = ctx;

    for (unsigned i = 0; i < MAX_MRS; i++) {
        if (d->mrs[i].used && d->mrs[i].lkey == lkey) {
            memset(out, 0, sizeof(*out));
            out->length = d->mrs[i].length;
            out->page_size = 4096;
            out->base = FDEV_GPA_BASE + d->mrs[i].offset;
            return true;
        }
    }
    return false;
}

static bool svc_reply(void *ctx, uint32_t qp_id, const void *capsule,
                      size_t len)
{
    struct dev *d = ctx;
    struct fdev_msg m;

    memset(&m, 0, sizeof(m));
    m.type = FDEV_REPLY;
    m.qp = qp_id;
    m.len = (uint32_t)(len < sizeof(m.data) ? len : sizeof(m.data));
    memcpy(m.data, capsule, m.len);
    if (d->v1 && m.len == sizeof(struct uet_ernic_reply)) {
        struct uet_ernic_reply r;

        memcpy(&r, m.data, sizeof(r));
        if (r.hdr.opcode == UET_ERNIC_OP_QUERY) {
            r.hdr.version = htole16(1);
            r.u.query.abi_version = htole16(1);
            r.u.query.caps &= htole32(~UET_ERNIC_CAP_ABORT);
            memcpy(m.data, &r, sizeof(r));
        }
    }
    /* A reply the test wants late: kept, as if the device were slow. */
    if (d->hold_op >= 0 && !d->held && m.len > 6 &&
        m.data[6] == (uint8_t)d->hold_op) {
        d->held = true;
        d->held_msg = m;
        return true;
    }
    /* The guest side queues replies until it has a receive posted. */
    (void)send(d->chan, &m, sizeof(m), 0);
    return true;
}

static void handle(struct dev *d, const struct fdev_msg *m)
{
    switch (m->type) {
    case FDEV_REG:
        if (m->offset == UINT64_MAX)
            break; /* not in guest memory: the device cannot reach it */
        for (unsigned i = 0; i < MAX_MRS; i++) {
            if (!d->mrs[i].used) {
                d->mrs[i].used = true;
                d->mrs[i].lkey = m->lkey;
                d->mrs[i].offset = m->offset;
                d->mrs[i].length = m->length;
                break;
            }
        }
        break;
    case FDEV_DEREG:
        uet_svc_mr_gone(d->svc, m->lkey);
        for (unsigned i = 0; i < MAX_MRS; i++) {
            if (d->mrs[i].used && d->mrs[i].lkey == m->lkey)
                d->mrs[i].used = false;
        }
        break;
    case FDEV_CMD:
        if (d->v1 && m->len >= sizeof(struct uet_ernic_hdr)) {
            struct uet_ernic_hdr h;

            memcpy(&h, m->data, sizeof(h));
            if (le16toh(h.version) > 1) {
                struct uet_ernic_reply r;

                memset(&r, 0, sizeof(r));
                r.hdr = h;
                r.hdr.version = htole16(1);
                r.hdr.flags = UET_ERNIC_F_REPLY;
                r.status = (int32_t)htole32(EPROTO);
                (void)svc_reply(d, m->qp, &r, sizeof(r));
                break;
            }
        }
        if (d->held && d->hold_after > 0 && --d->hold_after == 0) {
            (void)send(d->chan, &d->held_msg, sizeof(d->held_msg), 0);
            d->held = false;
            d->hold_op = -1;
        }
        uet_svc_command(d->svc, m->qp, m->data, m->len);
        break;
    case FDEV_HOLD:
        d->hold_op = (int)m->lkey;
        d->hold_after = m->length;
        d->held = false;
        break;
    case FDEV_QP_GONE:
        uet_svc_qp_gone(d->svc, m->qp);
        break;
    case FDEV_BYE:
        d->bye = true;
        break;
    case FDEV_WIRE:
        d->wire_down = m->lkey != 0;
        break;
    default:
        break;
    }
}

static void pump(struct dev *d)
{
    struct pollfd p[2] = {{.fd = d->chan, .events = POLLIN},
                          {.fd = d->wire, .events = POLLIN}};
    uint8_t buf[9216];
    struct fdev_msg m;

    if (!uet_engine_has_work(d->e) && !uet_svc_has_work(d->svc))
        (void)poll(p, 2, 1);
    while (recv(d->chan, &m, sizeof(m), MSG_DONTWAIT) == (ssize_t)sizeof(m))
        handle(d, &m);
    for (unsigned i = 0; i < 256; i++) {
        ssize_t r = recv(d->wire, buf, sizeof(buf), MSG_DONTWAIT);
        if (r <= 0)
            break;
        (void)uet_engine_rx_frame(d->e, buf, (size_t)r);
    }
    uet_engine_poll(d->e);
    uet_svc_poll(d->svc);
}

int main(int argc, char **argv)
{
    struct dev d;
    struct uet_engine_cfg cfg;
    struct uet_svc_stats ss;
    struct uet_engine_stats es;
    uint64_t ip, mem_fd, mem_len, chan, wire;
    char err[256] = "";

    if ((argc != 6 && (argc != 7 || strcmp(argv[6], "v1") != 0)) ||
        !parse_u64(argv[1], &ip) || !parse_u64(argv[2], &mem_fd) ||
        !parse_u64(argv[3], &mem_len) || !parse_u64(argv[4], &chan) ||
        !parse_u64(argv[5], &wire) || ip == 0 || ip > UINT32_MAX ||
        mem_fd > INT32_MAX || chan > INT32_MAX || wire > INT32_MAX) {
        fprintf(stderr, "usage: %s IPV4 MEM_FD MEM_LEN CHAN_FD WIRE_FD [v1]\n",
                argv[0]);
        return 2;
    }

    /* A peer that exits first must not take this one with it. */
    signal(SIGPIPE, SIG_IGN);

    memset(&d, 0, sizeof(d));
    d.hold_op = -1;
    d.v1 = argc == 7;
    d.mem_len = (size_t)mem_len;
    d.chan = (int)chan;
    d.wire = (int)wire;
    d.mem = mmap(NULL, d.mem_len, PROT_READ | PROT_WRITE, MAP_SHARED,
                 (int)mem_fd, 0);
    if (d.mem == MAP_FAILED) {
        perror("mmap");
        return 2;
    }
    alarm(120);

    uet_engine_cfg_defaults(&cfg);
    cfg.ip = (uint32_t)ip;
    cfg.rto_ms = 20;
    cfg.max_retries = 10;
    cfg.mr_quarantine_ms = 50;
    struct uet_engine_wire w = {.tx = wire_tx, .ctx = &d};
    struct uet_engine_dma dma = {.map = mem_map, .ctx = &d};
    d.e = uet_engine_create(&cfg, &w, &dma, err, sizeof(err));
    if (d.e == NULL) {
        fprintf(stderr, "uet_engine_create: %s\n", err);
        return 2;
    }
    static const struct uet_svc_ops ops = {.mr_view = svc_mr_view,
                                           .reply = svc_reply};
    d.svc = uet_svc_create(d.e, &ops, &d);
    if (d.svc == NULL)
        return 2;

    while (!d.bye)
        pump(&d);

    /* Let the engine finish what it owes the peer, then everything must
     * be back: the guest destroyed its QP and every region. */
    for (double end = now_ms() + 300.0; now_ms() < end;)
        pump(&d);

    uet_svc_get_stats(d.svc, &ss);
    uet_engine_get_stats(d.e, &es);
    printf("fake-device: %" PRIu64 " commands, %" PRIu64 " replies, %" PRIu64
           " transfers ok, %" PRIu64 " failed; engine tx %" PRIu64
           " rx %" PRIu64 " frames; left: %u regions %u peers %u ops\n",
           ss.commands, ss.replies, ss.ops_completed, ss.ops_failed,
           es.tx_frames, es.rx_frames, es.mrs + ss.mrs, es.peers + ss.peers,
           es.ops_in_flight + ss.ops_queued + ss.ops_posted);
    fflush(stdout);

    bool clean = ss.mrs == 0 && ss.peers == 0 && ss.ops_queued == 0 &&
                 ss.ops_posted == 0 && es.mrs == 0 && es.peers == 0 &&
                 es.ops_in_flight == 0;
    uet_svc_destroy(d.svc);
    uet_engine_destroy(d.e);
    munmap(d.mem, d.mem_len);
    return clean ? 0 : 1;
}
