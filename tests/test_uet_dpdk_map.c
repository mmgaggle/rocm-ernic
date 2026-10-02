/*
 * test_uet_dpdk_map.c -- guest memory DMA mapping in the DPDK wire
 *
 * A port or dmadev on a bus reaches guest memory through the IOMMU, so
 * src/uet_wire_dpdk.c maps each vfio-user DMA region for it, and copies
 * where a mapping is missing (uet_wire_dpdk.h, "Guest memory").  Real
 * devices are not needed to check the bookkeeping around that, which is
 * what this does, in one process, without privileges or hugepages:
 *
 *  - a net_ring port (a loopback: what goes out comes back in, in the same
 *    mbufs) with the skeleton dmadev, map=on, and the device-level map and
 *    unmap replaced by hooks that record each call and fail on request:
 *    region add maps for both devices, payload from a mapped region goes
 *    out attached and from anything else copied, placement into memory
 *    the dmadev has no mapping for is a memcpy(), and region removal sends
 *    the frames still queued before it unmaps (and says so when the port
 *    keeps them);
 *  - a second net_ring port, map=on without hooks: the real
 *    rte_extmem_register() and rte_dev_dma_map() (a no-op on a vdev) on
 *    add, their reverse on removal (the region registers again after);
 *  - a third, map=auto: a vdev needs no mapping, nothing is registered,
 *    and payload goes out attached from anywhere.
 *
 * Copyright (C) Advanced Micro Devices, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <errno.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/uio.h>

#include "uet_wire_dpdk.h"

#define REGION_LEN  (64u * 1024u)
#define NREGIONS    6u
#define HDR_LEN     64u
#define PAYLOAD_LEN 4096u
#define CRC_LEN     4u
#define FRAME_LEN   (HDR_LEN + PAYLOAD_LEN + CRC_LEN)
#define MAX_CALLS   64u

static int failures;

#define CHECK(cond, ...)                                  \
    do {                                                  \
        if (!(cond)) {                                    \
            printf("  FAIL %s:%d: ", __FILE__, __LINE__); \
            printf(__VA_ARGS__);                          \
            printf("\n");                                 \
            failures++;                                   \
        }                                                 \
    } while (0)

/* ------------------------------------------------------------------ */
/* Map hooks                                                          */
/* ------------------------------------------------------------------ */

struct call {
    bool map; /* else unmap */
    int dev;
    void *va;
    size_t len;
    unsigned inflight; /* frames attached to guest memory at the call */
    bool pending;      /* frames queued, not yet given to the port */
};

struct hooks {
    struct uet_wire_dpdk *w;
    struct call calls[MAX_CALLS];
    unsigned ncalls;
    void *fail_va[2][NREGIONS]; /* per device: these fail to map */
};

static void record(struct hooks *h, bool map, int dev, void *va, size_t len)
{
    if (h->ncalls == MAX_CALLS)
        return;
    h->calls[h->ncalls++] = (struct call){
        .map = map,
        .dev = dev,
        .va = va,
        .len = len,
        .inflight = uet_wire_dpdk_tx_inflight(h->w),
        .pending = uet_wire_dpdk_tx_pending(h->w),
    };
}

static int hook_map(void *ctx, int dev, void *va, size_t len)
{
    struct hooks *h = ctx;

    record(h, true, dev, va, len);
    for (unsigned i = 0; i < NREGIONS; i++)
        if (h->fail_va[dev][i] == va)
            return -EIO;
    return 0;
}

static int hook_unmap(void *ctx, int dev, void *va, size_t len)
{
    record(ctx, false, dev, va, len);
    return 0;
}

/* How many calls there were of this kind for this region. */
static unsigned calls(const struct hooks *h, bool map, int dev, void *va)
{
    unsigned n = 0;

    for (unsigned i = 0; i < h->ncalls; i++)
        if (h->calls[i].map == map && h->calls[i].dev == dev &&
            h->calls[i].va == va)
            n++;
    return n;
}

static const struct call *last_unmap(const struct hooks *h, void *va)
{
    for (unsigned i = h->ncalls; i-- > 0;)
        if (!h->calls[i].map && h->calls[i].va == va)
            return &h->calls[i];
    return NULL;
}

/* ------------------------------------------------------------------ */
/* Frames                                                             */
/* ------------------------------------------------------------------ */

static uint8_t hdr[HDR_LEN];
static uint8_t crc[CRC_LEN] = {0xde, 0xad, 0xbe, 0xef};
static uint8_t rx_buf[FRAME_LEN];
static size_t rx_len;
static unsigned rx_count;

static bool rx_cb(void *ctx, const struct uet_wire_dpdk_frame *f)
{
    (void)ctx;
    rx_count++;
    rx_len = f->len;
    if (f->len <= sizeof(rx_buf))
        memcpy(rx_buf, f->data, f->len);
    return false; /* released by the poll */
}

static void fill(uint8_t *p, size_t len, unsigned seed)
{
    for (size_t i = 0; i < len; i++)
        p[i] = (uint8_t)(i * 7u + seed);
}

/* Send a frame whose payload is at @payload, take it back from the
 * loopback and compare.  Returns false if it did not come back intact. */
static bool round_trip(struct uet_wire_dpdk *w, uint8_t *payload, unsigned seed)
{
    struct iovec iov[3] = {
        {.iov_base = hdr, .iov_len = HDR_LEN},
        {.iov_base = payload, .iov_len = PAYLOAD_LEN},
        {.iov_base = crc, .iov_len = CRC_LEN},
    };
    int rc;

    fill(payload, PAYLOAD_LEN, seed);
    rc = uet_wire_dpdk_tx_iov(w, iov, 3, FRAME_LEN);
    if (rc != 0) {
        printf("  tx_iov: %s\n", strerror(-rc));
        return false;
    }
    uet_wire_dpdk_flush(w);
    rx_count = 0;
    rx_len = 0;
    for (int i = 0; i < 100 && rx_count == 0; i++)
        (void)uet_wire_dpdk_poll(w, rx_cb, NULL, 8);
    return rx_count == 1 && rx_len == FRAME_LEN &&
           memcmp(rx_buf, hdr, HDR_LEN) == 0 &&
           memcmp(rx_buf + HDR_LEN, payload, PAYLOAD_LEN) == 0 &&
           memcmp(rx_buf + HDR_LEN + PAYLOAD_LEN, crc, CRC_LEN) == 0;
}

static struct uet_wire_dpdk *open_wire(const char *dev, const char *dma,
                                       const char *eal,
                                       enum uet_wire_dpdk_map map)
{
    struct uet_wire_dpdk_cfg c;
    struct uet_wire_dpdk *w;
    char err[256] = "";
    char desc[1024];

    memset(&c, 0, sizeof(c));
    c.dev = dev;
    c.dma = dma;
    c.eal = eal;
    c.mtu = 9000;
    c.ip = 0xc0a8c865u;
    c.udp_port = 4793;
    c.ipproto = 253;
    c.mac[0] = 0x02;
    c.mac[5] = 0x65;
    c.map = map;
    c.drain_ms = 20;
    w = uet_wire_dpdk_open(&c, err, sizeof(err));
    if (w == NULL) {
        printf("  open %s: %s\n", dev, err);
        return NULL;
    }
    uet_wire_dpdk_describe(w, desc, sizeof(desc));
    printf("  %s\n", desc);
    return w;
}

/* ------------------------------------------------------------------ */
/* Cases                                                              */
/* ------------------------------------------------------------------ */

/* map=on with hooks: the port and the dmadev each map every region. */
static void case_hooks(uint8_t *const r[NREGIONS])
{
    struct uet_wire_dpdk_stats st;
    struct uet_wire_dpdk *w;
    struct hooks *h = calloc(1, sizeof(*h));
    struct uet_wire_dpdk_map_ops ops = {hook_map, hook_unmap, h};
    const struct call *c;
    char why[192];
    uint8_t *heap;
    int rc;

    printf("map=on, net_ring0 + dma_skeleton, hooks\n");
    w = open_wire("net_ring0", "dma_skeleton",
                  "--vdev net_ring1 --vdev "
                  "net_ring2",
                  UET_WIRE_DPDK_MAP_ON);
    CHECK(w != NULL, "open");
    if (w == NULL || h == NULL) {
        free(h);
        return;
    }
    h->w = w;
    uet_wire_dpdk_set_map_ops(w, &ops);
    h->fail_va[0][0] = r[1]; /* r[1]: the port's mapping fails */
    h->fail_va[1][0] = r[2]; /* r[2]: the dmadev's */
    h->fail_va[0][1] = r[3]; /* r[3]: both */
    h->fail_va[1][1] = r[3];

    /* Add: each region is mapped for both devices, as far as it goes. */
    rc = uet_wire_dpdk_region_add(w, r[0], REGION_LEN, 4096, true, why,
                                  sizeof(why));
    printf("  r0: %d %s\n", rc, why);
    CHECK(rc == 1, "r0 mapped (%d)", rc);
    CHECK(calls(h, true, 0, r[0]) == 1 && calls(h, true, 1, r[0]) == 1,
          "r0 mapped once for the port and once for the dmadev");
    rc = uet_wire_dpdk_region_add(w, r[1], REGION_LEN, 4096, true, why,
                                  sizeof(why));
    printf("  r1: %d %s\n", rc, why);
    CHECK(rc == -EIO, "r1: the port's mapping failed (%d)", rc);
    rc = uet_wire_dpdk_region_add(w, r[2], REGION_LEN, 4096, true, why,
                                  sizeof(why));
    printf("  r2: %d %s\n", rc, why);
    CHECK(rc == -EIO, "r2: the dmadev's mapping failed (%d)", rc);
    rc = uet_wire_dpdk_region_add(w, r[3], REGION_LEN, 4096, true, why,
                                  sizeof(why));
    printf("  r3: %d %s\n", rc, why);
    CHECK(rc == -EIO, "r3: both failed (%d)", rc);
    rc = uet_wire_dpdk_region_add(w, r[4], REGION_LEN, 4096, false, why,
                                  sizeof(why));
    printf("  r4: %d %s\n", rc, why);
    CHECK(rc == -EACCES && calls(h, true, 0, r[4]) == 0,
          "r4: read-only, not mapped (%d)", rc);
    rc = uet_wire_dpdk_region_add(w, r[5], REGION_LEN, 4096, true, why,
                                  sizeof(why));
    CHECK(rc == 1, "r5 mapped (%d)", rc);
    uet_wire_dpdk_get_stats(w, &st);
    CHECK(st.regions_mapped == 4 && st.regions_unmapped == 2 &&
              st.map_failures == 4,
          "regions: %" PRIu64 " mapped, %" PRIu64 " not, %" PRIu64
          " failures; want 4, 2, 4",
          st.regions_mapped, st.regions_unmapped, st.map_failures);

    /* Transmit: attached from r0 and r2 (mapped for the port), copied
     * from r1, r3, r4 and the heap. */
    struct {
        uint8_t *p;
        bool attached;
        const char *what;
    } tx[] = {
        {r[0], true, "r0"},  {r[2], true, "r2"},  {r[1], false, "r1"},
        {r[3], false, "r3"}, {r[4], false, "r4"}, {NULL, false, "heap"},
    };
    heap = malloc(PAYLOAD_LEN);
    tx[5].p = heap;
    for (unsigned i = 0; i < sizeof(tx) / sizeof(tx[0]) && heap != NULL; i++) {
        struct uet_wire_dpdk_stats a, b;

        uet_wire_dpdk_get_stats(w, &a);
        CHECK(round_trip(w, tx[i].p, i), "%s: frame came back intact",
              tx[i].what);
        uet_wire_dpdk_get_stats(w, &b);
        CHECK(b.tx_extbuf_frames - a.tx_extbuf_frames ==
                  (tx[i].attached ? 1u : 0u),
              "%s: %s", tx[i].what,
              tx[i].attached ? "attached" : "not attached");
        CHECK(b.tx_copied_unmapped - a.tx_copied_unmapped ==
                  (tx[i].attached ? 0u : 1u),
              "%s: %s", tx[i].what,
              tx[i].attached ? "not copied" : "copied as not mapped");
        CHECK(uet_wire_dpdk_tx_inflight(w) == 0,
              "%s: nothing attached after the frame came back", tx[i].what);
    }

    /* Placement: the dmadev into r0, r1 and r5 (mapped for it), memcpy()
     * into r2, r3 and the heap.  The source is in r0 (mapped for it). */
    struct {
        uint8_t *dst;
        bool dma;
        const char *what;
    } place[] = {
        {r[1], true, "r1"},  {r[5], true, "r5"},    {r[2], false, "r2"},
        {r[3], false, "r3"}, {heap, false, "heap"},
    };
    fill(r[0], 1024, 99);
    for (unsigned i = 0; i < sizeof(place) / sizeof(place[0]) && heap != NULL;
         i++) {
        struct uet_wire_dpdk_stats a, b;

        memset(place[i].dst + 512, 0, 1024);
        uet_wire_dpdk_get_stats(w, &a);
        (void)uet_wire_dpdk_dma_copy(w, place[i].dst + 512, r[0], 1024);
        uet_wire_dpdk_get_stats(w, &b);
        CHECK(memcmp(place[i].dst + 512, r[0], 1024) == 0, "%s: placed",
              place[i].what);
        CHECK(b.dma_copies + b.dma_fallbacks -
                      (a.dma_copies + a.dma_fallbacks) ==
                  (place[i].dma ? 1u : 0u),
              "%s: %s", place[i].what,
              place[i].dma ? "by the dmadev" : "not by the dmadev");
        CHECK(b.dma_unmapped - a.dma_unmapped == (place[i].dma ? 0u : 1u),
              "%s: %s", place[i].what,
              place[i].dma ? "mapped" : "memcpy() as not mapped");
    }
    /* A source the dmadev cannot reach (the heap): memcpy() too. */
    {
        struct uet_wire_dpdk_stats a, b;

        uet_wire_dpdk_get_stats(w, &a);
        (void)uet_wire_dpdk_dma_copy(w, r[5], heap, 256);
        uet_wire_dpdk_get_stats(w, &b);
        CHECK(b.dma_unmapped - a.dma_unmapped == 1,
              "heap source: memcpy() as not mapped");
    }

    /* Removal while a frame attached to r0 is still queued here: it is
     * given to the port before r0 is unmapped.  The ring keeps it until it
     * is received, so the drain runs out of time and says so. */
    {
        struct iovec iov[3] = {
            {.iov_base = hdr, .iov_len = HDR_LEN},
            {.iov_base = r[0], .iov_len = PAYLOAD_LEN},
            {.iov_base = crc, .iov_len = CRC_LEN},
        };
        struct uet_wire_dpdk_stats a, b;
        bool drained;

        CHECK(uet_wire_dpdk_tx_iov(w, iov, 3, FRAME_LEN) == 0, "queued");
        CHECK(uet_wire_dpdk_tx_pending(w) && uet_wire_dpdk_tx_inflight(w) == 1,
              "one attached frame queued here");
        uet_wire_dpdk_get_stats(w, &a);
        drained = uet_wire_dpdk_region_remove(w, r[0], REGION_LEN);
        uet_wire_dpdk_get_stats(w, &b);
        c = last_unmap(h, r[0]);
        CHECK(!drained, "the ring still holds it: not drained");
        CHECK(b.drain_waits - a.drain_waits == 1 &&
                  b.drain_timeouts - a.drain_timeouts == 1,
              "waited and timed out");
        CHECK(calls(h, false, 0, r[0]) == 1 && calls(h, false, 1, r[0]) == 1,
              "r0 unmapped for both devices");
        CHECK(c != NULL && !c->pending,
              "the queue here was flushed before the unmap");
        rx_count = 0;
        for (int i = 0; i < 100 && rx_count == 0; i++)
            (void)uet_wire_dpdk_poll(w, rx_cb, NULL, 8);
        CHECK(rx_count == 1 && uet_wire_dpdk_tx_inflight(w) == 0,
              "received after all, and given back");
    }

    /* Removal with nothing in flight: no wait, unmapped, and payload in
     * the old range is copied from then on. */
    {
        struct uet_wire_dpdk_stats a, b;

        uet_wire_dpdk_get_stats(w, &a);
        CHECK(uet_wire_dpdk_region_remove(w, r[2], REGION_LEN), "r2 drained");
        uet_wire_dpdk_get_stats(w, &b);
        CHECK(b.drain_waits == a.drain_waits, "r2: no wait");
        CHECK(calls(h, false, 0, r[2]) == 1 && calls(h, false, 1, r[2]) == 0,
              "r2 unmapped for the port only (the dmadev never had it)");
        CHECK(round_trip(w, r[2], 7), "r2 after removal: intact");
        uet_wire_dpdk_get_stats(w, &b);
        CHECK(b.tx_copied_unmapped - a.tx_copied_unmapped == 1,
              "r2 after removal: copied");
        /* A region never mapped: nothing to unmap. */
        CHECK(uet_wire_dpdk_region_remove(w, r[3], REGION_LEN), "r3");
        CHECK(calls(h, false, 0, r[3]) == 0 && calls(h, false, 1, r[3]) == 0,
              "r3: nothing unmapped");
    }

    /* Close with r1 and r5 still there: unmapped on the way out. */
    uet_wire_dpdk_close(w);
    CHECK(calls(h, false, 1, r[1]) == 1 && calls(h, false, 0, r[1]) == 0,
          "close: r1 unmapped for the dmadev");
    CHECK(calls(h, false, 0, r[5]) == 1 && calls(h, false, 1, r[5]) == 1,
          "close: r5 unmapped for both");
    free(heap);
    free(h);
}

/* map=on without hooks: the real EAL calls, a no-op mapping on a vdev. */
static void case_real(uint8_t *const r[NREGIONS])
{
    struct uet_wire_dpdk_stats st;
    struct uet_wire_dpdk *w;
    char why[192];
    int rc;

    printf("map=on, net_ring1, rte_extmem_register + rte_dev_dma_map\n");
    w = open_wire("net_ring1", NULL, NULL, UET_WIRE_DPDK_MAP_ON);
    CHECK(w != NULL, "open");
    if (w == NULL)
        return;
    rc = uet_wire_dpdk_region_add(w, r[0], REGION_LEN, 4096, true, why,
                                  sizeof(why));
    printf("  r0: %d %s\n", rc, why);
    CHECK(rc == 1, "r0 registered and mapped (%d)", rc);
    /* A second registration of the same memory fails in the EAL. */
    rc = uet_wire_dpdk_region_add(w, r[0], REGION_LEN, 4096, true, why,
                                  sizeof(why));
    printf("  r0 again: %d %s\n", rc, why);
    CHECK(rc < 0, "r0 twice: refused (%d)", rc);
    CHECK(round_trip(w, r[0], 3), "r0: intact");
    CHECK(round_trip(w, r[1], 4), "r1 (not added): intact");
    uet_wire_dpdk_get_stats(w, &st);
    CHECK(st.tx_extbuf_frames == 1 && st.tx_copied_unmapped == 1,
          "r0 attached, r1 copied (%" PRIu64 ", %" PRIu64 ")",
          st.tx_extbuf_frames, st.tx_copied_unmapped);
    CHECK(uet_wire_dpdk_region_remove(w, r[0], REGION_LEN), "r0 removed");
    rc = uet_wire_dpdk_region_add(w, r[0], REGION_LEN, 4096, true, why,
                                  sizeof(why));
    CHECK(rc == 1, "r0 registers again after removal (%d)", rc);
    uet_wire_dpdk_close(w);
}

/* map=auto: a vdev reaches memory by its address; nothing is mapped. */
static void case_auto(uint8_t *const r[NREGIONS])
{
    struct uet_wire_dpdk_stats st;
    struct uet_wire_dpdk *w;
    uint8_t *heap = malloc(PAYLOAD_LEN);
    char why[192];
    int rc;

    printf("map=auto, net_ring2\n");
    w = open_wire("net_ring2", NULL, NULL, UET_WIRE_DPDK_MAP_AUTO);
    CHECK(w != NULL && heap != NULL, "open");
    if (w == NULL || heap == NULL) {
        free(heap);
        return;
    }
    rc = uet_wire_dpdk_region_add(w, r[0], REGION_LEN, 4096, true, why,
                                  sizeof(why));
    printf("  r0: %d %s\n", rc, why);
    CHECK(rc == 0, "r0: no device needs it mapped (%d)", rc);
    CHECK(round_trip(w, r[0], 5), "r0: intact");
    CHECK(round_trip(w, heap, 6), "heap: intact");
    uet_wire_dpdk_get_stats(w, &st);
    CHECK(st.tx_extbuf_frames == 2 && st.tx_copied_unmapped == 0,
          "both attached (%" PRIu64 ", %" PRIu64 ")", st.tx_extbuf_frames,
          st.tx_copied_unmapped);
    CHECK(uet_wire_dpdk_region_remove(w, r[0], REGION_LEN), "r0 removed");
    uet_wire_dpdk_close(w);
    free(heap);
}

int main(void)
{
    uint8_t *r[NREGIONS];
    uint8_t *mem;

    setvbuf(stdout, NULL, _IOLBF, 0);
    /* Page-aligned regions, as vfio-user maps them. */
    mem = mmap(NULL, (size_t)REGION_LEN * NREGIONS, PROT_READ | PROT_WRITE,
               MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mem == MAP_FAILED) {
        perror("mmap");
        return 1;
    }
    for (unsigned i = 0; i < NREGIONS; i++)
        r[i] = mem + (size_t)i * REGION_LEN;
    /* Not IPv4 (an experimental ethertype): nothing fills in a checksum. */
    memset(hdr, 0xa5, sizeof(hdr));
    hdr[12] = 0x88;
    hdr[13] = 0xb5;

    case_hooks(r);
    case_real(r);
    case_auto(r);

    munmap(mem, (size_t)REGION_LEN * NREGIONS);
    if (failures != 0) {
        printf("FAIL: %d checks\n", failures);
        return 1;
    }
    printf("PASS\n");
    return 0;
}
