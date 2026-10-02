/*
 * uet_wire_dpdk.h -- a DPDK port as the UET engine's wire
 *
 * The TAP gives the engine one write() or read() per frame.  This backend
 * puts the engine on a DPDK ethdev port instead: bursts of frames in each
 * direction, through mbuf pools, polled from the server's main loop (the
 * engine and every access to guest memory stay on that thread).
 *
 * Each offload the backend uses sits behind a capability check, with a
 * software fallback that does the same job, and uet_wire_dpdk_describe()
 * says which path each one took:
 *
 *  - rte_flow: UDP to the UET port and the UET IP protocol, both to the
 *    engine's address, and ARP, steered to the engine's queues, the port
 *    isolated so the rest stays with the kernel.  Fallback: every frame
 *    comes to the engine's filter, which leaves what is not UET to the
 *    guest's Ethernet.
 *  - RSS over the UDP source port, which carries UET's entropy, when there
 *    is more than one queue.  Fallback: one queue.
 *  - Transmit of a frame in pieces (uet_wire_dpdk_tx_iov()): a chain of
 *    mbufs whose payload segments are external buffers in guest memory, so
 *    nothing copies the payload before the port does.  Fallback: one mbuf,
 *    copied.
 *  - Receive buffer split, headers and payload in separate buffers, when
 *    asked for (rx_split): after the UDP header where the port splits by
 *    protocol, after 256 bytes where it splits by length.  The engine
 *    takes a frame in one piece, so a split frame is gathered (copied)
 *    first: this is the hook for an engine that takes them in two.
 *    Fallback: one buffer per frame.
 *  - Placement of received payload in guest memory by a dmadev
 *    (uet_wire_dpdk_dma_copy()).  Fallback: memcpy().  A dmadev on a bus
 *    copies only from memory it can reach (the EAL's, or a mapped guest
 *    region); the reference provider copies each received frame into a
 *    buffer of its own (uet_pds_sec_rx_pkt()) before it places the
 *    payload, so with such a dmadev every placement is a memcpy() until
 *    the provider places from the frame where it lies.
 *  - Receive and transmit timestamps from the port's clock.  Fallback: the
 *    host's clock, read once per burst.
 *  - IPv4 header checksums, filled in on transmit and checked on receive.
 *    Fallback: computed in software.  UET sends a zero UDP checksum and
 *    receivers ignore it (UEC 1.0.1, 3.5.10.1), so there is no UDP
 *    checksum to offload.
 *
 * Guest memory.  A port or a dmadev on a bus (PCI) reaches memory through
 * the IOMMU, by IOVA.  The EAL maps its own memory there, but not the
 * guest's, which the server maps in from vfio-user.  So the server passes
 * each guest DMA region to uet_wire_dpdk_region_add() when vfio-user adds
 * it, and to uet_wire_dpdk_region_remove() before it goes.  For each
 * device that needs it, the backend registers the region with
 * rte_extmem_register() and maps it with rte_dev_dma_map(), IOVA = virtual
 * address; on removal it first waits until the port holds no frame that
 * refers to guest memory, then unmaps and unregisters.  Payload in memory
 * that is not mapped for the port goes out copied; payload placed in
 * memory that is not mapped for the dmadev is copied with memcpy().
 * Virtual devices reach memory by its virtual address and need none of
 * this (rte_dev_dma_map() is a no-op for them).
 *
 * Copyright (C) Advanced Micro Devices, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef UET_WIRE_DPDK_H
#define UET_WIRE_DPDK_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/uio.h>

/* Whether guest memory is DMA-mapped for the port and the dmadev. */
enum uet_wire_dpdk_map {
    UET_WIRE_DPDK_MAP_AUTO = 0, /* for devices on a bus, not for vdevs */
    UET_WIRE_DPDK_MAP_ON,       /* for every device: tests the path */
    UET_WIRE_DPDK_MAP_OFF,      /* never: devices on a bus get copies */
};

struct uet_wire_dpdk_cfg {
    /* The port: a virtual device's devargs ("net_tap0,iface=uet0"), which
     * is probed as a vdev, or a bus address ("0000:c1:00.0"), which is
     * allowed and probed (and then needs hugepages and vfio-pci). */
    const char *dev;
    /* More EAL arguments, separated by spaces, after the backend's own:
     * "-l 0 --no-telemetry", then "--no-huge -m 512 --no-shconf --no-pci"
     * when every device is virtual, else "--in-memory" (hugepages, no
     * files, so two engines can run side by side).  NULL for none. */
    const char *eal;
    /* A dmadev to place received payload with: a vdev ("dma_skeleton") or
     * the name of a device the EAL probes ("0000:6a:01.0").  NULL: none. */
    const char *dma;
    uint16_t queues; /* receive and transmit queue pairs; 0 means 1 */
    uint16_t mtu;    /* IP MTU to configure on the port */
    uint32_t ip;     /* the engine's IPv4 address, host order */
    uint16_t udp_port;
    uint8_t ipproto;
    uint8_t mac[6]; /* the engine's MAC */
    enum uet_wire_dpdk_map map;
    bool rx_split;     /* ask for receive buffer split */
    uint32_t drain_ms; /* region removal waits this long; 0 means 100 */
};

struct uet_wire_dpdk;

/* Starts the EAL (once per process), the port and the dmadev. */
struct uet_wire_dpdk *uet_wire_dpdk_open(const struct uet_wire_dpdk_cfg *cfg,
                                         char *err, size_t errlen);
void uet_wire_dpdk_close(struct uet_wire_dpdk *w);

/* What each offload is doing, one line, for the startup report. */
void uet_wire_dpdk_describe(const struct uet_wire_dpdk *w, char *buf,
                            size_t len);

/* The port's MTU, or 0 when it cannot say. */
uint16_t uet_wire_dpdk_mtu(const struct uet_wire_dpdk *w);

/* True once the port's link is up (a memif peer has connected). */
bool uet_wire_dpdk_link_up(const struct uet_wire_dpdk *w);

/*
 * Queue a frame for transmit; it goes out at the next flush, or when a
 * burst is full.  The IPv4 header checksum of an IPv4 frame is filled in
 * (by the port, or here).  Returns 0, or a negative errno (-ENOBUFS when no
 * mbuf is free).
 */
int uet_wire_dpdk_tx(struct uet_wire_dpdk *w, const void *frame, size_t len);

/*
 * The same for a frame in pieces (see struct uet_engine_wire): iov[0] the
 * headers and iov[n - 1] the trailer, copied; the pieces between attached
 * as external buffers when the port takes multi-segment frames and
 * addresses its buffers by virtual address and the payload is 2 KiB or
 * more, else copied too.
 */
int uet_wire_dpdk_tx_iov(struct uet_wire_dpdk *w, const struct iovec *iov,
                         unsigned n, size_t len);

/* Send what is queued; what the port does not take now waits for the next
 * flush.  A frame queued while the queue is still full is lost. */
void uet_wire_dpdk_flush(struct uet_wire_dpdk *w);

/* True while frames wait for the port. */
bool uet_wire_dpdk_tx_pending(const struct uet_wire_dpdk *w);

/*
 * One received frame.  @data and @len are the frame, contiguous; it stays
 * valid until uet_wire_dpdk_release(@cookie), which whoever keeps the frame
 * must call once.  @csum_ok says its IPv4 header checksum was checked
 * (good) by the port.  @ts_ns is when it was received: with @hw_ts, the
 * port's own timestamp (its clock and its units: the kernel's realtime
 * nanoseconds for af_packet), else CLOCK_MONOTONIC nanoseconds read once
 * per burst.
 */
struct uet_wire_dpdk_frame {
    const uint8_t *data;
    size_t len;
    bool csum_ok;
    bool hw_ts;
    uint64_t ts_ns;
    void *cookie;
};

/*
 * Offer every frame received since the last poll, up to @budget, to @rx.
 * When @rx returns true it has taken the frame and will release it; when
 * it returns false the frame is released here.  Returns how many frames
 * there were.
 */
typedef bool (*uet_wire_dpdk_rx_fn)(void *ctx,
                                    const struct uet_wire_dpdk_frame *f);
unsigned uet_wire_dpdk_poll(struct uet_wire_dpdk *w, uet_wire_dpdk_rx_fn rx,
                            void *ctx, unsigned budget);

void uet_wire_dpdk_release(void *cookie);

/*
 * Copy received payload into guest memory with the dmadev, waiting for it
 * to complete, or with memcpy() when there is none or it fails.  Returns 0.
 */
int uet_wire_dpdk_dma_copy(void *ctx, void *dst, const void *src, size_t len);

/* True when a dmadev is in use, so uet_wire_dpdk_dma_copy() is worth
 * installing. */
bool uet_wire_dpdk_has_dma(const struct uet_wire_dpdk *w);

/*
 * A guest DMA region as vfio-user mapped it into this process: @va and
 * @len, aligned to @page_size, @writable unless the guest mapped it
 * read-only.  Returns 1 when it is now DMA-mapped for every device that
 * needs it, 0 when no device needs it (virtual devices, map=off, IOVA as
 * PA), and a negative errno when a mapping failed, in which case payload
 * in it is copied (for the device whose mapping failed).  @why, if not
 * NULL, says what happened, for the log.
 */
int uet_wire_dpdk_region_add(struct uet_wire_dpdk *w, void *va, size_t len,
                             size_t page_size, bool writable, char *why,
                             size_t whylen);

/*
 * The region at @va (@len bytes) is going away.  First every frame that
 * refers to guest memory, in any region, is sent and given back by the
 * port, waiting up to drain_ms; after that the frames still queued here
 * are dropped and the transmit queue is stopped and started, which makes
 * the port give back the rest.  Then the region is unmapped and
 * unregistered.  Returns false when the port still held such frames after
 * all that (unmapped anyway: the region is going).
 */
bool uet_wire_dpdk_region_remove(struct uet_wire_dpdk *w, void *va, size_t len);

/* Frames attached to guest memory that the port, or the queue here, still
 * holds. */
unsigned uet_wire_dpdk_tx_inflight(const struct uet_wire_dpdk *w);

/*
 * For tests: the device-level map and unmap, in place of rte_dev_dma_map()
 * and rte_dev_dma_unmap() (rte_extmem_register() still runs).  @dev is 0
 * for the port and 1 for the dmadev.  Return 0 or a negative errno.
 */
struct uet_wire_dpdk_map_ops {
    int (*map)(void *ctx, int dev, void *va, size_t len);
    int (*unmap)(void *ctx, int dev, void *va, size_t len);
    void *ctx;
};
void uet_wire_dpdk_set_map_ops(struct uet_wire_dpdk *w,
                               const struct uet_wire_dpdk_map_ops *ops);

struct uet_wire_dpdk_stats {
    uint64_t rx_frames;
    uint64_t rx_multiseg; /* gathered from more than one mbuf */
    uint64_t rx_csum_hw;  /* IPv4 checksum checked by the port */
    uint64_t rx_ts_hw;    /* timestamped by the port */
    uint64_t tx_frames;
    uint64_t tx_extbuf_frames; /* sent with guest memory attached */
    uint64_t tx_copied_frames;
    uint64_t tx_dropped; /* the port would not take them */
    uint64_t tx_nombuf;
    uint64_t dma_copies;
    uint64_t dma_bytes;
    uint64_t dma_fallbacks; /* memcpy() after the dmadev failed */
    uint64_t last_rx_ts_ns;
    uint64_t last_tx_ts_ns;
    /* guest memory */
    uint64_t regions_mapped;     /* added and mapped for some device */
    uint64_t regions_unmapped;   /* added, and mapped for none */
    uint64_t map_failures;       /* regions with a mapping that failed */
    uint64_t tx_copied_unmapped; /* copied: payload not mapped */
    uint64_t dma_unmapped;       /* memcpy(): memory not mapped */
    uint64_t drain_waits;        /* removals that waited for frames */
    uint64_t drain_timeouts;     /* ... and still had some after */
    uint64_t tx_queue_restarts;  /* ... and stopped the queue */
};

void uet_wire_dpdk_get_stats(const struct uet_wire_dpdk *w,
                             struct uet_wire_dpdk_stats *out);

#endif /* UET_WIRE_DPDK_H */
