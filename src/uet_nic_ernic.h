/*
 * uet_nic_ernic.h -- the UET engine's port on the emulated wire
 *
 * The UEC reference provider reaches the network through a "NIC shim": a
 * table of callbacks that move whole Ethernet frames. Its built-in shims
 * open a raw socket or an AF_XDP socket on a kernel netdev. Neither fits a
 * device model, which owns its wire (the TAP behind the emulated LIF) and
 * must keep every packet on the thread that services the guest.
 *
 * This shim is that port. Frames the provider transmits go to a callback
 * the owner supplies; frames the owner takes off the wire are offered to
 * uet_nic_ernic_rx_frame(), which keeps the ones addressed to the engine and
 * queues them until the provider polls for them. It also answers ARP for the
 * engine's address and resolves next hops by ARP without ever blocking,
 * which is what the provider's own resolver (popen of "ip route", system()
 * of "ping", SIOCGARP) cannot do.
 *
 * Everything here runs on one thread. Nothing is locked.
 *
 * Copyright (C) Advanced Micro Devices, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef UET_NIC_ERNIC_H
#define UET_NIC_ERNIC_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/uio.h>

/* Name the shim registers under, and the value of UET_NIC_SHIM for it. */
#define UET_NIC_ERNIC_NAME "ernic"

/* What a configuration of 0 means for the two encapsulations (UEC 1.0.1,
 * 3.2.5): UDP to port 4793, or IP protocol 253. */
#define UET_NIC_ERNIC_UDP_PORT 4793
#define UET_NIC_ERNIC_IPPROTO  253

struct uet_nic_ernic;

/*
 * Put one Ethernet frame on the wire.  Returns 0 or a negative errno.  A
 * frame the wire cannot take right now (a full TAP queue) is dropped rather
 * than retried: the provider's reliability layer recovers it, as it would a
 * loss anywhere else on the path.
 */
typedef int (*uet_nic_ernic_tx_fn)(void *ctx, const void *frame, size_t len);

/* The same for a frame in pieces (see struct uet_engine_wire); NULL when
 * the wire takes flat frames only. */
typedef int (*uet_nic_ernic_tx_iov_fn)(void *ctx, const struct iovec *iov,
                                       unsigned n, size_t len);

struct uet_nic_ernic_cfg {
    uint32_t ip;            /* the engine's IPv4 address, host order */
    uint8_t mac[6];         /* the engine's MAC address */
    uint16_t mtu;           /* IP MTU of the wire */
    uint16_t udp_port;      /* UET over UDP: destination port, 0: 4793 */
    uint8_t ipproto;        /* UET over IP: protocol, 0: 253 */
    const char *name;       /* interface name the provider reports */
    uet_nic_ernic_tx_fn tx; /* where transmitted frames go */
    uet_nic_ernic_tx_iov_fn tx_iov;
    void *tx_ctx;
    bool tx_ipv4_csum; /* the wire fills in IPv4 header checksums */
};

struct uet_nic_ernic_stats {
    uint64_t rx_frames;         /* UET frames queued for the provider */
    uint64_t rx_frames_ext;     /* of which left in the wire's buffer */
    uint64_t rx_dropped;        /* UET frames dropped: queue full or too big */
    uint64_t tx_frames;         /* frames the provider transmitted */
    uint64_t tx_frames_iov;     /* of which in pieces, payload in place */
    uint64_t tx_dropped;        /* frames the wire would not take */
    uint64_t arp_requests;      /* ARP requests sent to resolve a next hop */
    uint64_t arp_replies;       /* ARP replies sent for the engine's address */
    uint64_t arp_learned;       /* neighbors learned or refreshed from ARP */
    uint64_t nh_pending;        /* resolutions answered with -EAGAIN */
    uint64_t icmp_echo_replies; /* pings to the engine answered */
    uint64_t icmp_limited;      /* echo requests over the rate, unanswered */
    uint64_t icmp_dropped;      /* other or malformed ICMP to the engine */
    uint64_t tx_loopback;       /* of tx_frames, to the engine itself: never on
                                 * the wire */
    uint64_t loop_flushed;      /* looped frames dropped by an abort */
};

/*
 * Create the shim.  It is not visible to the provider until
 * uet_nic_ernic_register() is called.  Returns NULL on a bad configuration
 * or when out of memory.
 */
struct uet_nic_ernic *uet_nic_ernic_create(const struct uet_nic_ernic_cfg *cfg);
void uet_nic_ernic_destroy(struct uet_nic_ernic *n);

/*
 * Make this shim the provider's NIC shim.  Must be called before
 * uet_initialize().  The provider holds one external shim per process, so
 * only one instance can be registered at a time.  Returns 0 or a negative
 * errno.
 */
int uet_nic_ernic_register(struct uet_nic_ernic *n);
void uet_nic_ernic_unregister(void);

/*
 * Wire-side receive filter.  Offer it every frame taken off the wire.  It
 * returns true when the frame belonged to the engine and has been consumed:
 * a UET frame addressed to the engine's IP and MAC, in either form (UDP to
 * the UET port, or the UET IP protocol), or an ARP packet whose target is
 * the engine's IP.  Everything else, including ARP for other addresses
 * (which is only looked at to refresh neighbors the engine already knows),
 * is left for the guest.
 */
bool uet_nic_ernic_rx_frame(struct uet_nic_ernic *n, const void *frame,
                            size_t len);

/*
 * The same for a frame left in the wire's buffer: when it returns true the
 * shim owns the buffer and calls @release(@cookie) once it is done with it
 * (at once, for ARP or a frame it drops), so the frame is copied once, into
 * the provider's buffer, instead of twice.  @csum_ok says the wire checked
 * the IPv4 header checksum, which the filter then does not.  When it
 * returns false the caller keeps the buffer.
 */
bool uet_nic_ernic_rx_frame_ext(struct uet_nic_ernic *n, const void *frame,
                                size_t len, bool csum_ok,
                                void (*release)(void *cookie), void *cookie);

/* True while received frames are waiting for the provider to poll them. */
bool uet_nic_ernic_rx_pending(const struct uet_nic_ernic *n);

/*
 * Drop every frame the engine has sent itself and not read yet.  To the
 * transports that is loss on the wire, which they recover from; it is how
 * a transfer taken back stops landing through the loopback.
 */
void uet_nic_ernic_loop_flush(struct uet_nic_ernic *n);

/*
 * Resend ARP for next hops that have not answered yet, and give up on ones
 * that never will.  @now_ms is a monotonic millisecond clock.
 */
void uet_nic_ernic_tick(struct uet_nic_ernic *n, uint64_t now_ms);

void uet_nic_ernic_get_stats(const struct uet_nic_ernic *n,
                             struct uet_nic_ernic_stats *out);

#endif /* UET_NIC_ERNIC_H */
