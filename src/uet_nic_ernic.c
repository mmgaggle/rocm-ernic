/*
 * uet_nic_ernic.c -- the UET engine's port on the emulated wire
 *
 * See uet_nic_ernic.h for what this is and why it exists.
 *
 * The provider calls in through the struct uet_nic callbacks below; the
 * owner calls in through the uet_nic_ernic_*() functions.  Both happen on
 * the thread that services the guest, so the receive queue and the neighbor
 * table are plain data.
 *
 * Copyright (C) Advanced Micro Devices, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>

/* The provider's NIC shim interface and packet layouts. */
#include "uet_nic.h"
#include "uet_pkt_hdr.h"

#include "uet_nic_ernic.h"

#define ETH_HLEN_          14u
#define ETHERTYPE_IPV4_    0x0800u
#define ETHERTYPE_ARP_     0x0806u
#define ETH_MIN_FRAME      60u /* without the FCS */
#define IPV4_MIN_HLEN      20u
#define UDP_HLEN           8u
#define IPPROTO_UDP_       17u
#define ARP_LEN            28u
#define ARP_OP_REQUEST_    1u
#define ARP_OP_REPLY_      2u
#define ARP_HTYPE_ETHERNET 1u

/* Frames received but not yet polled by the provider. */
#define RX_SLOTS 256u

/* Next-hop resolution. */
#define NEIGH_MAX        32u
#define ARP_RETRY_MS     250u    /* resend an unanswered request after this */
#define ARP_MAX_TRIES    4u      /* then report the next hop unreachable */
#define ARP_FAIL_HOLD_MS 1000u   /* for this long before trying again */
#define ARP_REFRESH_MS   300000u /* re-confirm a known neighbor this often */

enum neigh_state {
    NEIGH_FREE = 0,
    NEIGH_INCOMPLETE, /* request sent, no answer yet */
    NEIGH_REACHABLE,  /* MAC known */
    NEIGH_FAILED,     /* never answered; held down for ARP_FAIL_HOLD_MS */
};

struct neigh {
    uint32_t ip; /* host order */
    uint8_t mac[6];
    enum neigh_state state;
    unsigned tries;
    uint64_t last_req_ms;  /* last request sent, or when it failed */
    uint64_t confirmed_ms; /* last time the neighbor's MAC was seen */
    uint64_t last_used_ms; /* for eviction */
};

struct rx_slot {
    size_t len;
    uint8_t *data;      /* the slot's own copy */
    const uint8_t *ext; /* or the wire's buffer, released once read */
    void (*release)(void *cookie);
    void *cookie;
};

struct uet_nic_ernic {
    uint32_t ip;
    uint8_t mac[6];
    uint16_t mtu;
    uint16_t udp_port;
    uint8_t ipproto;
    char name[IFNAMSIZ];
    uet_nic_ernic_tx_fn tx;
    uet_nic_ernic_tx_iov_fn tx_iov;
    void *tx_ctx;
    bool tx_ipv4_csum;

    size_t slot_size; /* largest frame the queue holds */
    uint8_t *slot_mem;
    struct rx_slot slots[RX_SLOTS];
    unsigned rx_head; /* next slot the provider reads */
    unsigned rx_count;

    struct neigh neigh[NEIGH_MAX];

    struct uet_nic_ernic_stats stats;
};

/* ------------------------------------------------------------------ */
/* Helpers                                                            */
/* ------------------------------------------------------------------ */

static uint64_t now_ms(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

static uint16_t rd16(const uint8_t *p)
{
    return (uint16_t)(((unsigned)p[0] << 8) | p[1]);
}

static uint32_t rd32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | p[3];
}

static void wr16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)v;
}

static void wr32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

/* RFC 1071: the ones' complement sum over a valid header is all ones. */
static bool ipv4_csum_ok(const uint8_t *ip, size_t ihl)
{
    uint32_t sum = 0;

    for (size_t i = 0; i + 1 < ihl; i += 2)
        sum += rd16(ip + i);
    while (sum >> 16)
        sum = (sum & 0xffffu) + (sum >> 16);
    return sum == 0xffffu;
}

static void format_mac(char *out, const uint8_t mac[6])
{
    static const char hex[] = "0123456789abcdef";

    for (unsigned i = 0; i < 6; i++) {
        out[i * 3] = hex[mac[i] >> 4];
        out[i * 3 + 1] = hex[mac[i] & 0xfu];
        out[i * 3 + 2] = (i == 5) ? '\0' : ':';
    }
}

/* ------------------------------------------------------------------ */
/* ARP                                                                */
/* ------------------------------------------------------------------ */

static void send_arp(struct uet_nic_ernic *n, uint16_t op,
                     const uint8_t dst_mac[6], uint32_t dst_ip)
{
    /* Padded to the Ethernet minimum; the padding goes on the wire, so it
     * starts out cleared like the rest of the frame. */
    uint8_t f[ETH_MIN_FRAME];
    static const uint8_t bcast[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    uint8_t *a = f + ETH_HLEN_;

    memset(f, 0, sizeof(f));
    memcpy(f, op == ARP_OP_REQUEST_ ? bcast : dst_mac, 6);
    memcpy(f + 6, n->mac, 6);
    wr16(f + 12, ETHERTYPE_ARP_);

    wr16(a, ARP_HTYPE_ETHERNET);
    wr16(a + 2, ETHERTYPE_IPV4_);
    a[4] = 6;
    a[5] = 4;
    wr16(a + 6, op);
    memcpy(a + 8, n->mac, 6);
    wr32(a + 14, n->ip);
    if (op == ARP_OP_REPLY_)
        memcpy(a + 18, dst_mac, 6);
    wr32(a + 24, dst_ip);

    if (n->tx(n->tx_ctx, f, sizeof(f)) == 0) {
        if (op == ARP_OP_REQUEST_)
            n->stats.arp_requests++;
        else
            n->stats.arp_replies++;
    }
}

static struct neigh *neigh_find(struct uet_nic_ernic *n, uint32_t ip)
{
    for (unsigned i = 0; i < NEIGH_MAX; i++) {
        if (n->neigh[i].state != NEIGH_FREE && n->neigh[i].ip == ip)
            return &n->neigh[i];
    }
    return NULL;
}

/* A free entry, else the one used longest ago. */
static struct neigh *neigh_alloc(struct uet_nic_ernic *n, uint32_t ip)
{
    struct neigh *victim = &n->neigh[0];

    for (unsigned i = 0; i < NEIGH_MAX; i++) {
        if (n->neigh[i].state == NEIGH_FREE) {
            victim = &n->neigh[i];
            break;
        }
        if (n->neigh[i].last_used_ms < victim->last_used_ms)
            victim = &n->neigh[i];
    }

    memset(victim, 0, sizeof(*victim));
    victim->ip = ip;
    victim->state = NEIGH_INCOMPLETE;
    victim->last_used_ms = now_ms();
    return victim;
}

/*
 * Record what an ARP packet says about its sender.  Only an exchange with
 * the engine itself may add an entry; any other ARP on the segment just
 * refreshes a neighbor the engine already talks to, so a busy segment cannot
 * flush the table.
 */
static void neigh_learn(struct uet_nic_ernic *n, uint32_t ip,
                        const uint8_t mac[6], bool may_create)
{
    struct neigh *e = neigh_find(n, ip);

    if (e == NULL) {
        if (!may_create)
            return;
        e = neigh_alloc(n, ip);
    }

    memcpy(e->mac, mac, 6);
    e->state = NEIGH_REACHABLE;
    e->tries = 0;
    e->confirmed_ms = now_ms();
    n->stats.arp_learned++;
}

static bool handle_arp(struct uet_nic_ernic *n, const uint8_t *f, size_t len)
{
    if (len < ETH_HLEN_ + ARP_LEN)
        return false;

    const uint8_t *a = f + ETH_HLEN_;
    if (rd16(a) != ARP_HTYPE_ETHERNET || rd16(a + 2) != ETHERTYPE_IPV4_ ||
        a[4] != 6 || a[5] != 4)
        return false;

    uint16_t op = rd16(a + 6);
    const uint8_t *sha = a + 8;
    uint32_t spa = rd32(a + 14);
    uint32_t tpa = rd32(a + 24);
    bool for_us = (tpa == n->ip);

    /* 0.0.0.0 is an address probe; it says nothing about a neighbor. */
    if (spa != 0 && spa != n->ip)
        neigh_learn(n, spa, sha, for_us);

    if (!for_us)
        return false;

    if (op == ARP_OP_REQUEST_ && spa != 0)
        send_arp(n, ARP_OP_REPLY_, sha, spa);

    return true;
}

/* ------------------------------------------------------------------ */
/* The provider's side: struct uet_nic callbacks                      */
/* ------------------------------------------------------------------ */

static struct uet_nic_ernic *shim_of(struct uet_nic *nic)
{
    return (struct uet_nic_ernic *)nic->shim_ctx;
}

static int shim_initialize(struct uet_nic *nic)
{
    struct uet_nic_ernic *n = shim_of(nic);
    struct in_addr in;

    if (n == NULL)
        return -ENODEV;

    memcpy(nic->ifname, n->name, sizeof(nic->ifname));
    memset(nic->network_type, 0, sizeof(nic->network_type));
    memcpy(nic->network_type, "Ethernet(ernic)", sizeof("Ethernet(ernic)"));

    memcpy(nic->mac_addr, n->mac, sizeof(nic->mac_addr));
    format_mac(nic->mac_addr_str, n->mac);

    nic->ipv4_addr = n->ip;
    in.s_addr = htonl(n->ip);
    if (inet_ntop(AF_INET, &in, nic->ipv4_addr_str,
                  sizeof(nic->ipv4_addr_str)) == NULL)
        return -EINVAL;
    nic->has_ipv4 = true;
    nic->has_ipv6 = false;

    nic->mtu = n->mtu;
    nic->l2_hdr_size = ETH_HLEN_;
    nic->min_pkt_size = UET_MIN_PKT_SIZE;
    nic->min_ip_pkt_size = nic->min_pkt_size - nic->l2_hdr_size;
    nic->max_pkt_size = (size_t)n->mtu + ETH_HLEN_;
    nic->sock_fd = -1;

    /* The wire may fill in IPv4 header checksums; and the filter checks
     * them on every frame it queues, so the provider need not. */
    nic->tx_ipv4_csum = n->tx_ipv4_csum;
    nic->rx_ipv4_csum = true;

    return 0;
}

static void shim_finalize(struct uet_nic *nic)
{
    /* The owner holds the state and frees it in uet_nic_ernic_destroy(). */
    nic->shim_ctx = NULL;
}

static int shim_getinfo(struct uet_nic *nic, struct uet_nic_info *info)
{
    info->ifname = nic->ifname;
    info->network_type = nic->network_type;
    info->mac_addr_str = nic->mac_addr_str;
    info->mtu = nic->mtu;
    info->link_state = UET_NIC_LINK_STATE_UP;
    return 0;
}

static int shim_tx_pkt(struct uet_nic *nic, void *pkt, void *iphdr,
                       size_t pkt_size)
{
    struct uet_nic_ernic *n = shim_of(nic);

    (void)iphdr;
    if (n == NULL)
        return -ENODEV;

    if (pkt_size > (size_t)n->mtu + ETH_HLEN_) {
        n->stats.tx_dropped++;
        return -EMSGSIZE;
    }

    int rc = n->tx(n->tx_ctx, pkt, pkt_size);
    if (rc < 0) {
        n->stats.tx_dropped++;
        /* A congested wire loses the frame, which PDS recovers.  Anything
         * else is a broken wire and the provider should hear about it. */
        return (rc == -EAGAIN || rc == -ENOBUFS) ? 0 : rc;
    }

    n->stats.tx_frames++;
    return 0;
}

static int shim_tx_pkt_iov(struct uet_nic *nic, const struct iovec *iov,
                           int iovcnt, size_t pkt_size)
{
    struct uet_nic_ernic *n = shim_of(nic);

    if (n == NULL)
        return -ENODEV;
    if (n->tx_iov == NULL || iovcnt < 2)
        return -ENOTSUP;

    if (pkt_size > (size_t)n->mtu + ETH_HLEN_) {
        n->stats.tx_dropped++;
        return -EMSGSIZE;
    }

    int rc = n->tx_iov(n->tx_ctx, iov, (unsigned)iovcnt, pkt_size);
    if (rc == -ENOTSUP)
        return rc;
    if (rc < 0) {
        n->stats.tx_dropped++;
        return (rc == -EAGAIN || rc == -ENOBUFS) ? 0 : rc;
    }

    n->stats.tx_frames++;
    n->stats.tx_frames_iov++;
    return 0;
}

static int shim_rx_poll(struct uet_nic *nic)
{
    struct uet_nic_ernic *n = shim_of(nic);

    return (n != NULL && n->rx_count > 0) ? 1 : 0;
}

/* Give a wire's buffer back once the frame in it has been read. */
static void slot_release(struct rx_slot *s)
{
    if (s->ext != NULL && s->release != NULL)
        s->release(s->cookie);
    s->ext = NULL;
    s->release = NULL;
    s->cookie = NULL;
}

static int shim_rx_pkt(struct uet_nic *nic, void *pkt, size_t pkt_buf_size,
                       size_t *rx_pkt_size)
{
    struct uet_nic_ernic *n = shim_of(nic);

    if (n == NULL || n->rx_count == 0)
        return 0;

    struct rx_slot *s = &n->slots[n->rx_head];
    n->rx_head = (n->rx_head + 1) % RX_SLOTS;
    n->rx_count--;

    /* The provider sizes its buffer from max_pkt_size, which bounds what
     * was queued, so this only trips if it ever stops doing that. */
    if (s->len > pkt_buf_size || s->len < nic->min_pkt_size) {
        n->stats.rx_dropped++;
        slot_release(s);
        return 0;
    }

    memcpy(pkt, s->ext != NULL ? s->ext : s->data, s->len);
    *rx_pkt_size = s->len;
    slot_release(s);
    return 1;
}

/*
 * Non-blocking next-hop resolution.  The engine's peers share its Ethernet
 * segment, so the next hop for a destination is the destination itself.
 */
static int shim_resolve_nh(struct uet_nic *nic, const struct uet_fa *fa,
                           bool is_ipv6, uint8_t *mac)
{
    struct uet_nic_ernic *n = shim_of(nic);
    static const uint8_t none[6] = {0};

    if (n == NULL)
        return -ENODEV;
    if (is_ipv6)
        return -EAFNOSUPPORT;
    if (fa->v4 == n->ip || fa->v4 == 0)
        return -EHOSTUNREACH;

    uint64_t now = now_ms();
    struct neigh *e = neigh_find(n, fa->v4);
    if (e == NULL)
        e = neigh_alloc(n, fa->v4);
    e->last_used_ms = now;

    switch (e->state) {
    case NEIGH_REACHABLE:
        memcpy(mac, e->mac, 6);
        /* Keep using the MAC while asking again, so a long-lived peer
         * that moved is noticed without stalling traffic to one that did
         * not. */
        if (now - e->confirmed_ms >= ARP_REFRESH_MS &&
            now - e->last_req_ms >= ARP_RETRY_MS) {
            e->last_req_ms = now;
            send_arp(n, ARP_OP_REQUEST_, none, e->ip);
        }
        return 0;
    case NEIGH_FAILED:
        if (now - e->last_req_ms < ARP_FAIL_HOLD_MS)
            return -EHOSTUNREACH;
        e->state = NEIGH_INCOMPLETE;
        e->tries = 0;
        break;
    case NEIGH_INCOMPLETE:
    case NEIGH_FREE:
    default:
        break;
    }

    if (e->tries == 0 || now - e->last_req_ms >= ARP_RETRY_MS) {
        e->tries++;
        e->last_req_ms = now;
        send_arp(n, ARP_OP_REQUEST_, none, e->ip);
    }
    n->stats.nh_pending++;
    return -EAGAIN;
}

static const struct uet_nic_shim_ops shim_ops = {
    .name = UET_NIC_ERNIC_NAME,
    .nic_initialize = shim_initialize,
    .nic_finalize = shim_finalize,
    .nic_getinfo = shim_getinfo,
    .nic_tx_pkt = shim_tx_pkt,
    .nic_rx_pkt = shim_rx_pkt,
    .nic_rx_poll = shim_rx_poll,
    .nic_resolve_nh = shim_resolve_nh,
    .nic_tx_pkt_iov = shim_tx_pkt_iov,
};

/* ------------------------------------------------------------------ */
/* The owner's side                                                   */
/* ------------------------------------------------------------------ */

struct uet_nic_ernic *uet_nic_ernic_create(const struct uet_nic_ernic_cfg *cfg)
{
    if (cfg == NULL || cfg->tx == NULL || cfg->ip == 0 || cfg->mtu < 576)
        return NULL;

    struct uet_nic_ernic *n = calloc(1, sizeof(*n));
    if (n == NULL)
        return NULL;

    n->ip = cfg->ip;
    memcpy(n->mac, cfg->mac, 6);
    n->mtu = cfg->mtu;
    n->udp_port = cfg->udp_port != 0 ? cfg->udp_port : UET_NIC_ERNIC_UDP_PORT;
    n->ipproto = cfg->ipproto != 0 ? cfg->ipproto : UET_NIC_ERNIC_IPPROTO;
    snprintf(n->name, sizeof(n->name), "%s",
             cfg->name != NULL ? cfg->name : "ernic-uet");
    n->tx = cfg->tx;
    n->tx_iov = cfg->tx_iov;
    n->tx_ctx = cfg->tx_ctx;
    n->tx_ipv4_csum = cfg->tx_ipv4_csum;

    n->slot_size = (size_t)cfg->mtu + ETH_HLEN_;
    n->slot_mem = calloc(RX_SLOTS, n->slot_size);
    if (n->slot_mem == NULL) {
        free(n);
        return NULL;
    }
    for (unsigned i = 0; i < RX_SLOTS; i++)
        n->slots[i].data = n->slot_mem + (size_t)i * n->slot_size;

    return n;
}

void uet_nic_ernic_destroy(struct uet_nic_ernic *n)
{
    if (n == NULL)
        return;
    for (unsigned i = 0; i < n->rx_count; i++)
        slot_release(&n->slots[(n->rx_head + i) % RX_SLOTS]);
    free(n->slot_mem);
    free(n);
}

int uet_nic_ernic_register(struct uet_nic_ernic *n)
{
    if (n == NULL)
        return -EINVAL;
    return uet_nic_register_shim(&shim_ops, n);
}

void uet_nic_ernic_unregister(void)
{
    (void)uet_nic_register_shim(NULL, NULL);
}

/*
 * The filter.  @ext is NULL for a frame to copy into a slot; otherwise the
 * slot keeps the wire's buffer, and @release(@cookie) gives it back once
 * the frame has been read or dropped.  @csum_ok: the wire has checked the
 * IPv4 header checksum.
 */
static bool rx_frame(struct uet_nic_ernic *n, const uint8_t *f, size_t len,
                     bool ext, bool csum_ok, void (*release)(void *),
                     void *cookie)
{
    if (n == NULL || f == NULL || len < ETH_HLEN_)
        return false;

    uint16_t ethertype = rd16(f + 12);
    if (ethertype == ETHERTYPE_ARP_) {
        bool mine = handle_arp(n, f, len);

        if (mine && ext && release != NULL)
            release(cookie);
        return mine;
    }
    if (ethertype != ETHERTYPE_IPV4_ || len < ETH_HLEN_ + IPV4_MIN_HLEN)
        return false;

    const uint8_t *ip = f + ETH_HLEN_;
    size_t ihl = (size_t)(ip[0] & 0x0fu) * 4u;
    if ((ip[0] >> 4) != 4 || ihl < IPV4_MIN_HLEN || len < ETH_HLEN_ + ihl)
        return false;
    if (rd32(ip + 16) != n->ip)
        return false;
    /* UET over IP, or UET over UDP to the UET port.  Other UDP to the
     * engine's address is not UET, and not the guest's either, but it is
     * left alone like any other stray frame. */
    bool udp = ip[9] == IPPROTO_UDP_;
    if (udp) {
        if (len < ETH_HLEN_ + ihl + UDP_HLEN ||
            rd16(ip + ihl + 2) != n->udp_port)
            return false;
    } else if (ip[9] != n->ipproto) {
        return false;
    }

    /* Sent to the engine's address but not to its MAC: somebody else's
     * stale neighbor entry.  Not ours to take. */
    if (memcmp(f, n->mac, 6) != 0)
        return false;

    /* From here on the frame is the engine's, good or bad.  The provider
     * trusts the IP total length further than it checks it, so a frame
     * whose header does not hold together is dropped here: no options (the
     * provider has no use for them), no fragments, a length that fits in
     * what arrived, and a valid header checksum.  Ethernet padding past the
     * IP datagram is not handed on. */
    size_t tot_len = rd16(ip + 2);
    if (ihl != IPV4_MIN_HLEN || (rd16(ip + 6) & 0x3fffu) != 0 ||
        tot_len < IPV4_MIN_HLEN + (udp ? UDP_HLEN : 0u) ||
        ETH_HLEN_ + tot_len > len || (!csum_ok && !ipv4_csum_ok(ip, ihl)) ||
        (udp && rd16(ip + ihl + 4) != tot_len - ihl)) {
        n->stats.rx_dropped++;
        if (ext && release != NULL)
            release(cookie);
        return true;
    }
    len = ETH_HLEN_ + tot_len;

    if (len > n->slot_size || n->rx_count == RX_SLOTS) {
        n->stats.rx_dropped++;
        if (ext && release != NULL)
            release(cookie);
        return true;
    }

    struct rx_slot *s = &n->slots[(n->rx_head + n->rx_count) % RX_SLOTS];
    if (ext) {
        s->ext = f;
        s->release = release;
        s->cookie = cookie;
        n->stats.rx_frames_ext++;
    } else {
        memcpy(s->data, f, len);
    }
    s->len = len;
    n->rx_count++;
    n->stats.rx_frames++;
    return true;
}

bool uet_nic_ernic_rx_frame(struct uet_nic_ernic *n, const void *frame,
                            size_t len)
{
    return rx_frame(n, frame, len, false, false, NULL, NULL);
}

bool uet_nic_ernic_rx_frame_ext(struct uet_nic_ernic *n, const void *frame,
                                size_t len, bool csum_ok,
                                void (*release)(void *cookie), void *cookie)
{
    return rx_frame(n, frame, len, true, csum_ok, release, cookie);
}

bool uet_nic_ernic_rx_pending(const struct uet_nic_ernic *n)
{
    return n != NULL && n->rx_count > 0;
}

void uet_nic_ernic_tick(struct uet_nic_ernic *n, uint64_t now)
{
    static const uint8_t none[6] = {0};

    if (n == NULL)
        return;

    for (unsigned i = 0; i < NEIGH_MAX; i++) {
        struct neigh *e = &n->neigh[i];

        if (e->state != NEIGH_INCOMPLETE || now - e->last_req_ms < ARP_RETRY_MS)
            continue;
        if (e->tries >= ARP_MAX_TRIES) {
            e->state = NEIGH_FAILED;
            e->last_req_ms = now;
            continue;
        }
        e->tries++;
        e->last_req_ms = now;
        send_arp(n, ARP_OP_REQUEST_, none, e->ip);
    }
}

void uet_nic_ernic_get_stats(const struct uet_nic_ernic *n,
                             struct uet_nic_ernic_stats *out)
{
    if (n == NULL || out == NULL)
        return;
    *out = n->stats;
}
