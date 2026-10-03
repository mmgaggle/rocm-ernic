/*
 * uet_wire_dpdk.c -- a DPDK port as the UET engine's wire
 *
 * See uet_wire_dpdk.h.  Everything here runs on the server's main thread,
 * the one that services vfio-user: the port is polled from the main loop,
 * and the dmadev is waited on synchronously.  The EAL's own threads (its
 * interrupt thread, and the skeleton dmadev's copy thread) are the only
 * others.
 *
 * Copyright (C) Advanced Micro Devices, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <rte_bus.h>
#include <rte_byteorder.h>
#include <rte_dev.h>
#include <rte_dmadev.h>
#include <rte_eal.h>
#include <rte_errno.h>
#include <rte_ethdev.h>
#include <rte_flow.h>
#include <rte_ip.h>
#include <rte_mbuf.h>
#include <rte_mbuf_dyn.h>
#include <rte_memory.h>

#include "uet_wire_dpdk.h"

#define RX_BURST    32u
#define TX_BURST    64u
#define RING_DESC   4096u
#define MAX_QUEUES  16u
#define MAX_TX_SEGS 16u   /* pieces of one frame, see struct uet_engine_wire */
#define EXT_SHINFO  8192u /* external buffers attached at once, at most */
#define HDR_SPLIT   256u  /* header buffer with buffer split */
/* Payload below this goes out copied: an external buffer costs an mbuf and
 * a segment of its own, which a copy of a small payload does not. */
#define EXTBUF_MIN  2048u
#define DMA_SPIN_NS (100u * 1000u * 1000u) /* give up on a copy after this */
#define DRAIN_MS    100u /* region removal waits this long by default */
/* Guest regions mapped at once, at most: each external memory area takes
 * one of the EAL's RTE_MAX_MEMSEG_LISTS (128) memseg lists, and VFIO keeps
 * at most 256 mappings. */
#define MAX_REGIONS   32u
#define ETH_HLEN_     14u
#define ETHERTYPE_IP  0x0800u
#define ETHERTYPE_ARP 0x0806u

struct uet_wire_dpdk;
struct guest_region;

static void region_unmap(struct uet_wire_dpdk *w, struct guest_region *r);

/* The shared info of one external buffer, kept on a free list. */
struct ext_shinfo {
    struct rte_mbuf_ext_shared_info info;
    struct ext_shinfo *next_free;
    struct uet_wire_dpdk *owner;
};

/* A guest DMA region registered with the EAL, and for which devices it is
 * mapped. */
struct guest_region {
    uint8_t *va;
    size_t len;
    bool port_mapped;
    bool dma_mapped;
};

enum { MAP_DEV_PORT = 0, MAP_DEV_DMA = 1 };

struct uet_wire_dpdk {
    struct uet_wire_dpdk_cfg cfg;
    char dev_name[RTE_ETH_NAME_MAX_LEN];
    uint16_t port;
    uint16_t nq;
    uint16_t mtu;
    struct rte_mempool *pool;     /* frames */
    struct rte_mempool *ext_pool; /* mbufs that carry external buffers */
    struct rte_mempool *hdr_pool; /* headers, with buffer split */

    /* what each offload ended up as, for describe() */
    bool flow_hw;
    bool flow_isolated;
    bool flow_no_rss; /* the port has RSS, but not as a flow action */
    unsigned flow_rules;
    char flow_why[96];
    bool rss_hw;
    uint64_t rss_hf;
    bool tx_multiseg;
    bool iova_va;
    bool rx_split;
    bool rx_scatter;
    bool rx_ts_hw;
    bool tx_ts_hw; /* IEEE 1588 timesync, for the record */
    bool tx_csum_hw;
    bool rx_csum_hw;
    bool promisc;
    bool mac_added;
    int ts_off;       /* dynfield offset of the receive timestamp */
    size_t ts_off_sz; /* the same, once it is known to be one */
    uint64_t ts_flag;

    uint16_t tx_max_segs; /* mbufs per frame the port takes */
    uint32_t split_proto; /* protocol split after these headers, or 0 */

    int16_t dma; /* dmadev id, or -1 */
    char dma_name[64];
    uint16_t dma_idx;

    struct rte_mbuf *tx[TX_BURST];
    unsigned ntx;

    struct ext_shinfo *shinfo;
    struct ext_shinfo *shinfo_free;
    unsigned ext_inflight; /* external buffers the port still holds */

    /* Guest memory: which devices need it mapped, and the regions. */
    struct rte_device *port_dev;
    struct rte_device *dma_dev;
    bool port_map;
    bool dma_map;
    bool dma_via_port;  /* the port's mapping is the dmadev's (one VFIO
                         * container) */
    char map_why[96];   /* why nothing is mapped, for describe() */
    char retry_why[96]; /* why the port started without split/timestamps */
    struct uet_wire_dpdk_map_ops map_ops;
    struct guest_region regions[MAX_REGIONS];
    unsigned nregions;
    unsigned last_region;

    struct uet_wire_dpdk_stats st;
};

static bool g_eal_up;

static void set_err(char *err, size_t errlen, const char *fmt, ...)
    __attribute__((format(printf, 3, 4)));

static void set_err(char *err, size_t errlen, const char *fmt, ...)
{
    va_list ap;

    if (err == NULL || errlen == 0)
        return;
    va_start(ap, fmt);
    vsnprintf(err, errlen, fmt, ap);
    va_end(ap);
}

static uint64_t now_ns(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * UINT64_C(1000000000) + (uint64_t)ts.tv_nsec;
}

/* A devargs string names a virtual device when it starts with one of the
 * vdev driver prefixes; anything else is a bus address. */
static bool is_vdev(const char *dev)
{
    return strncmp(dev, "net_", 4) == 0 || strncmp(dev, "eth_", 4) == 0 ||
           strncmp(dev, "dma_", 4) == 0 || strncmp(dev, "crypto_", 7) == 0;
}

/* The device name in a devargs string: what comes before the first ','. */
static void devargs_name(const char *dev, char *out, size_t len)
{
    size_t n = strcspn(dev, ",");

    if (n >= len)
        n = len - 1;
    memcpy(out, dev, n);
    out[n] = '\0';
}

/* ------------------------------------------------------------------ */
/* EAL                                                                */
/* ------------------------------------------------------------------ */

#define MAX_EAL_ARGS 64

static int eal_start(const struct uet_wire_dpdk_cfg *cfg, char *err,
                     size_t errlen)
{
    /* Static: the EAL may keep pointers into its arguments. */
    static char *argv[MAX_EAL_ARGS];
    static char lcore[16];
    char *extra = NULL;
    int argc = 0;
    cpu_set_t saved;
    int rc;

    if (g_eal_up)
        return 0;

#define ARG(s)                                 \
    do {                                       \
        if (argc >= MAX_EAL_ARGS - 1)          \
            goto too_many;                     \
        argv[argc++] = (char *)(uintptr_t)(s); \
    } while (0)

    /* One lcore, the calling thread; the EAL would otherwise start an idle
     * worker thread on every CPU. */
    snprintf(lcore, sizeof(lcore), "0");
    ARG("rocm-ernic-uet");
    ARG("-l");
    ARG(lcore);
    ARG("--no-telemetry");
    ARG("--log-level=*:warning");
    bool have_dma = cfg->dma != NULL && *cfg->dma != '\0';

    if (is_vdev(cfg->dev) && (!have_dma || is_vdev(cfg->dma))) {
        /* Virtual devices need neither hugepages nor PCI. */
        ARG("--no-shconf");
        ARG("--no-huge");
        ARG("-m");
        ARG("512");
        ARG("--no-pci");
    } else {
        /* A device on a bus DMAs from hugepages.  In memory: no files in
         * hugetlbfs or the runtime directory, so a second engine (another
         * port) runs beside this one without a --file-prefix. */
        ARG("--in-memory");
    }
    ARG(is_vdev(cfg->dev) ? "--vdev" : "-a");
    ARG(cfg->dev);
    if (have_dma) {
        ARG(is_vdev(cfg->dma) ? "--vdev" : "-a");
        ARG(cfg->dma);
    }
    if (cfg->eal != NULL && *cfg->eal != '\0') {
        char *save = NULL;

        extra = strdup(cfg->eal);
        if (extra == NULL) {
            set_err(err, errlen, "out of memory");
            return -ENOMEM;
        }
        for (char *tok = strtok_r(extra, " ", &save); tok != NULL;
             tok = strtok_r(NULL, " ", &save))
            ARG(tok);
    }
    argv[argc] = NULL;
#undef ARG

    /* rte_eal_init() binds the calling thread to the main lcore's CPU.
     * This thread is the server's only one and should run wherever the
     * scheduler likes, so its affinity is put back afterwards. */
    CPU_ZERO(&saved);
    (void)pthread_getaffinity_np(pthread_self(), sizeof(saved), &saved);
    rc = rte_eal_init(argc, argv);
    (void)pthread_setaffinity_np(pthread_self(), sizeof(saved), &saved);
    /* extra stays allocated, for the same reason as argv. */
    if (rc < 0) {
        set_err(err, errlen, "rte_eal_init: %s", rte_strerror(rte_errno));
        free(extra);
        return -rte_errno;
    }
    g_eal_up = true;
    return 0;

too_many:
    set_err(err, errlen, "too many EAL arguments");
    free(extra);
    return -E2BIG;
}

/* ------------------------------------------------------------------ */
/* External buffers                                                   */
/* ------------------------------------------------------------------ */

/* The port is done with a piece of guest memory: nothing to free there,
 * only the shared info to put back.  Mbufs are freed on this thread, in a
 * transmit burst or a flush. */
static void ext_free_cb(void *addr, void *opaque)
{
    struct ext_shinfo *s = opaque;

    (void)addr;
    s->next_free = s->owner->shinfo_free;
    s->owner->shinfo_free = s;
    s->owner->ext_inflight--;
}

/* ------------------------------------------------------------------ */
/* Port                                                               */
/* ------------------------------------------------------------------ */

static void flow_note(struct uet_wire_dpdk *w, const char *what,
                      const struct rte_flow_error *fe)
{
    snprintf(w->flow_why, sizeof(w->flow_why), "%s: %s", what,
             fe->message != NULL ? fe->message : rte_strerror(rte_errno));
}

/*
 * The rules that bring the engine its frames: UDP to the UET port, the UET
 * IP protocol and ICMP (the engine answers pings), all to the engine's
 * address, and ARP.  UET over UDP is spread over the queues by RSS on the
 * source port (the entropy) when there is more than one.  Validated first,
 * created only if all of them validate.
 */
#define FLOW_RULES 4u
static void flow_setup(struct uet_wire_dpdk *w, bool create)
{
    struct rte_flow_attr attr = {.ingress = 1};
    struct rte_flow_error fe;
    struct rte_flow_item_ipv4 ip_spec, ip_mask;
    struct rte_flow_item_ipv4 ipp_spec, ipp_mask;
    struct rte_flow_item_ipv4 icmp_spec, icmp_mask;
    struct rte_flow_item_udp udp_spec, udp_mask;
    struct rte_flow_item_eth arp_spec, arp_mask;
    uint16_t queues[MAX_QUEUES];
    struct rte_flow_action_queue q0 = {.index = 0};
    struct rte_flow_action_rss rss;

    memset(&ip_spec, 0, sizeof(ip_spec));
    memset(&ip_mask, 0, sizeof(ip_mask));
    ip_spec.hdr.dst_addr = rte_cpu_to_be_32(w->cfg.ip);
    ip_mask.hdr.dst_addr = UINT32_MAX;
    ipp_spec = ip_spec;
    ipp_mask = ip_mask;
    ipp_spec.hdr.next_proto_id = w->cfg.ipproto;
    ipp_mask.hdr.next_proto_id = UINT8_MAX;
    icmp_spec = ipp_spec;
    icmp_mask = ipp_mask;
    icmp_spec.hdr.next_proto_id = 1; /* ICMP */
    memset(&udp_spec, 0, sizeof(udp_spec));
    memset(&udp_mask, 0, sizeof(udp_mask));
    udp_spec.hdr.dst_port = rte_cpu_to_be_16(w->cfg.udp_port);
    udp_mask.hdr.dst_port = UINT16_MAX;
    memset(&arp_spec, 0, sizeof(arp_spec));
    memset(&arp_mask, 0, sizeof(arp_mask));
    arp_spec.hdr.ether_type = rte_cpu_to_be_16(ETHERTYPE_ARP);
    arp_mask.hdr.ether_type = UINT16_MAX;

    for (uint16_t i = 0; i < w->nq; i++)
        queues[i] = i;
    memset(&rss, 0, sizeof(rss));
    rss.func = RTE_ETH_HASH_FUNCTION_DEFAULT;
    rss.types = w->rss_hf;
    rss.queue_num = w->nq;
    rss.queue = queues;

    const struct rte_flow_item udp_pat[] = {
        {.type = RTE_FLOW_ITEM_TYPE_ETH},
        {.type = RTE_FLOW_ITEM_TYPE_IPV4, .spec = &ip_spec, .mask = &ip_mask},
        {.type = RTE_FLOW_ITEM_TYPE_UDP, .spec = &udp_spec, .mask = &udp_mask},
        {.type = RTE_FLOW_ITEM_TYPE_END},
    };
    const struct rte_flow_item ipp_pat[] = {
        {.type = RTE_FLOW_ITEM_TYPE_ETH},
        {.type = RTE_FLOW_ITEM_TYPE_IPV4, .spec = &ipp_spec, .mask = &ipp_mask},
        {.type = RTE_FLOW_ITEM_TYPE_END},
    };
    const struct rte_flow_item icmp_pat[] = {
        {.type = RTE_FLOW_ITEM_TYPE_ETH},
        {.type = RTE_FLOW_ITEM_TYPE_IPV4,
         .spec = &icmp_spec,
         .mask = &icmp_mask},
        {.type = RTE_FLOW_ITEM_TYPE_END},
    };
    const struct rte_flow_item arp_pat[] = {
        {.type = RTE_FLOW_ITEM_TYPE_ETH, .spec = &arp_spec, .mask = &arp_mask},
        {.type = RTE_FLOW_ITEM_TYPE_END},
    };
    const struct rte_flow_action to_q0[] = {
        {.type = RTE_FLOW_ACTION_TYPE_QUEUE, .conf = &q0},
        {.type = RTE_FLOW_ACTION_TYPE_END},
    };
    const struct rte_flow_action to_rss[] = {
        {.type = RTE_FLOW_ACTION_TYPE_RSS, .conf = &rss},
        {.type = RTE_FLOW_ACTION_TYPE_END},
    };
    /* RSS across the engine's queues when the port can do it in a flow
     * rule; when it cannot, everything to queue 0. */
    const struct rte_flow_action *udp_act =
        (w->rss_hw && !w->flow_no_rss) ? to_rss : to_q0;
    if (!create && udp_act == to_rss) {
        memset(&fe, 0, sizeof(fe));
        if (rte_flow_validate(w->port, &attr, udp_pat, to_rss, &fe) != 0) {
            w->flow_no_rss = true;
            udp_act = to_q0;
        }
    }

    struct {
        const char *what;
        const struct rte_flow_item *pat;
        const struct rte_flow_action *act;
    } rules[] = {
        {"UDP rule", udp_pat, udp_act},
        {"IP protocol rule", ipp_pat, to_q0},
        {"ICMP rule", icmp_pat, to_q0},
        {"ARP rule", arp_pat, to_q0},
    };
    _Static_assert(sizeof(rules) / sizeof(rules[0]) == FLOW_RULES,
                   "every rule is counted");

    for (unsigned i = 0; i < sizeof(rules) / sizeof(rules[0]); i++) {
        memset(&fe, 0, sizeof(fe));
        if (!create) {
            if (rte_flow_validate(w->port, &attr, rules[i].pat, rules[i].act,
                                  &fe) != 0) {
                flow_note(w, rules[i].what, &fe);
                return;
            }
            continue;
        }
        if (rte_flow_create(w->port, &attr, rules[i].pat, rules[i].act, &fe) ==
            NULL) {
            flow_note(w, rules[i].what, &fe);
            (void)rte_flow_flush(w->port, &fe);
            w->flow_rules = 0;
            return;
        }
        w->flow_rules++;
    }
    if (create)
        w->flow_hw = true;
    else
        w->flow_rules = FLOW_RULES; /* all validated */
}

/* Buffer split after the UDP header, where the port splits by protocol. */
#define SPLIT_PROTO \
    (RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN | RTE_PTYPE_L4_UDP)

static uint32_t split_proto(uint16_t port)
{
    uint32_t ptypes[64];
    int n = rte_eth_buffer_split_get_supported_hdr_ptypes(port, ptypes, 64);

    for (int i = 0; i < n && i < 64; i++)
        if (ptypes[i] == SPLIT_PROTO)
            return SPLIT_PROTO;
    return 0;
}

/*
 * Configure the port, set up its queues, validate the flow rules (and
 * isolate it if they all do) and start it, with what w and conf say.
 */
static int port_start(struct uet_wire_dpdk *w,
                      const struct rte_eth_dev_info *di,
                      const struct rte_eth_conf *conf, char *err, size_t errlen)
{
    struct rte_eth_rxconf rxconf;
    struct rte_eth_txconf txconf;
    struct rte_flow_error fe;
    int rc;

    rc = rte_eth_dev_configure(w->port, w->nq, w->nq, conf);
    if (rc != 0) {
        set_err(err, errlen, "rte_eth_dev_configure: %s", rte_strerror(-rc));
        return rc;
    }

    for (uint16_t q = 0; q < w->nq; q++) {
        uint16_t nrx = RING_DESC, ntx = RING_DESC;

        (void)rte_eth_dev_adjust_nb_rx_tx_desc(w->port, &nrx, &ntx);
        rxconf = di->default_rxconf;
        rxconf.offloads = conf->rxmode.offloads;
        if (w->rx_split) {
            /* Headers in one buffer, payload in another: after the UDP
             * header where the port splits by protocol, after HDR_SPLIT
             * bytes where it splits by length. */
            union rte_eth_rxseg segs[2];

            memset(segs, 0, sizeof(segs));
            segs[0].split.mp = w->hdr_pool;
            segs[0].split.length = w->split_proto != 0 ? 0 : HDR_SPLIT;
            segs[0].split.proto_hdr = w->split_proto;
            segs[1].split.mp = w->pool;
            segs[1].split.length = 0;
            rxconf.rx_seg = segs;
            rxconf.rx_nseg = 2;
            rc = rte_eth_rx_queue_setup(w->port, q, nrx, rte_socket_id(),
                                        &rxconf, NULL);
        } else {
            rc = rte_eth_rx_queue_setup(w->port, q, nrx, rte_socket_id(),
                                        &rxconf, w->pool);
        }
        if (rc != 0) {
            set_err(err, errlen, "rte_eth_rx_queue_setup: %s",
                    rte_strerror(-rc));
            return rc;
        }
        txconf = di->default_txconf;
        txconf.offloads = conf->txmode.offloads;
        rc = rte_eth_tx_queue_setup(w->port, q, ntx, rte_socket_id(), &txconf);
        if (rc != 0) {
            set_err(err, errlen, "rte_eth_tx_queue_setup: %s",
                    rte_strerror(-rc));
            return rc;
        }
    }

    /* Flow rules: validated before start, created after it.  Isolation
     * (only the matched frames come to these queues; the rest stay with
     * the kernel on a bifurcated driver) is asked for when all of them
     * validate, before start, as most drivers want it. */
    w->flow_rules = 0;
    w->flow_why[0] = '\0';
    w->flow_no_rss = false;
    flow_setup(w, false);
    if (w->flow_rules == FLOW_RULES) {
        memset(&fe, 0, sizeof(fe));
        w->flow_isolated = rte_flow_isolate(w->port, 1, &fe) == 0;
    }
    w->flow_rules = 0;

    rc = rte_eth_dev_start(w->port);
    if (rc != 0) {
        set_err(err, errlen, "rte_eth_dev_start: %s", rte_strerror(-rc));
        return rc;
    }
    return 0;
}

static int port_setup(struct uet_wire_dpdk *w, char *err, size_t errlen)
{
    struct rte_eth_dev_info di;
    struct rte_eth_conf conf;
    struct rte_flow_error fe;
    uint32_t frame = (uint32_t)w->cfg.mtu + ETH_HLEN_ + 4u; /* VLAN slack */
    uint32_t room;
    int rc;

    rc = rte_eth_dev_info_get(w->port, &di);
    if (rc != 0) {
        set_err(err, errlen, "rte_eth_dev_info_get: %s", rte_strerror(-rc));
        return rc;
    }
    w->port_dev = di.device;

    /* Queues, and RSS over the UDP source port across them. */
    w->nq = w->cfg.queues == 0 ? 1 : w->cfg.queues;
    if (w->nq > MAX_QUEUES)
        w->nq = MAX_QUEUES;
    if (w->nq > di.max_rx_queues)
        w->nq = di.max_rx_queues;
    if (w->nq > di.max_tx_queues)
        w->nq = di.max_tx_queues;
    if (w->nq == 0)
        w->nq = 1;

    memset(&conf, 0, sizeof(conf));
    if (w->nq > 1) {
        uint64_t want = RTE_ETH_RSS_NONFRAG_IPV4_UDP | RTE_ETH_RSS_L4_SRC_ONLY;

        if (di.flow_type_rss_offloads & RTE_ETH_RSS_NONFRAG_IPV4_UDP) {
            /* The source port alone is the entropy; a port that cannot
             * hash on it alone hashes the 4-tuple, which spreads the same
             * flows. */
            w->rss_hf = want & di.flow_type_rss_offloads;
            conf.rxmode.mq_mode = RTE_ETH_MQ_RX_RSS;
            conf.rx_adv_conf.rss_conf.rss_hf = w->rss_hf;
            w->rss_hw = true;
        } else {
            w->nq = 1; /* nothing would spread the frames */
        }
    }

    /* The MTU, where the port lets it be set; some (af_packet) carry
     * larger frames than they say they can. */
    if (di.max_rx_pktlen >= frame && w->cfg.mtu <= di.max_mtu)
        conf.rxmode.mtu = w->cfg.mtu;

    /* Receive offloads. */
    if (di.rx_offload_capa & RTE_ETH_RX_OFFLOAD_IPV4_CKSUM) {
        conf.rxmode.offloads |= RTE_ETH_RX_OFFLOAD_IPV4_CKSUM;
        w->rx_csum_hw = true;
    }
    if (di.rx_offload_capa & RTE_ETH_RX_OFFLOAD_TIMESTAMP) {
        if (rte_mbuf_dyn_rx_timestamp_register(&w->ts_off, &w->ts_flag) == 0 &&
            w->ts_off >= 0) {
            w->ts_off_sz = (size_t)w->ts_off;
            conf.rxmode.offloads |= RTE_ETH_RX_OFFLOAD_TIMESTAMP;
            w->rx_ts_hw = true;
        }
    }
    if (w->cfg.rx_split &&
        (di.rx_offload_capa & RTE_ETH_RX_OFFLOAD_BUFFER_SPLIT) &&
        di.rx_seg_capa.max_nseg >= 2 && di.rx_seg_capa.multi_pools) {
        conf.rxmode.offloads |= RTE_ETH_RX_OFFLOAD_BUFFER_SPLIT;
        w->rx_split = true;
        w->split_proto = split_proto(w->port);
    }

    /* Transmit offloads. */
    if (di.tx_offload_capa & RTE_ETH_TX_OFFLOAD_IPV4_CKSUM) {
        conf.txmode.offloads |= RTE_ETH_TX_OFFLOAD_IPV4_CKSUM;
        w->tx_csum_hw = true;
    }
    if (di.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MULTI_SEGS) {
        conf.txmode.offloads |= RTE_ETH_TX_OFFLOAD_MULTI_SEGS;
        w->tx_multiseg = true;
    }
    /* Mbufs per frame: ice takes 8; 0 means the port does not say. */
    w->tx_max_segs = di.tx_desc_lim.nb_mtu_seg_max != 0
                         ? di.tx_desc_lim.nb_mtu_seg_max
                         : UINT16_MAX;
    /* External buffers carry virtual addresses; a port that needs
     * physical ones gets copies. */
    w->iova_va = rte_eal_iova_mode() == RTE_IOVA_VA;

    /* Buffers: a whole jumbo frame per mbuf.  Pool sizes: the rings, the
     * engine's receive queue (it holds frames until the provider reads
     * them) and a few bursts.  1 KiB over the frame: some PMDs
     * (af_packet) keep their own header in front of the frame in the same
     * buffer size. */
    room = frame < RTE_MBUF_DEFAULT_DATAROOM
               ? RTE_MBUF_DEFAULT_DATAROOM
               : ((frame + 1023u) & ~1023u) + 1024u;
    if (room > UINT16_MAX - RTE_PKTMBUF_HEADROOM)
        room = UINT16_MAX - RTE_PKTMBUF_HEADROOM;
    if (!w->rx_split && (di.rx_offload_capa & RTE_ETH_RX_OFFLOAD_SCATTER) &&
        frame > room) {
        conf.rxmode.offloads |= RTE_ETH_RX_OFFLOAD_SCATTER;
        w->rx_scatter = true;
    }
    w->pool = rte_pktmbuf_pool_create(
        "uet_frames", 2u * RING_DESC * w->nq + 2048u, 256, 0,
        (uint16_t)(room + RTE_PKTMBUF_HEADROOM), (int)rte_socket_id());
    w->ext_pool = rte_pktmbuf_pool_create("uet_ext", EXT_SHINFO, 256, 0, 0,
                                          (int)rte_socket_id());
    if (w->pool == NULL || w->ext_pool == NULL) {
        set_err(err, errlen, "mbuf pools: %s", rte_strerror(rte_errno));
        return -ENOMEM;
    }
    if (w->rx_split) {
        w->hdr_pool = rte_pktmbuf_pool_create(
            "uet_hdrs", 2u * RING_DESC * w->nq + 2048u, 256, 0,
            HDR_SPLIT + RTE_PKTMBUF_HEADROOM, (int)rte_socket_id());
        if (w->hdr_pool == NULL) {
            w->rx_split = false;
            conf.rxmode.offloads &= ~RTE_ETH_RX_OFFLOAD_BUFFER_SPLIT;
        }
    }
    w->mtu = w->cfg.mtu;

    rc = port_start(w, &di, &conf, err, errlen);
    if (rc != 0 && (w->rx_split || w->rx_ts_hw)) {
        /* A port can report an offload and still refuse it in this
         * configuration (ice starts with buffer split only by protocol,
         * and with timestamps only where it has the clock).  Once more
         * without the optional ones. */
        snprintf(w->retry_why, sizeof(w->retry_why), "%s",
                 err != NULL ? err : "");
        (void)rte_eth_dev_stop(w->port);
        memset(&fe, 0, sizeof(fe));
        (void)rte_flow_isolate(w->port, 0, &fe);
        w->flow_isolated = false;
        conf.rxmode.offloads &=
            ~(RTE_ETH_RX_OFFLOAD_BUFFER_SPLIT | RTE_ETH_RX_OFFLOAD_TIMESTAMP);
        w->rx_split = false;
        w->split_proto = 0;
        w->rx_ts_hw = false;
        rc = port_start(w, &di, &conf, err, errlen);
    }
    if (rc != 0)
        return rc;

    if (w->flow_why[0] == '\0')
        flow_setup(w, true);
    if (!w->flow_hw && w->flow_isolated) {
        /* Isolated with no rules would bring nothing at all. */
        (void)rte_eth_dev_stop(w->port);
        memset(&fe, 0, sizeof(fe));
        (void)rte_flow_isolate(w->port, 0, &fe);
        w->flow_isolated = false;
        rc = rte_eth_dev_start(w->port);
        if (rc != 0) {
            set_err(err, errlen, "rte_eth_dev_start: %s", rte_strerror(-rc));
            return rc;
        }
    }
    if (!w->flow_hw && w->flow_why[0] == '\0')
        snprintf(w->flow_why, sizeof(w->flow_why), "not created");

    /* The engine's own MAC; failing that, everything. */
    struct rte_ether_addr mac;

    memcpy(mac.addr_bytes, w->cfg.mac, sizeof(mac.addr_bytes));
    w->mac_added = rte_eth_dev_mac_addr_add(w->port, &mac, 0) == 0;
    w->promisc = rte_eth_promiscuous_enable(w->port) == 0;

    /* Transmit timestamps exist only as IEEE 1588 timesync. */
    if (rte_eth_timesync_enable(w->port) == 0) {
        w->tx_ts_hw = true;
        (void)rte_eth_timesync_disable(w->port);
    }

    if (!w->flow_hw && !w->promisc && !w->mac_added) {
        set_err(err, errlen,
                "the port takes neither the engine's MAC nor "
                "promiscuous mode");
        return -ENOTSUP;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* Devices and guest memory                                           */
/* ------------------------------------------------------------------ */

struct dev_find {
    const char *name;
    struct rte_device *dev;
    size_t best;
};

/* The device whose name is @name, or the longest prefix of it that ends
 * at a '-' or '_' (an idxd dmadev "0000:6a:01.0-q0" is on the device
 * "0000:6a:01.0"). */
static int dev_find_on_bus(const struct rte_bus *bus, const void *data)
{
    struct dev_find *f = (struct dev_find *)(uintptr_t)data;
    struct rte_dev_iterator it;
    struct rte_device *dev;
    char str[64];

    snprintf(str, sizeof(str), "bus=%s", rte_bus_name(bus));
    memset(&it, 0, sizeof(it));
    RTE_DEV_FOREACH(dev, str, &it)
    {
        const char *n = rte_dev_name(dev);
        size_t len = strlen(n);

        if (len <= f->best || strncmp(f->name, n, len) != 0)
            continue;
        if (f->name[len] == '\0' || f->name[len] == '-' ||
            f->name[len] == '_') {
            f->dev = dev;
            f->best = len;
        }
    }
    return 1; /* on to the next bus */
}

static struct rte_device *dev_find(const char *name)
{
    struct dev_find f = {.name = name};

    (void)rte_bus_find(NULL, dev_find_on_bus, &f);
    return f.dev;
}

static const char *dev_bus(const struct rte_device *dev)
{
    const struct rte_bus *bus = dev != NULL ? rte_dev_bus(dev) : NULL;

    return bus != NULL ? rte_bus_name(bus) : "?";
}

/* A device on a bus reaches memory through the IOMMU and needs it mapped;
 * a vdev reaches it through the CPU, and an idxd work queue on the dsa bus
 * (the kernel's driver) by the process's own addresses (shared virtual
 * memory). */
static bool dev_needs_map(const struct rte_device *dev)
{
    const char *bus = dev_bus(dev);

    return strcmp(bus, "vdev") != 0 && strcmp(bus, "dsa") != 0;
}

/* Some PCI drivers map memory their own way (mlx5 registers it); the rest
 * map it in the process's one VFIO container. */
static bool dev_maps_in_vfio(const struct rte_device *dev)
{
    const struct rte_driver *drv = rte_dev_driver(dev);
    const char *name = drv != NULL ? rte_driver_name(drv) : "";

    return strcmp(dev_bus(dev), "pci") == 0 && strncmp(name, "mlx", 3) != 0;
}

/* Which devices need guest memory mapped (see uet_wire_dpdk.h). */
static void map_setup(struct uet_wire_dpdk *w)
{
    bool have_dma = w->dma >= 0;

    if (have_dma)
        w->dma_dev = dev_find(w->dma_name);

    switch (w->cfg.map) {
    case UET_WIRE_DPDK_MAP_OFF:
        snprintf(w->map_why, sizeof(w->map_why), "map=off");
        return;
    case UET_WIRE_DPDK_MAP_ON:
        w->port_map = true;
        w->dma_map = have_dma;
        break;
    case UET_WIRE_DPDK_MAP_AUTO:
    default:
        w->port_map = w->port_dev != NULL && dev_needs_map(w->port_dev);
        /* A dmadev that cannot be found is taken to need it, and so gets
         * no mapping: memcpy(). */
        w->dma_map =
            have_dma && (w->dma_dev == NULL || dev_needs_map(w->dma_dev));
        break;
    }
    if (!w->iova_va) {
        /* Physical addresses: guest memory is not contiguous in them, so
         * no external buffers and no dmadev into it at all. */
        w->port_map = w->dma_map = false;
        snprintf(w->map_why, sizeof(w->map_why), "IOVA as PA: copies");
        return;
    }
    if (!w->port_map && !w->dma_map) {
        snprintf(w->map_why, sizeof(w->map_why),
                 "by VA, no device needs it mapped");
        return;
    }
    /* Two PCI devices in the one VFIO container share its mappings: a
     * second rte_dev_dma_map() of the same range would map it twice. */
    w->dma_via_port =
        w->port_map && w->dma_map && w->dma_dev != NULL &&
        (w->dma_dev == w->port_dev ||
         (dev_maps_in_vfio(w->port_dev) && dev_maps_in_vfio(w->dma_dev)));
}

static int dma_setup(struct uet_wire_dpdk *w)
{
    struct rte_dma_info info;
    struct rte_dma_conf dconf;
    struct rte_dma_vchan_conf vconf;
    char name[64];
    int dev;

    w->dma = -1;
    if (w->cfg.dma == NULL || *w->cfg.dma == '\0')
        return 0;

    devargs_name(w->cfg.dma, name, sizeof(name));
    dev = rte_dma_get_dev_id_by_name(name);
    if (dev < 0) {
        /* A vdev may name itself differently from its devargs. */
        dev = rte_dma_next_dev(0);
    }
    if (dev < 0 || rte_dma_info_get((int16_t)dev, &info) != 0)
        return -ENODEV;
    if (!(info.dev_capa & RTE_DMA_CAPA_MEM_TO_MEM))
        return -ENOTSUP;

    memset(&dconf, 0, sizeof(dconf));
    dconf.nb_vchans = 1;
    if (rte_dma_configure((int16_t)dev, &dconf) != 0)
        return -EIO;
    memset(&vconf, 0, sizeof(vconf));
    vconf.direction = RTE_DMA_DIR_MEM_TO_MEM;
    vconf.nb_desc = 128;
    if (vconf.nb_desc < info.min_desc)
        vconf.nb_desc = info.min_desc;
    if (info.max_desc != 0 && vconf.nb_desc > info.max_desc)
        vconf.nb_desc = info.max_desc;
    if (rte_dma_vchan_setup((int16_t)dev, 0, &vconf) != 0 ||
        rte_dma_start((int16_t)dev) != 0)
        return -EIO;

    w->dma = (int16_t)dev;
    snprintf(w->dma_name, sizeof(w->dma_name), "%s", info.dev_name);
    return 0;
}

struct uet_wire_dpdk *uet_wire_dpdk_open(const struct uet_wire_dpdk_cfg *cfg,
                                         char *err, size_t errlen)
{
    struct uet_wire_dpdk *w;
    int rc;

    if (cfg == NULL || cfg->dev == NULL || *cfg->dev == '\0') {
        set_err(err, errlen, "no DPDK device");
        return NULL;
    }

    w = calloc(1, sizeof(*w));
    if (w == NULL) {
        set_err(err, errlen, "out of memory");
        return NULL;
    }
    w->cfg = *cfg;
    w->dma = -1;

    rc = eal_start(cfg, err, errlen);
    if (rc != 0)
        goto fail;

    devargs_name(cfg->dev, w->dev_name, sizeof(w->dev_name));
    if (rte_eth_dev_get_port_by_name(w->dev_name, &w->port) != 0) {
        /* A bus address written short ("c1:00.0"), or a vdev that names
         * its port differently: the one port there is. */
        uint16_t n = rte_eth_dev_count_avail();

        w->port = rte_eth_find_next(0);
        if (n != 1 || w->port >= RTE_MAX_ETHPORTS) {
            set_err(err, errlen, "no DPDK port named %s (%u ports)",
                    w->dev_name, (unsigned)n);
            goto fail;
        }
        (void)rte_eth_dev_get_name_by_port(w->port, w->dev_name);
    }

    /* Free list of shared infos for external buffers. */
    w->shinfo = calloc(EXT_SHINFO, sizeof(*w->shinfo));
    if (w->shinfo == NULL) {
        set_err(err, errlen, "out of memory");
        goto fail;
    }
    for (unsigned i = 0; i < EXT_SHINFO; i++) {
        w->shinfo[i].owner = w;
        w->shinfo[i].next_free = w->shinfo_free;
        w->shinfo_free = &w->shinfo[i];
    }

    rc = port_setup(w, err, errlen);
    if (rc != 0)
        goto fail;
    if (dma_setup(w) != 0) {
        /* The copy falls back to memcpy(); say so rather than fail. */
        w->dma = -1;
        snprintf(w->dma_name, sizeof(w->dma_name), "unavailable");
    }
    map_setup(w);
    return w;

fail:
    uet_wire_dpdk_close(w);
    return NULL;
}

void uet_wire_dpdk_close(struct uet_wire_dpdk *w)
{
    struct rte_flow_error fe;

    if (w == NULL)
        return;
    if (g_eal_up) {
        for (unsigned i = 0; i < w->ntx; i++)
            rte_pktmbuf_free(w->tx[i]);
        w->ntx = 0;
        if (rte_eth_dev_is_valid_port(w->port)) {
            memset(&fe, 0, sizeof(fe));
            (void)rte_flow_flush(w->port, &fe);
            (void)rte_eth_dev_stop(w->port);
        }
        /* Stopped, the port holds no frame: guest memory is unmapped
         * while the devices are still there to unmap it from. */
        while (w->nregions != 0)
            region_unmap(w, &w->regions[--w->nregions]);
        if (rte_eth_dev_is_valid_port(w->port))
            (void)rte_eth_dev_close(w->port);
        if (w->dma >= 0) {
            (void)rte_dma_stop(w->dma);
            (void)rte_dma_close(w->dma);
        }
        rte_mempool_free(w->pool);
        rte_mempool_free(w->ext_pool);
        rte_mempool_free(w->hdr_pool);
    }
    free(w->shinfo);
    free(w);
}

void uet_wire_dpdk_describe(const struct uet_wire_dpdk *w, char *buf,
                            size_t len)
{
    char flow[160];
    char rss[80];
    char mem[160];
    char split[48];

    if (w->flow_hw)
        snprintf(flow, sizeof(flow), "flow hw (%u rules%s%s)", w->flow_rules,
                 w->flow_isolated ? ", isolated" : "",
                 w->flow_no_rss ? ", queue 0: no rss action" : "");
    else
        snprintf(flow, sizeof(flow), "flow sw filter (%s)", w->flow_why);
    if (w->rss_hw && w->flow_isolated && w->flow_no_rss)
        snprintf(rss, sizeof(rss), "rss unused (UET to queue 0), %u queues",
                 (unsigned)w->nq);
    else if (w->rss_hw)
        snprintf(rss, sizeof(rss), "rss hw on udp %s, %u queues",
                 (w->rss_hf & RTE_ETH_RSS_L4_SRC_ONLY) ? "sport" : "4-tuple",
                 (unsigned)w->nq);
    else
        snprintf(rss, sizeof(rss), "rss off, %u queue%s", (unsigned)w->nq,
                 w->nq == 1 ? "" : "s");

    if (w->port_map || w->dma_map)
        snprintf(mem, sizeof(mem),
                 "dma-mapped per region for %s%s (rte_dev_dma_map)",
                 !w->dma_map    ? "the port"
                 : !w->port_map ? "the dmadev"
                                : "the port and the dmadev",
                 w->dma_via_port ? ", one VFIO container" : "");
    else
        snprintf(mem, sizeof(mem), "%s", w->map_why);
    if (w->rx_split)
        snprintf(split, sizeof(split), "hw (%s)",
                 w->split_proto != 0 ? "after UDP" : "after 256 bytes");
    else
        snprintf(split, sizeof(split), "%s",
                 w->cfg.rx_split ? "off (unsupported)" : "off");

    snprintf(buf, len,
             "dpdk %s (%s): %s; %s; tx %s; rx split %s%s; dma %s; ts rx %s "
             "tx %s; ipv4 csum tx %s rx %s; udp csum none (UET sends 0); "
             "mac %s; guest mem %s%s%s",
             w->dev_name, dev_bus(w->port_dev), flow, rss,
             w->tx_multiseg && w->iova_va ? "extbuf zero-copy"
                                          : "copy (no multi-seg or PA iova)",
             split, w->rx_scatter ? ", scatter" : "",
             w->dma >= 0 ? w->dma_name : "memcpy", w->rx_ts_hw ? "hw" : "sw",
             w->tx_ts_hw ? "hw (1588)" : "sw", w->tx_csum_hw ? "hw" : "sw",
             w->rx_csum_hw ? "hw" : "sw",
             w->mac_added ? "added" : (w->promisc ? "promisc" : "none"), mem,
             w->retry_why[0] != '\0' ? "; started without split and rx "
                                       "timestamps after: "
                                     : "",
             w->retry_why);
}

uint16_t uet_wire_dpdk_mtu(const struct uet_wire_dpdk *w)
{
    uint16_t mtu = 0;

    if (w == NULL || rte_eth_dev_get_mtu(w->port, &mtu) != 0)
        return w != NULL ? w->mtu : 0;
    return mtu;
}

bool uet_wire_dpdk_link_up(const struct uet_wire_dpdk *w)
{
    struct rte_eth_link link;

    if (w == NULL)
        return false;
    memset(&link, 0, sizeof(link));
    if (rte_eth_link_get_nowait(w->port, &link) != 0)
        return false;
    return link.link_status == RTE_ETH_LINK_UP;
}

bool uet_wire_dpdk_has_dma(const struct uet_wire_dpdk *w)
{
    return w != NULL && w->dma >= 0;
}

/* ------------------------------------------------------------------ */
/* Transmit                                                           */
/* ------------------------------------------------------------------ */

/* The region [p, p + n) lies in, or NULL. */
static struct guest_region *region_of(struct uet_wire_dpdk *w, const void *p,
                                      size_t n)
{
    const uint8_t *a = p;

    for (unsigned k = 0; k < w->nregions; k++) {
        unsigned i = (w->last_region + k) % w->nregions;
        struct guest_region *r = &w->regions[i];

        if (a >= r->va && n <= r->len && (size_t)(a - r->va) <= r->len - n) {
            w->last_region = i;
            return r;
        }
    }
    return NULL;
}

/* May the port read [p, p + n) by its virtual address? */
static bool port_may_read(struct uet_wire_dpdk *w, const void *p, size_t n)
{
    struct guest_region *r;

    if (!w->port_map)
        return true;
    r = region_of(w, p, n);
    return r != NULL && r->port_mapped;
}

/* May the dmadev reach [p, p + n): memory of the EAL's own, or a guest
 * region mapped for it? */
static bool dma_may_reach(struct uet_wire_dpdk *w, const void *p, size_t n)
{
    const struct rte_memseg_list *msl;
    struct guest_region *r;

    if (!w->dma_map)
        return true;
    r = region_of(w, p, n);
    if (r != NULL)
        return r->dma_mapped;
    msl = rte_mem_virt2memseg_list(p);
    return msl != NULL && !msl->external;
}

/* The IPv4 header checksum: the port's job if it can, else done here. */
static void tx_csum(struct uet_wire_dpdk *w, struct rte_mbuf *m)
{
    uint8_t *f = rte_pktmbuf_mtod(m, uint8_t *);

    if (m->data_len < ETH_HLEN_ + sizeof(struct rte_ipv4_hdr) ||
        (((unsigned)f[12] << 8) | f[13]) != ETHERTYPE_IP)
        return;

    struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *)(void *)(f + ETH_HLEN_);
    ip->hdr_checksum = 0;
    if (w->tx_csum_hw) {
        m->l2_len = ETH_HLEN_;
        m->l3_len = (uint64_t)(ip->version_ihl & 0x0fu) * 4u;
        m->ol_flags |= RTE_MBUF_F_TX_IPV4 | RTE_MBUF_F_TX_IP_CKSUM;
    } else {
        ip->hdr_checksum = rte_ipv4_cksum(ip);
    }
}

static int tx_queue(struct uet_wire_dpdk *w, struct rte_mbuf *m)
{
    tx_csum(w, m);
    if (w->ntx == TX_BURST) {
        uet_wire_dpdk_flush(w);
        if (w->ntx == TX_BURST) {
            /* The port is not taking frames: lose this one, which the
             * transport recovers like any other loss. */
            rte_pktmbuf_free(m);
            w->st.tx_dropped++;
            return -ENOBUFS;
        }
    }
    w->tx[w->ntx++] = m;
    if (w->ntx == TX_BURST)
        uet_wire_dpdk_flush(w);
    return 0;
}

int uet_wire_dpdk_tx(struct uet_wire_dpdk *w, const void *frame, size_t len)
{
    struct rte_mbuf *m;
    char *p;

    if (len > UINT16_MAX)
        return -EMSGSIZE;
    m = rte_pktmbuf_alloc(w->pool);
    if (m == NULL) {
        w->st.tx_nombuf++;
        return -ENOBUFS;
    }
    p = rte_pktmbuf_append(m, (uint16_t)len);
    if (p == NULL) {
        rte_pktmbuf_free(m);
        return -EMSGSIZE;
    }
    memcpy(p, frame, len);
    int rc = tx_queue(w, m);
    if (rc == 0)
        w->st.tx_copied_frames++;
    return rc;
}

/* One mbuf holding all the pieces, for a port that cannot take more. */
static int tx_iov_copy(struct uet_wire_dpdk *w, const struct iovec *iov,
                       unsigned n, size_t len)
{
    struct rte_mbuf *m;
    char *p;

    if (len > UINT16_MAX)
        return -EMSGSIZE;
    m = rte_pktmbuf_alloc(w->pool);
    if (m == NULL) {
        w->st.tx_nombuf++;
        return -ENOBUFS;
    }
    p = rte_pktmbuf_append(m, (uint16_t)len);
    if (p == NULL) {
        rte_pktmbuf_free(m);
        return -EMSGSIZE;
    }
    for (unsigned i = 0; i < n; i++) {
        memcpy(p, iov[i].iov_base, iov[i].iov_len);
        p += iov[i].iov_len;
    }
    int rc = tx_queue(w, m);
    if (rc == 0)
        w->st.tx_copied_frames++;
    return rc;
}

/* A small mbuf holding a copy of @len bytes. */
static struct rte_mbuf *copy_seg(struct uet_wire_dpdk *w, const void *data,
                                 size_t len)
{
    struct rte_mbuf *m = rte_pktmbuf_alloc(w->pool);
    char *p;

    if (m == NULL)
        return NULL;
    p = rte_pktmbuf_append(m, (uint16_t)len);
    if (p == NULL) {
        rte_pktmbuf_free(m);
        return NULL;
    }
    memcpy(p, data, len);
    return m;
}

int uet_wire_dpdk_tx_iov(struct uet_wire_dpdk *w, const struct iovec *iov,
                         unsigned n, size_t len)
{
    struct rte_mbuf *head, *m;
    size_t total = 0;

    if (n < 2 || n > MAX_TX_SEGS || len > UINT16_MAX)
        return -ENOTSUP;
    for (unsigned i = 0; i < n; i++)
        total += iov[i].iov_len;
    if (total != len)
        return -EINVAL;
    if (!w->tx_multiseg || !w->iova_va || n > w->tx_max_segs ||
        len - iov[0].iov_len - iov[n - 1].iov_len < EXTBUF_MIN)
        return tx_iov_copy(w, iov, n, len);
    for (unsigned i = 1; i + 1 < n; i++) {
        if (!port_may_read(w, iov[i].iov_base, iov[i].iov_len)) {
            /* Not mapped for the port: it would fault in the IOMMU. */
            int rc = tx_iov_copy(w, iov, n, len);

            if (rc == 0)
                w->st.tx_copied_unmapped++;
            return rc;
        }
    }

    head = copy_seg(w, iov[0].iov_base, iov[0].iov_len);
    if (head == NULL) {
        w->st.tx_nombuf++;
        return -ENOBUFS;
    }

    /* The payload, attached where it is in guest memory. */
    for (unsigned i = 1; i + 1 < n; i++) {
        struct ext_shinfo *s = w->shinfo_free;

        if (iov[i].iov_len > UINT16_MAX || s == NULL)
            goto copy;
        m = rte_pktmbuf_alloc(w->ext_pool);
        if (m == NULL)
            goto copy;
        w->shinfo_free = s->next_free;
        w->ext_inflight++;
        s->info.free_cb = ext_free_cb;
        s->info.fcb_opaque = s;
        rte_mbuf_ext_refcnt_set(&s->info, 1);
        rte_pktmbuf_attach_extbuf(m, iov[i].iov_base,
                                  (rte_iova_t)(uintptr_t)iov[i].iov_base,
                                  (uint16_t)iov[i].iov_len, &s->info);
        m->data_len = (uint16_t)iov[i].iov_len;
        m->pkt_len = (uint32_t)iov[i].iov_len;
        if (rte_pktmbuf_chain(head, m) != 0) {
            rte_pktmbuf_free(m);
            goto copy;
        }
    }

    m = copy_seg(w, iov[n - 1].iov_base, iov[n - 1].iov_len);
    if (m == NULL || rte_pktmbuf_chain(head, m) != 0) {
        rte_pktmbuf_free(m);
        goto copy;
    }
    int rc = tx_queue(w, head);
    if (rc == 0)
        w->st.tx_extbuf_frames++;
    return rc;

copy:
    rte_pktmbuf_free(head);
    return tx_iov_copy(w, iov, n, len);
}

bool uet_wire_dpdk_tx_pending(const struct uet_wire_dpdk *w)
{
    return w != NULL && w->ntx != 0;
}

void uet_wire_dpdk_flush(struct uet_wire_dpdk *w)
{
    unsigned sent;

    if (w == NULL || w->ntx == 0)
        return;
    /* What a full ring does not take waits for the next flush. */
    sent = rte_eth_tx_burst(w->port, 0, w->tx, (uint16_t)w->ntx);
    w->st.tx_frames += sent;
    if (sent < w->ntx)
        memmove(w->tx, w->tx + sent, (w->ntx - sent) * sizeof(w->tx[0]));
    w->ntx -= sent;
    if (sent != 0)
        w->st.last_tx_ts_ns = now_ns();
}

/* ------------------------------------------------------------------ */
/* Receive                                                            */
/* ------------------------------------------------------------------ */

void uet_wire_dpdk_release(void *cookie)
{
    rte_pktmbuf_free(cookie);
}

/* A frame spread over several mbufs (buffer split, scatter) gathered into
 * one, which then stands for it. */
static struct rte_mbuf *gather(struct uet_wire_dpdk *w, struct rte_mbuf *m)
{
    struct rte_mbuf *one;
    char *p;

    if (m->pkt_len > UINT16_MAX)
        return NULL;
    one = rte_pktmbuf_alloc(w->pool);
    if (one == NULL)
        return NULL;
    p = rte_pktmbuf_append(one, (uint16_t)m->pkt_len);
    if (p == NULL || rte_pktmbuf_read(m, 0, m->pkt_len, p) == NULL) {
        rte_pktmbuf_free(one);
        return NULL;
    }
    one->ol_flags = m->ol_flags;
    w->st.rx_multiseg++;
    return one;
}

bool uet_wire_dpdk_rx_pending(const struct uet_wire_dpdk *w)
{
    if (w == NULL)
        return false;
    for (uint16_t q = 0; q < w->nq; q++) {
        if (rte_eth_rx_queue_count(w->port, q) > 0)
            return true;
    }
    return false;
}

unsigned uet_wire_dpdk_poll(struct uet_wire_dpdk *w, uet_wire_dpdk_rx_fn rx,
                            void *ctx, unsigned budget)
{
    struct rte_mbuf *mb[RX_BURST];
    unsigned total = 0;

    for (uint16_t q = 0; q < w->nq; q++) {
        while (total < budget) {
            uint16_t want =
                (uint16_t)(budget - total < RX_BURST ? budget - total
                                                     : RX_BURST);
            uint16_t got = rte_eth_rx_burst(w->port, q, mb, want);
            uint64_t sw_ts = 0;

            if (got == 0)
                break;
            if (!w->rx_ts_hw)
                sw_ts = now_ns();
            for (uint16_t i = 0; i < got; i++) {
                struct rte_mbuf *m = mb[i];
                struct uet_wire_dpdk_frame f;

                if (m->nb_segs > 1) {
                    struct rte_mbuf *one = gather(w, m);

                    rte_pktmbuf_free(m);
                    if (one == NULL)
                        continue;
                    m = one;
                }
                memset(&f, 0, sizeof(f));
                f.data = rte_pktmbuf_mtod(m, const uint8_t *);
                f.len = m->data_len;
                f.cookie = m;
                f.csum_ok = (m->ol_flags & RTE_MBUF_F_RX_IP_CKSUM_MASK) ==
                            RTE_MBUF_F_RX_IP_CKSUM_GOOD;
                if (w->rx_ts_hw && (m->ol_flags & w->ts_flag)) {
                    f.hw_ts = true;
                    f.ts_ns = *RTE_MBUF_DYNFIELD(m, w->ts_off_sz,
                                                 rte_mbuf_timestamp_t *);
                    w->st.rx_ts_hw++;
                } else {
                    f.ts_ns = sw_ts != 0 ? sw_ts : now_ns();
                }
                w->st.last_rx_ts_ns = f.ts_ns;
                w->st.rx_frames++;
                if (f.csum_ok)
                    w->st.rx_csum_hw++;
                if (!rx(ctx, &f))
                    rte_pktmbuf_free(m);
            }
            total += got;
            if (got < want)
                break;
        }
    }
    return total;
}

/* ------------------------------------------------------------------ */
/* Placement in guest memory                                          */
/* ------------------------------------------------------------------ */

int uet_wire_dpdk_dma_copy(void *ctx, void *dst, const void *src, size_t len)
{
    struct uet_wire_dpdk *w = ctx;
    uint16_t last = 0;
    bool error = false;
    uint64_t start;
    int idx;

    if (w == NULL || w->dma < 0 || !w->iova_va || len > UINT32_MAX)
        goto cpu;
    if (!dma_may_reach(w, dst, len) || !dma_may_reach(w, src, len)) {
        w->st.dma_unmapped++;
        goto cpu;
    }

    idx = rte_dma_copy(w->dma, 0, (rte_iova_t)(uintptr_t)src,
                       (rte_iova_t)(uintptr_t)dst, (uint32_t)len,
                       RTE_DMA_OP_FLAG_SUBMIT);
    if (idx < 0)
        goto cpu;

    /* Synchronous: the packet is acknowledged when this returns. */
    start = now_ns();
    for (;;) {
        uint16_t done = rte_dma_completed(w->dma, 0, 1, &last, &error);

        if (done == 1 && !error) {
            w->st.dma_copies++;
            w->st.dma_bytes += len;
            return 0;
        }
        if (error || now_ns() - start > DMA_SPIN_NS)
            break;
        sched_yield();
    }
    w->st.dma_fallbacks++;
cpu:
    memcpy(dst, src, len);
    return 0;
}

/* ------------------------------------------------------------------ */
/* Guest memory regions                                               */
/* ------------------------------------------------------------------ */

static int dev_map(struct uet_wire_dpdk *w, int which, void *va, size_t len)
{
    struct rte_device *dev = which == MAP_DEV_PORT ? w->port_dev : w->dma_dev;
    int rc;

    if (w->map_ops.map != NULL)
        return w->map_ops.map(w->map_ops.ctx, which, va, len);
    if (dev == NULL)
        return -ENODEV;
    rc = rte_dev_dma_map(dev, va, (uint64_t)(uintptr_t)va, len);
    if (rc == 0)
        return 0;
    /* 1: a vdev with no driver; -1 with rte_errno otherwise. */
    return rc > 0 ? -ENODEV : (rte_errno != 0 ? -rte_errno : -EIO);
}

static void dev_unmap(struct uet_wire_dpdk *w, int which, void *va, size_t len)
{
    struct rte_device *dev = which == MAP_DEV_PORT ? w->port_dev : w->dma_dev;

    if (w->map_ops.unmap != NULL)
        (void)w->map_ops.unmap(w->map_ops.ctx, which, va, len);
    else if (dev != NULL)
        (void)rte_dev_dma_unmap(dev, va, (uint64_t)(uintptr_t)va, len);
}

/* The page size to register a region with: its own, or a larger power of
 * two that its address and length are multiples of (up to 1 GiB), which
 * keeps the EAL's page table for it small.  0 if it is not aligned. */
static size_t region_pgsz(const void *va, size_t len, size_t page_size)
{
    uintptr_t a = (uintptr_t)va;
    size_t pg = page_size != 0 ? page_size : (size_t)sysconf(_SC_PAGESIZE);

    if (pg == 0 || (pg & (pg - 1)) != 0 || a % pg != 0 || len % pg != 0)
        return 0;
    while (pg < ((size_t)1 << 30) && a % (pg * 2) == 0 && len % (pg * 2) == 0)
        pg *= 2;
    return pg;
}

static void region_unmap(struct uet_wire_dpdk *w, struct guest_region *r)
{
    if (r->port_mapped)
        dev_unmap(w, MAP_DEV_PORT, r->va, r->len);
    if (r->dma_mapped && !w->dma_via_port)
        dev_unmap(w, MAP_DEV_DMA, r->va, r->len);
    (void)rte_extmem_unregister(r->va, r->len);
    r->port_mapped = r->dma_mapped = false;
}

int uet_wire_dpdk_region_add(struct uet_wire_dpdk *w, void *va, size_t len,
                             size_t page_size, bool writable, char *why,
                             size_t whylen)
{
    struct guest_region *r;
    char port_err[64] = "", dma_err[64] = "";
    size_t pg;
    int rc, first = 0;

    if (w == NULL || va == NULL || len == 0)
        return -EINVAL;
    if (!w->port_map && !w->dma_map) {
        set_err(why, whylen, "not mapped: %s", w->map_why);
        return 0;
    }
    if (!writable)
        first = -EACCES;
    else if (w->nregions == MAX_REGIONS)
        first = -ENOSPC;
    else if ((pg = region_pgsz(va, len, page_size)) == 0)
        first = -EINVAL;
    else if (rte_extmem_register(va, len, NULL, 0, pg) != 0)
        first = rte_errno != 0 ? -rte_errno : -EIO;
    if (first != 0) {
        w->st.map_failures++;
        w->st.regions_unmapped++;
        set_err(why, whylen, "not mapped (%s): payload in it is copied",
                first == -EACCES   ? "read-only"
                : first == -ENOSPC ? "too many regions"
                : first == -EINVAL ? "not page aligned"
                                   : rte_strerror(-first));
        return first;
    }

    r = &w->regions[w->nregions];
    memset(r, 0, sizeof(*r));
    r->va = va;
    r->len = len;
    if (w->port_map) {
        rc = dev_map(w, MAP_DEV_PORT, va, len);
        r->port_mapped = rc == 0;
        if (rc != 0) {
            snprintf(port_err, sizeof(port_err), "%s", rte_strerror(-rc));
            first = rc;
        }
    }
    if (w->dma_map) {
        if (w->dma_via_port) {
            r->dma_mapped = r->port_mapped;
        } else {
            rc = dev_map(w, MAP_DEV_DMA, va, len);
            r->dma_mapped = rc == 0;
            if (rc != 0) {
                snprintf(dma_err, sizeof(dma_err), "%s", rte_strerror(-rc));
                first = first != 0 ? first : rc;
            }
        }
    }
    if (first != 0)
        w->st.map_failures++;
    if (!r->port_mapped && !r->dma_mapped) {
        (void)rte_extmem_unregister(va, len);
        w->st.regions_unmapped++;
        set_err(why, whylen, "not mapped (%s): payload in it is copied",
                port_err[0] != '\0' ? port_err : dma_err);
        return first;
    }
    w->nregions++;
    w->st.regions_mapped++;
    if (port_err[0] != '\0')
        set_err(why, whylen,
                "DMA-mapped for the dmadev only; port: %s, payload in it is "
                "copied",
                port_err);
    else if (dma_err[0] != '\0')
        set_err(why, whylen,
                "DMA-mapped for the port only; dmadev: %s, placement in it "
                "by memcpy()",
                dma_err);
    else
        set_err(why, whylen, "DMA-mapped for %s%s",
                !w->dma_map    ? "the port"
                : !w->port_map ? "the dmadev"
                               : "the port and the dmadev",
                w->dma_via_port ? " (one VFIO container)" : "");
    return first != 0 ? first : 1;
}

/* Wait until the port holds no frame attached to guest memory; see
 * uet_wire_dpdk_region_remove(). */
static bool tx_drain(struct uet_wire_dpdk *w)
{
    uint64_t limit, start;

    if (w->ext_inflight == 0)
        return true;
    w->st.drain_waits++;
    limit = (uint64_t)(w->cfg.drain_ms != 0 ? w->cfg.drain_ms : DRAIN_MS) *
            UINT64_C(1000000);
    start = now_ns();
    for (;;) {
        uet_wire_dpdk_flush(w);
        (void)rte_eth_tx_done_cleanup(w->port, 0, 0);
        if (w->ext_inflight == 0)
            return true;
        if (now_ns() - start > limit)
            break;
        sched_yield();
    }

    /* The frames still queued here are lost (the transport recovers
     * them); a stopped transmit queue gives back what the port holds. */
    for (unsigned i = 0; i < w->ntx; i++)
        rte_pktmbuf_free(w->tx[i]);
    w->st.tx_dropped += w->ntx;
    w->ntx = 0;
    if (w->ext_inflight != 0 && rte_eth_dev_tx_queue_stop(w->port, 0) == 0) {
        (void)rte_eth_dev_tx_queue_start(w->port, 0);
        w->st.tx_queue_restarts++;
    }
    if (w->ext_inflight == 0)
        return true;
    w->st.drain_timeouts++;
    return false;
}

bool uet_wire_dpdk_region_remove(struct uet_wire_dpdk *w, void *va, size_t len)
{
    const uint8_t *a = va;
    bool drained;

    if (w == NULL)
        return true;
    drained = tx_drain(w);
    for (unsigned i = 0; i < w->nregions;) {
        struct guest_region *r = &w->regions[i];

        if (a < r->va + r->len && r->va < a + len) {
            region_unmap(w, r);
            w->regions[i] = w->regions[--w->nregions];
            w->last_region = 0;
        } else {
            i++;
        }
    }
    return drained;
}

unsigned uet_wire_dpdk_tx_inflight(const struct uet_wire_dpdk *w)
{
    return w != NULL ? w->ext_inflight : 0;
}

void uet_wire_dpdk_set_map_ops(struct uet_wire_dpdk *w,
                               const struct uet_wire_dpdk_map_ops *ops)
{
    if (w == NULL)
        return;
    if (ops != NULL)
        w->map_ops = *ops;
    else
        memset(&w->map_ops, 0, sizeof(w->map_ops));
}

void uet_wire_dpdk_get_stats(const struct uet_wire_dpdk *w,
                             struct uet_wire_dpdk_stats *out)
{
    if (w == NULL || out == NULL)
        return;
    *out = w->st;
}
