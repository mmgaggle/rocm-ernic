/*
 * uet_engine.h -- Ultra Ethernet Transport engine, as device firmware
 *
 * The engine runs the UEC reference provider's semantic, packet delivery
 * and transport security sublayers (SES, PDS and TSS) inside the server,
 * the way a real UET NIC runs them in firmware.  It has an IPv4 and MAC
 * address of its own on the emulated wire and speaks real UET frames
 * (Ethernet, IPv4, UDP to port 4793 or IP protocol 253, PDS and SES
 * headers, and a TSS header when security is on) to its peers.
 *
 * The owner supplies two things: a wire to transmit frames on, and a way to
 * reach the memory that regions describe (guest memory, in the server).  It
 * feeds the engine every frame it takes off the wire through
 * uet_engine_rx_frame() and calls uet_engine_poll() from its main loop.
 * Everything, including every access to region memory, happens inside
 * those calls, on the caller's thread.
 *
 * The provider keeps its PDS, RUDI, TSS and impairment state in globals and
 * reads its configuration from the environment, so there is one engine per
 * process and creating it sets UET_* environment variables.
 *
 * This header deliberately includes nothing from the provider, so code that
 * only drives the engine does not need its headers.
 *
 * Copyright (C) Advanced Micro Devices, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef UET_ENGINE_H
#define UET_ENGINE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/uio.h>

#define UET_ENGINE_MAX_PEERS 32u
#define UET_ENGINE_MAX_MRS   256u
#define UET_ENGINE_MAX_OPS   64u /* operations in flight at once */

/* Packet delivery sublayer implementation. */
enum uet_engine_pds {
    UET_ENGINE_PDS_FULL = 0, /* RUD/ROD/RUDI/UUD ("pds") */
    UET_ENGINE_PDS_SNG,      /* stop-and-go ROD only ("sng") */
};

/* Transport security sublayer mode. */
enum uet_engine_sec {
    UET_ENGINE_SEC_NONE = 0,
    UET_ENGINE_SEC_DIRECT,
    UET_ENGINE_SEC_CLUSTER,
};

/* How UET frames are put on the wire (UEC 1.0.1, 3.2.5).  Received frames
 * are taken in either form, whichever this says. */
enum uet_engine_encap {
    UET_ENGINE_ENCAP_UDP = 0, /* UDP to udp_port, entropy in the source port */
    UET_ENGINE_ENCAP_IP, /* IP protocol ipproto, behind an entropy header */
};

/* What carries the engine's frames.  The engine itself only ever sees a
 * struct uet_engine_wire; these are for its owner, from --uet. */
enum uet_engine_wire_kind {
    UET_ENGINE_WIRE_TAP = 0, /* the device's TAP (--tap) */
    UET_ENGINE_WIRE_DPDK,    /* a DPDK port (uet_wire_dpdk.h) */
};

enum uet_engine_dpdk_map {
    UET_ENGINE_DPDK_MAP_AUTO = 0,
    UET_ENGINE_DPDK_MAP_ON,
    UET_ENGINE_DPDK_MAP_OFF,
};

#define UET_ENGINE_DPDK_ARG_MAX 256u

#define UET_ENGINE_UDP_PORT 4793u /* IANA, UEC 1.0.1 Table 3-28 */
#define UET_ENGINE_IPPROTO  253u  /* experimental (RFC 3692) */

struct uet_engine_cfg {
    uint32_t ip;             /* engine's IPv4 address, host order */
    uint8_t mac[6];          /* engine's MAC, see mac_set */
    bool mac_set;            /* false: 02:55 followed by the IP's bytes */
    uint32_t job_id;         /* JobID, 24 bits */
    uint16_t pid_on_fep;     /* PIDonFEP of the engine's endpoint, 12 bits */
    uint16_t resource_index; /* resource index of that endpoint, 12 bits */
    uint32_t initiator_id;   /* SES initiator ID the endpoint sends */
    enum uet_engine_pds pds;
    enum uet_engine_sec sec;
    uint32_t ssi;         /* TSS source identifier, 0: use the IP */
    uint32_t rto_ms;      /* PDS retransmit timeout, 0: provider's */
    uint32_t max_retries; /* PDS retransmit limit, 0: provider's */
    uint32_t drop_thresh; /* test only: drop this many 1/100 % of PDS
                           * transmits (UET_PKT_DROP_THRESH), 0: none */
    uint16_t mtu;         /* IP MTU of the wire; 0: the wire's own, which
                           * the owner fills in, else 1500 */
    enum uet_engine_encap encap;
    uint16_t udp_port; /* UDP destination port */
    uint8_t ipproto;   /* IP protocol without UDP */
    uint32_t payload;  /* Payload MTU (1024, 2048, 4096, 8192); 0: the
                        * largest whose packets fit the MTU */
    uint32_t window;   /* packets in flight per transfer: the PDS window
                        * offered to a peer, and the RUDI bound; a multiple
                        * of 128.  0: the provider's 128, which suits a
                        * wire that queues 1000 frames */
    /* The wire, for the owner (see enum uet_engine_wire_kind).  In --uet,
     * ';' stands for ',' in dpdk-dev= and dpdk-dma=, and separates the
     * arguments of dpdk-eal=. */
    enum uet_engine_wire_kind wire;
    char dpdk_dev[UET_ENGINE_DPDK_ARG_MAX]; /* devargs of the port */
    char dpdk_eal[UET_ENGINE_DPDK_ARG_MAX]; /* more EAL arguments */
    char dpdk_dma[UET_ENGINE_DPDK_ARG_MAX]; /* dmadev, or "" */
    uint16_t dpdk_queues;                   /* queue pairs, 0: 1 */
    /* Guest memory DMA-mapped for the port and the dmadev: for devices on
     * a bus (auto), for every device (on), or never (off: copies). */
    enum uet_engine_dpdk_map dpdk_map;
    bool dpdk_split; /* receive buffer split, where the port has it */
    /*
     * How long a deregistered region's provider descriptor is kept, disabled
     * and unreachable, before it is closed and may be reused.  A partially
     * received message holds a pointer to the descriptor until it completes
     * or goes idle (5 s in the provider), so this has to outlast that.  Not
     * an --uet option; tests shorten it.
     */
    uint32_t mr_quarantine_ms;
};

/* Fill in the defaults: everything but the address. */
void uet_engine_cfg_defaults(struct uet_engine_cfg *cfg);

/*
 * Parse "key=value[,key=value...]" (the argument of --uet) on top of what
 * @cfg already holds, and check the result is complete and consistent.
 * Returns false with a message in @err on any problem.
 */
bool uet_engine_cfg_parse(struct uet_engine_cfg *cfg, const char *opts,
                          char *err, size_t errlen);

/* The MAC a configuration gives the engine (mac=, or 02:55 and the IP). */
void uet_engine_cfg_mac(const struct uet_engine_cfg *cfg, uint8_t mac[6]);

/* One-line description of a configuration, for the startup report. */
void uet_engine_cfg_describe(const struct uet_engine_cfg *cfg, char *buf,
                             size_t len);

/*
 * Where the engine's frames go.  tx() returns 0 or a negative errno.
 *
 * tx_iov(), when there is one, takes a frame in pieces so a payload need
 * not be copied into it: iov[0] is the headers and iov[n - 1] the CRC,
 * valid only for the call; the pieces between are payload in region
 * memory, which stays readable and unchanged until the operation
 * completes, so a wire may transmit from them after it returns.  It
 * returns -ENOTSUP for a frame it cannot take that way.
 *
 * flush(), when there is one, is called at the end of every
 * uet_engine_poll() for a wire that batches what it is given.
 *
 * tx_ipv4_csum says the wire fills in the IPv4 header checksum of every
 * frame, so the engine leaves it 0.
 */
struct uet_engine_wire {
    int (*tx)(void *ctx, const void *frame, size_t len);
    int (*tx_iov)(void *ctx, const struct iovec *iov, unsigned n, size_t len);
    void (*flush)(void *ctx);
    void *ctx;
    bool tx_ipv4_csum;
};

/*
 * How the engine reaches region memory.  map() returns a pointer through
 * which @len bytes at DMA address @addr can be accessed, or NULL when they
 * cannot be.  @write says whether the engine will store through it.  The
 * engine never asks for a range that crosses a page of the region it is
 * accessing.  With no map() a DMA address is taken to be a process address.
 */
struct uet_engine_dma {
    void *(*map)(void *ctx, uint64_t addr, size_t len, bool write);
    /* Optional: place received payload at @dst, a pointer map() returned,
     * with a copy engine; 0 or a negative errno.  NULL: memcpy(). */
    int (*copy)(void *ctx, void *dst, const void *src, size_t len);
    void *ctx;
};

struct uet_engine;

struct uet_engine *uet_engine_create(const struct uet_engine_cfg *cfg,
                                     const struct uet_engine_wire *wire,
                                     const struct uet_engine_dma *dma,
                                     char *err, size_t errlen);
void uet_engine_destroy(struct uet_engine *e);

/* The configuration the engine runs with: its MAC, MTU and Payload MTU
 * filled in. */
void uet_engine_identity(const struct uet_engine *e,
                         struct uet_engine_cfg *out);

/* What the transport settled on, for the startup report: the identity's
 * description plus the ACK coalescing that follows from the payload. */
void uet_engine_describe(const struct uet_engine *e, char *buf, size_t len);

/*
 * Wire-side receive filter.  Returns true when the frame was the engine's
 * (UET for its address, or ARP for its address) and has been consumed;
 * anything else is left for the caller to deliver to the guest.
 */
bool uet_engine_rx_frame(struct uet_engine *e, const void *frame, size_t len);

/*
 * The same for a frame the engine may keep in the wire's buffer until it
 * has read it (see uet_nic_ernic_rx_frame_ext()): on true the engine owns
 * the buffer and calls @release(@cookie) when done; on false the caller
 * keeps it.  @csum_ok says the wire checked the IPv4 header checksum.
 */
bool uet_engine_rx_frame_ext(struct uet_engine *e, const void *frame,
                             size_t len, bool csum_ok,
                             void (*release)(void *cookie), void *cookie);

/* Run the transport: received frames, retransmit timers, ARP retries. */
void uet_engine_poll(struct uet_engine *e);

/* True while there is work that should not wait for the idle sleep. */
bool uet_engine_has_work(const struct uet_engine *e);

/*
 * A memory region, described the way a driver describes one: by a page
 * buffer list of DMA addresses that lives in region memory itself.  Offsets
 * within the region start at 0.
 */
struct uet_engine_mr_desc {
    uint64_t root;        /* level 0: DMA address of the first page;
                           * level 1: of the page address array;
                           * level 2: of the array of page directories */
    uint32_t page_size;   /* power of 2 */
    uint8_t level;        /* 0, 1 or 2 */
    uint32_t page_offset; /* where the region starts in its first page */
    uint64_t len;
    bool remote_read;     /* peers may read it */
    bool remote_write;    /* peers may write it */
    bool idempotent_safe; /* peers may target it with RUDI */
};

/* Returns 0 with the region's handle and remote key, or a negative errno. */
int uet_engine_mr_reg(struct uet_engine *e, const struct uet_engine_mr_desc *d,
                      uint32_t *mr, uint64_t *rkey);

/*
 * A memory region given as a list of page DMA addresses held in the
 * caller's own memory, which is how the datapath keeps an ionic MR.  The
 * engine copies the list and serves the provider's page-list reads from its
 * copy, so the caller may free its list at once, and the engine can make the
 * region unreachable on its own when it is deregistered.  Offsets within the
 * region start at 0.
 */
struct uet_engine_pages {
    const uint64_t *pages; /* DMA address of each page, in order */
    uint32_t npages;
    uint32_t page_size;   /* power of 2 */
    uint32_t page_offset; /* where the region starts in pages[0] */
    uint64_t len;
    bool remote_read;
    bool remote_write;
    bool idempotent_safe;
};

int uet_engine_mr_reg_pages(struct uet_engine *e,
                            const struct uet_engine_pages *p, uint32_t *mr,
                            uint64_t *rkey);

/*
 * Deregister a region.  Peers lose access at once, and for a region from
 * uet_engine_mr_reg_pages() so does everything else: an operation that
 * still needs it fails instead of touching memory the owner may already
 * have taken back.  The handle is released once no operation refers to it
 * and the quarantine has passed.  Returns 0, or -EINVAL for a bad handle.
 */
int uet_engine_mr_dereg(struct uet_engine *e, uint32_t mr);

/*
 * Make a peer endpoint addressable.  Its MAC is resolved by ARP in the
 * background; until that finishes, operations to it return -EAGAIN.
 */
int uet_engine_peer_add(struct uet_engine *e, uint32_t ip, uint16_t pid_on_fep,
                        uint16_t resource_index, uint32_t *peer);

/* Removal, like deregistration, waits for operations still using it. */
int uet_engine_peer_remove(struct uet_engine *e, uint32_t peer);

struct uet_engine_rma {
    uint32_t peer;
    uint32_t mr;         /* local region */
    uint64_t local_addr; /* offset within it */
    uint64_t len;
    uint64_t remote_addr; /* offset within the remote region */
    uint64_t rkey;        /* the remote region's key */
    bool rudi;            /* use RUDI if the key and the peer allow it */
    uint64_t cookie;      /* handed back in the completion */
};

/*
 * Post an RMA write or read.  Returns 0 when posted; -EAGAIN when it cannot
 * be posted yet (no free operation slot, or the peer's MAC is still being
 * resolved) and should be retried after polling; -ECANCELED when the region
 * or the peer is being released; -EHOSTUNREACH when the peer never answered
 * ARP; or another negative errno.
 */
int uet_engine_post_write(struct uet_engine *e, const struct uet_engine_rma *w);
int uet_engine_post_read(struct uet_engine *e, const struct uet_engine_rma *r);

struct uet_engine_comp {
    uint64_t cookie;
    int status; /* 0, or a negative errno */
};

/* Reap up to @max completions of posted operations. */
size_t uet_engine_poll_comp(struct uet_engine *e, struct uet_engine_comp *out,
                            size_t max);

struct uet_engine_stats {
    /* wire */
    uint64_t rx_frames;
    uint64_t rx_frames_ext; /* of which left in the wire's buffer */
    uint64_t rx_dropped;
    uint64_t tx_frames;
    uint64_t tx_frames_iov; /* of which with the payload left in place */
    uint64_t tx_dropped;
    uint64_t arp_requests;
    uint64_t arp_replies;
    uint64_t nh_pending;
    /* operations */
    uint64_t ops_posted;
    uint64_t ops_completed;
    uint64_t ops_failed;
    /* region memory */
    uint64_t dma_read_maps;
    uint64_t dma_write_maps;
    uint64_t dma_faults;
    uint64_t revoked_hits; /* page-list reads refused after deregistration */
    /* tables, now */
    uint32_t mrs;   /* region handles held, quarantined ones included */
    uint32_t peers; /* peer handles held, ones being removed included */
    uint32_t ops_in_flight;
};

void uet_engine_get_stats(const struct uet_engine *e,
                          struct uet_engine_stats *out);

#endif /* UET_ENGINE_H */
