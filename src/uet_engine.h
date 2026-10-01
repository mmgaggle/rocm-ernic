/*
 * uet_engine.h -- Ultra Ethernet Transport engine, as device firmware
 *
 * The engine runs the UEC reference provider's semantic, packet delivery
 * and transport security sublayers (SES, PDS and TSS) inside the server,
 * the way a real UET NIC runs them in firmware.  It has an IPv4 and MAC
 * address of its own on the emulated wire and speaks real UET frames
 * (Ethernet, IPv4 protocol 253, PDS and SES headers, and a TSS header
 * when security is on) to its peers.
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

#define UET_ENGINE_MAX_PEERS 32u
#define UET_ENGINE_MAX_MRS   64u
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
    uint16_t mtu;         /* IP MTU of the wire */
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

/* One-line description of a configuration, for the startup report. */
void uet_engine_cfg_describe(const struct uet_engine_cfg *cfg, char *buf,
                             size_t len);

/* Where the engine's frames go.  Returns 0 or a negative errno. */
struct uet_engine_wire {
    int (*tx)(void *ctx, const void *frame, size_t len);
    void *ctx;
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
    void *ctx;
};

struct uet_engine;

struct uet_engine *uet_engine_create(const struct uet_engine_cfg *cfg,
                                     const struct uet_engine_wire *wire,
                                     const struct uet_engine_dma *dma,
                                     char *err, size_t errlen);
void uet_engine_destroy(struct uet_engine *e);

/*
 * Wire-side receive filter.  Returns true when the frame was the engine's
 * (UET for its address, or ARP for its address) and has been consumed;
 * anything else is left for the caller to deliver to the guest.
 */
bool uet_engine_rx_frame(struct uet_engine *e, const void *frame, size_t len);

/* Run the transport: received frames, retransmit timers, ARP retries. */
void uet_engine_poll(struct uet_engine *e);

/* True while there is work that should not wait for the idle sleep. */
bool uet_engine_has_work(const struct uet_engine *e);

/*
 * A memory region, described the way a driver describes one: by a page
 * buffer list of DMA addresses.  Offsets within the region start at 0.
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
int uet_engine_mr_dereg(struct uet_engine *e, uint32_t mr);

/*
 * Make a peer endpoint addressable.  Its MAC is resolved by ARP in the
 * background; until that finishes, operations to it return -EAGAIN.
 */
int uet_engine_peer_add(struct uet_engine *e, uint32_t ip, uint16_t pid_on_fep,
                        uint16_t resource_index, uint32_t *peer);
int uet_engine_peer_remove(struct uet_engine *e, uint32_t peer);

struct uet_engine_write {
    uint32_t peer;
    uint32_t mr;     /* local region the data is read from */
    uint64_t offset; /* where in it */
    uint64_t len;
    uint64_t remote_addr; /* offset within the remote region */
    uint64_t rkey;        /* the remote region's key */
    bool rudi;            /* use RUDI if the key and the peer allow it */
    uint64_t cookie;      /* handed back in the completion */
};

/*
 * Post an RMA write.  Returns 0 when posted, -EAGAIN when it cannot be
 * posted yet (no free operation slot, or the peer's MAC is still being
 * resolved) and should be retried after polling, or another negative errno.
 */
int uet_engine_post_write(struct uet_engine *e,
                          const struct uet_engine_write *w);

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
    uint64_t rx_dropped;
    uint64_t tx_frames;
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
};

void uet_engine_get_stats(const struct uet_engine *e,
                          struct uet_engine_stats *out);

#endif /* UET_ENGINE_H */
