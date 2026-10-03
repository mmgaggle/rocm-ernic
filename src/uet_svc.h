/*
 * uet_svc.h -- the UET engine's guest command channel
 *
 * A guest drives the engine with command capsules (shared/uet_ernic_abi.h)
 * sent on a "service QP": an RC queue pair connected to a destination QPN in
 * UET_ERNIC_SVC_QPN_BASE's range.  The datapath intercepts those SENDs and
 * hands each capsule here; this module checks it, runs it on the engine, and
 * hands back exactly one reply capsule per command, through a callback that
 * delivers it into the QP's next posted receive.
 *
 * Commands that the engine finishes asynchronously (WRITE, READ) are kept
 * in a pending table until their completion is reaped in uet_svc_poll().
 * Region and peer handles belong to the service QP that created them, and
 * every handle and pending command of a QP goes when the QP goes.
 *
 * Nothing here knows about vfio-user or ionic rings: the datapath supplies
 * the two callbacks, which is what lets the protocol be tested on its own.
 * Everything runs on the thread that owns the engine.
 *
 * Copyright (C) Advanced Micro Devices, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef UET_SVC_H
#define UET_SVC_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct uet_engine;
struct uet_svc;

/* An ionic memory region, as the datapath holds it. */
struct uet_svc_mr_view {
    uint64_t length;       /* bytes */
    uint32_t page_size;    /* power of 2 */
    const uint64_t *pages; /* DMA address of each page, or NULL when the
                            * region is one contiguous run at @base */
    uint32_t npages;       /* entries in @pages */
    uint32_t first_off;    /* where the region starts in pages[0] */
    uint64_t base;         /* DMA address of the first byte, when contiguous */
};

struct uet_svc_ops {
    /* Look an lkey up.  False when the guest has no such region. */
    bool (*mr_view)(void *ctx, uint32_t lkey, struct uet_svc_mr_view *out);
    /*
     * Deliver a reply capsule into the service QP's next posted receive.
     * True once delivered, or when the QP no longer exists; false when it has
     * no receive posted, in which case the reply is kept, in order, and
     * offered again on a later poll.
     */
    bool (*reply)(void *ctx, uint32_t qp_id, const void *capsule, size_t len);
};

struct uet_svc_stats {
    uint64_t commands;          /* capsules received */
    uint64_t dropped;           /* capsules too broken to answer */
    uint64_t replies;           /* replies delivered */
    uint64_t replies_waited;    /* times a reply found no receive posted */
    uint64_t replies_discarded; /* replies for a QP that went away */
    uint64_t ops_completed;     /* WRITE/READ answered with success */
    uint64_t ops_failed;        /* WRITE/READ answered with an error */
    uint64_t ops_aborted;       /* WRITE/READ taken back by ABORT, or because
                                 * their QP went away */
    uint64_t aborts_deferred;   /* ABORT answered EAGAIN: no room for the
                                 * answers yet */
    uint64_t rekeys;            /* MR_REKEY answered with a new key */
    uint32_t ops_queued;        /* now: waiting to be posted */
    uint32_t ops_posted;        /* now: in the engine */
    uint32_t mrs;               /* now: region handles, dead ones included */
    uint32_t mrs_dead;          /* now: of which their ionic MR went away
                                 * before MR_DEREG */
    uint32_t peers;             /* now: peer handles */
    uint32_t replies_pending;   /* now: replies waiting for a receive */
};

struct uet_svc *uet_svc_create(struct uet_engine *engine,
                               const struct uet_svc_ops *ops, void *ctx);

/* Releases every handle on the engine; replies still owed are dropped. */
void uet_svc_destroy(struct uet_svc *s);

/* One capsule, as sent on service QP @qp_id. */
void uet_svc_command(struct uet_svc *s, uint32_t qp_id, const void *capsule,
                     size_t len);

/* Reap completions, retry posts that had to wait, deliver queued replies. */
void uet_svc_poll(struct uet_svc *s);

/* True while posts are waiting to be retried. */
bool uet_svc_has_work(const struct uet_svc *s);

/* The guest destroyed service QP @qp_id. */
void uet_svc_qp_gone(struct uet_svc *s, uint32_t qp_id);

/*
 * The guest destroyed, invalidated or re-registered the ionic region @lkey.
 * Every engine registration of it is revoked at once.
 */
void uet_svc_mr_gone(struct uet_svc *s, uint32_t lkey);

void uet_svc_get_stats(const struct uet_svc *s, struct uet_svc_stats *out);

#endif /* UET_SVC_H */
