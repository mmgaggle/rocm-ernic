/*
 * uet_ernic.h -- libuet_ernic: the UET API on an ernic engine
 *
 * Copyright (c) Advanced Micro Devices, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: MIT
 *
 * libuet_ernic runs in a guest whose ionic NIC is a rocm-ernic instance
 * started with --uet. It implements the subset of the UEC reference
 * provider's uet_api.h (the ENABLE_VERBS=0 signatures) that the libfabric
 * "uet" provider calls, by driving the engine inside the device through the
 * command channel in uet_ernic_abi.h: an RC queue pair on the ionic device,
 * connected to the engine's service QPN.
 *
 * So the provider can link against this library instead of the reference
 * library and move data through the device rather than through a raw
 * socket of its own.
 *
 * The declarations below repeat uet_api.h's exactly (abi_check.c compiles
 * both together, so they cannot drift), because uet_api.h itself includes
 * libfabric internals that do not build against an installed libfabric.
 *
 * Differences from the reference library:
 *  - One device-side endpoint serves every endpoint opened here, so they
 *    all share its address (uet_getname) and JobID.
 *  - RMA writes and reads only.  A local buffer passed with no region is
 *    registered on demand: the 2 MiB-aligned window around it, within its
 *    mapping, is registered once and reused (UET_ERNIC_MR_CACHE=0 drops
 *    each registration when its transfers are done instead).  As with any
 *    registration cache, a buffer that is unmapped and mapped again at the
 *    same address must not be written from while the stale registration
 *    is cached.
 *  - No immediate data, no messages, no atomics, no target-side events.
 *  - Remote addresses are offsets from the start of the remote region.
 *  - uet_mr_disable() keeps the region reachable by peers until
 *    uet_mr_close(), because re-enabling cannot keep the key.
 *  - IPv4 peers only.
 *
 * Environment:
 *  UET_ERNIC_DEVICE     ibverbs device to use (default: the first ionic
 *                       one, see uet_ernic_device_match(); there is no
 *                       fallback to other devices)
 *  UET_ERNIC_GID_INDEX  GID index for the service QP's address (default 0)
 *  UET_ERNIC_MR_CACHE   0 to drop on-demand registrations after use
 *  UET_FORCE_RUDI       new endpoints use RUDI for idempotent RMA, as in the
 *                       reference library; uet_ep_setopt() overrides it
 */

#ifndef UET_ERNIC_H
#define UET_ERNIC_H

#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>

#include <rdma/fabric.h>
#include <rdma/fi_domain.h>
#include <rdma/fi_endpoint.h>
#include <rdma/fi_eq.h>

/* struct uet_addr, from the reference provider. */
#include "uet_addr.h"

/* libfabric 2 no longer defines it; the value is libfabric 1's. */
#ifndef FI_PROV_SPECIFIC
#define FI_PROV_SPECIFIC (1U << 31)
#endif

/*
 * The same values as uet_api.h, spelled the same: abi_check.c defines both,
 * and a macro may only be redefined token for token, white space included.
 */
/* clang-format off */
#define UET_DEF_JOB_ID  1
#define UET_JOB_ID_ANY  0xffffffff
#define UET_NULL_HANDLE NULL
#define UET_FLAGS_NONE  0
#define UET_MR_KEY_NONE                 ((uint64_t) 0)
#define UET_MR_KEY_IDEMPOTENT_SAFE      0x8000000000000000ULL
#define UET_OPT_FORCE_RUDI ((int)(FI_PROV_SPECIFIC | 1U))
#define UET_OPT_ABORT ((int)(FI_PROV_SPECIFIC | 2U))
#define UET_OPT_ABORT_OP ((int)(FI_PROV_SPECIFIC | 3U))
/* clang-format on */

typedef void *uet_handle_t;
typedef void *uet_domain_handle_t;
typedef void *uet_ep_handle_t;
typedef void *uet_cq_handle_t;
typedef void *uet_addr_handle_t;
typedef void *uet_mr_handle_t;

typedef void (*uet_eq_callback_t)(uet_handle_t handle,
                                  struct fi_eq_entry *eq_entry);
typedef void (*uet_eq_err_callback_t)(uet_handle_t handle,
                                      struct fi_eq_err_entry *eq_err_entry);

int uet_initialize(uet_handle_t *handle);
int uet_finalize(uet_handle_t handle);

int uet_domain(uet_handle_t handle, struct fid_fabric *fabric,
               struct fi_info *info, struct fid_domain *domain, void *context,
               uet_eq_callback_t eq_callback,
               uet_eq_err_callback_t eq_err_callback,
               uet_domain_handle_t *domain_handle);
int uet_domain_close(uet_domain_handle_t domain_handle);

int uet_mr_reg(uet_domain_handle_t domain_handle, const void *buf, size_t len,
               uint64_t access, uint64_t requested_key, uint64_t flags,
               void *context, uet_mr_handle_t *mr_handle);
uint64_t uet_mr_key(uet_mr_handle_t mr_handle);
/* A new key for the region, in @key and from uet_mr_key() (MR_REKEY): the
 * old key is dead when this returns, and the region keeps its pages and
 * binding.  -FI_ENOSYS from a device without UET_ERNIC_CAP_REKEY. */
int uet_mr_rekey(uet_mr_handle_t mr_handle, uint64_t *key);
int uet_ep_bind_mr(uet_ep_handle_t ep_handle, uet_mr_handle_t mr_handle,
                   uint64_t flags);
int uet_mr_enable(uet_mr_handle_t mr_handle);
int uet_mr_disable(uet_mr_handle_t mr_handle);
int uet_mr_close(uet_mr_handle_t mr_handle);

int uet_endpoint(uet_domain_handle_t domain_handle, struct fi_info *info,
                 struct fid_ep *ep, void *context, uet_ep_handle_t *ep_handle);
int uet_getname(uet_ep_handle_t ep_handle, struct uet_addr *uet_addr);
int uet_ep_bind_cq(uet_ep_handle_t ep_handle, struct fi_cq_attr *attr,
                   struct fid_cq *cq, uint64_t flags, void *context,
                   uet_cq_handle_t *cq_handle);
int uet_ep_enable(uet_ep_handle_t ep_handle);
int uet_ep_setopt(uet_ep_handle_t ep_handle, int level, int optname,
                  const void *optval, size_t optlen);
/* UET_OPT_ABORT: whether uet_ep_abort() can take transfers back. */
int uet_ep_getopt(uet_ep_handle_t ep_handle, int level, int optname,
                  void *optval, size_t *optlen);
/*
 * Discard what the endpoint has outstanding, ahead of uet_ep_close(), as in
 * the reference library (the libfabric provider calls it from fi_close):
 * the device takes the endpoint's transfers back with ABORT, sends nothing
 * more of them, and no completion is reported for them.  Returns 0 once
 * they are gone, or when there were none.
 *
 * When the device cannot take them back (older than ABI version 2, or
 * pds=sng: -FI_ENOSYS), or ABORT fails (another error), the library tears
 * itself down instead: it destroys its service QP, which makes the device
 * drop what it can and answer none of it, and reports an error.  The
 * endpoint can then be closed, but the instance is dead: every later call
 * that needs the device fails with -FI_EIO, and releasing things succeeds.
 */
int uet_ep_abort(uet_ep_handle_t ep_handle);
/*
 * Take back one transfer of the endpoint posted with @context: the first
 * one still in flight, if several were (call again for the next).  0 when
 * the device took it back: nothing of it goes on the wire again, and it
 * reports no completion.  -FI_ENOENT when none is in flight (one that
 * finished reports its completion as usual).  -FI_ENOSYS from a device
 * without UET_ERNIC_CAP_ABORT_OP; -FI_EBUSY when the device could not take
 * it out of its engine, and it may still land.  UET_OPT_ABORT_OP says
 * whether it works.
 */
int uet_ep_abort_op(uet_ep_handle_t ep_handle, void *context);
int uet_ep_close(uet_ep_handle_t ep_handle);
int uet_ep_progress(uet_ep_handle_t ep_handle);

ssize_t uet_cq_read(uet_cq_handle_t cq_handle, void *buf, size_t count);
ssize_t uet_cq_readerr(uet_cq_handle_t cq_handle, struct fi_cq_err_entry *buf);
int uet_cq_close(uet_cq_handle_t cq_handle);

int uet_av_insert(uet_domain_handle_t domain_handle, struct uet_addr *uet_addr,
                  uet_addr_handle_t *addr_handle);
int uet_av_remove(uet_addr_handle_t addr_handle);

ssize_t uet_write(uet_ep_handle_t ep_handle, uint32_t job_id, void *buf,
                  size_t len, uint64_t *data, uet_mr_handle_t mr_handle,
                  uet_addr_handle_t dst_addr_handle, uint64_t remote_mem_addr,
                  uint64_t remote_key, void *context);
ssize_t uet_read(uet_ep_handle_t ep_handle, uint32_t job_id, void *buf,
                 size_t len, uet_mr_handle_t mr_handle,
                 uet_addr_handle_t uet_addr_handle, uint64_t remote_mem_addr,
                 uint64_t remote_key, void *context);

/* ---- not in uet_api.h ------------------------------------------------- */

/* The PCI vendor ID of an ionic function, which an ernic device has too. */
#define UET_ERNIC_PCI_VENDOR 0x1dd8u

/*
 * Whether the ibverbs device @name can have an engine behind it: an ionic
 * device, by its name or, once udev has renamed it, by its PCI vendor ID.
 * This is how uet_initialize() picks a device when UET_ERNIC_DEVICE is not
 * set.
 */
bool uet_ernic_device_match(const char *name);

#endif /* UET_ERNIC_H */
