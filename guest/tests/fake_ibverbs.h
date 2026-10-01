/*
 * fake_ibverbs.h -- the parts of libibverbs libuet_ernic uses, faked
 *
 * Copyright (c) Advanced Micro Devices, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef FAKE_IBVERBS_H
#define FAKE_IBVERBS_H

#include <stddef.h>
#include <stdint.h>

/*
 * Point the fake at its device (a socket speaking fake_device_proto.h) and
 * at the guest memory both share.  Memory registrations must lie in it.
 */
void fake_ibv_attach(int chan_fd, void *mem, size_t mem_len);

struct fake_ibv_stats {
    uint64_t sends;   /* capsules sent to the device */
    uint64_t replies; /* capsules received from it */
    uint64_t mr_regs;
    uint64_t mr_deregs;
    uint64_t qp_destroys;
    uint64_t bad_sends; /* SENDs refused: QP not connected to the engine */
};

void fake_ibv_get_stats(struct fake_ibv_stats *out);

#endif /* FAKE_IBVERBS_H */
