/*
 * fake_device_proto.h -- between the fake libibverbs and the fake device
 *
 * Copyright (c) Advanced Micro Devices, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: MIT
 *
 * The guest library's test runs the guest and the device in separate
 * processes, as a VM and its vfio-user server are: the guest's memory is a
 * memfd both map, and this socketpair protocol stands in for the ionic
 * rings. The fake libibverbs (fake_ibverbs.c) speaks the guest side, the
 * fake device (tests/uet_fake_device.c) the device side, which runs the
 * real UET command channel (uet_svc.c) and engine.
 */

#ifndef FAKE_DEVICE_PROTO_H
#define FAKE_DEVICE_PROTO_H

#include <stdint.h>

/* Guest physical address of byte 0 of the shared guest memory. */
#define FDEV_GPA_BASE UINT64_C(0x100000000)

enum fdev_type {
    FDEV_REG = 1,     /* guest -> device: an ionic MR, by lkey */
    FDEV_DEREG = 2,   /* guest -> device: an ionic MR is gone */
    FDEV_CMD = 3,     /* guest -> device: a SEND on a service QP */
    FDEV_QP_GONE = 4, /* guest -> device: a service QP was destroyed */
    FDEV_BYE = 5,     /* guest -> device: the device was closed */
    FDEV_WIRE = 6,    /* test -> device: lkey 1 loses every IP frame the
                       * engine sends, 0 stops (ARP still passes) */
    FDEV_HOLD = 7,    /* test -> device: keep the next reply with opcode
                       * lkey, and send it just before the command that
                       * arrives length commands later */
    FDEV_REPLY = 0x81 /* device -> guest: a reply capsule for a QP */
};

struct fdev_msg {
    uint32_t type;
    uint32_t qp;     /* CMD, QP_GONE, REPLY */
    uint32_t lkey;   /* REG, DEREG */
    uint32_t len;    /* bytes of data[] used */
    uint64_t offset; /* REG: where the region starts in guest memory */
    uint64_t length; /* REG: its length */
    uint8_t data[64];
};

#endif /* FAKE_DEVICE_PROTO_H */
