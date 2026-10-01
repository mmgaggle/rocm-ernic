/*
 * abi_check.c -- uet_ernic.h against the reference provider's uet_api.h
 *
 * Copyright (c) Advanced Micro Devices, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: MIT
 *
 * Compiled, never linked: with both headers in one translation unit the
 * compiler rejects any prototype in uet_ernic.h that has drifted from the
 * reference's ENABLE_VERBS=0 declaration, and -Werror rejects any constant
 * defined differently. It builds against the libfabric headers bundled with
 * the reference, because uet_api.h needs their internals.
 */

#include "uet_api.h"
#include "uet_ernic.h"
