/*
 * uet_engine.c -- Ultra Ethernet Transport engine, as device firmware
 *
 * See uet_engine.h.  This file is the glue between ernic and the UEC
 * reference provider's ENABLE_VERBS=1 library (libuet_verbs): it turns the
 * engine configuration into the environment the provider reads, plugs the
 * wire in as a NIC shim, plugs region memory in as a DMA translator, and
 * keeps the table of regions, peers and in-flight operations the provider
 * leaves to its caller.
 *
 * Copyright (C) Advanced Micro Devices, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* The provider, built with ENABLE_VERBS=1. */
#include "uet_api.h"
#include "uet_addr.h"

#include "parse_int.h"
#include "uet_engine.h"
#include "uet_nic_ernic.h"

/* uet_progress() takes at most one received packet per endpoint, so a poll
 * keeps calling it while frames are queued, up to this many times. */
#define POLL_BUDGET 64u

/* Descriptors per endpoint; bounds the provider's in-flight messages. */
#define EP_QUEUE_DEPTH 64u

#define DEFAULT_JOB_ID       1u
#define DEFAULT_PID_ON_FEP   0u
#define DEFAULT_RES_INDEX    15u /* the reference test program's */
#define DEFAULT_INITIATOR_ID 16u
#define DEFAULT_MTU          1500u

#define MAX_JOB_ID 0xffffffu /* 24-bit SES field */

/* Region lengths and offsets are 64-bit on the wire and size_t inside the
 * provider. */
_Static_assert(SIZE_MAX >= UINT64_MAX, "size_t must hold a 64-bit length");
#define MAX_PID   0xfffu /* 12-bit SES field */
#define MAX_INDEX 0xfffu /* 12-bit SES field */

struct engine_mr {
    bool used;
    uet_mr_handle_t h;
};

struct engine_peer {
    bool used;
    uint16_t resource_index;
    /* uet_av_insert() keeps a pointer to this, so it lives here. */
    struct uet_addr addr;
    uet_addr_handle_t av;
};

struct engine_op {
    bool used;
    uint64_t cookie;
};

struct uet_engine {
    struct uet_engine_cfg cfg;
    struct uet_engine_wire wire;
    struct uet_engine_dma dma;

    struct uet_nic_ernic *nic;
    bool shim_registered;

    uet_handle_t uet;
    struct fi_info *info;
    uet_domain_handle_t dom;
    uet_ep_handle_t ep;
    uet_cq_handle_t tx_cq;
    uet_cq_handle_t rx_cq;
    struct fi_cq_attr cq_attr;
    bool rudi; /* what UET_OPT_FORCE_RUDI is set to on the endpoint */

    struct engine_mr mrs[UET_ENGINE_MAX_MRS];
    struct engine_peer peers[UET_ENGINE_MAX_PEERS];
    struct engine_op ops[UET_ENGINE_MAX_OPS];
    unsigned ops_in_flight;

    struct uet_engine_stats stats;
};

/* ------------------------------------------------------------------ */
/* Configuration                                                      */
/* ------------------------------------------------------------------ */

static void set_err(char *err, size_t errlen, const char *fmt, ...)
    __attribute__((format(printf, 3, 4)));

static void set_err(char *err, size_t errlen, const char *fmt, ...)
{
    if (err == NULL || errlen == 0)
        return;
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(err, errlen, fmt, ap);
    va_end(ap);
}

static bool parse_u32_range(const char *s, uint32_t lo, uint32_t hi,
                            uint32_t *out)
{
    char *end = NULL;
    unsigned long long v;

    if (s == NULL || *s == '\0' || *s == '-' || *s == '+')
        return false;
    errno = 0;
    v = strtoull(s, &end, 0);
    if (errno != 0 || end == s || *end != '\0' || v < lo || v > hi)
        return false;
    *out = (uint32_t)v;
    return true;
}

static bool parse_ipv4(const char *s, uint32_t *out)
{
    uint32_t v = 0;
    const char *p = s;

    for (int i = 0; i < 4; i++) {
        char part[4];
        size_t n = 0;
        uint32_t octet;

        while (*p >= '0' && *p <= '9' && n < sizeof(part) - 1)
            part[n++] = *p++;
        part[n] = '\0';
        if (n == 0 || (n > 1 && part[0] == '0') ||
            !parse_u32_range(part, 0, 255, &octet))
            return false;
        v = (v << 8) | octet;
        if (i < 3 && *p++ != '.')
            return false;
    }
    if (*p != '\0')
        return false;
    *out = v;
    return true;
}

static int hexval(char c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}

static bool parse_mac(const char *s, uint8_t mac[6])
{
    if (strlen(s) != 17)
        return false;
    for (unsigned i = 0; i < 6; i++) {
        int hi = hexval(s[i * 3]);
        int lo = hexval(s[i * 3 + 1]);

        if (hi < 0 || lo < 0 || (i < 5 && s[i * 3 + 2] != ':'))
            return false;
        mac[i] = (uint8_t)((hi << 4) | lo);
    }
    return true;
}

void uet_engine_cfg_defaults(struct uet_engine_cfg *cfg)
{
    memset(cfg, 0, sizeof(*cfg));
    cfg->job_id = DEFAULT_JOB_ID;
    cfg->pid_on_fep = DEFAULT_PID_ON_FEP;
    cfg->resource_index = DEFAULT_RES_INDEX;
    cfg->initiator_id = DEFAULT_INITIATOR_ID;
    cfg->pds = UET_ENGINE_PDS_FULL;
    cfg->sec = UET_ENGINE_SEC_NONE;
    cfg->mtu = DEFAULT_MTU;
}

static bool parse_one(struct uet_engine_cfg *cfg, const char *key,
                      const char *val, char *err, size_t errlen)
{
    uint32_t v;

    if (strcmp(key, "ip") == 0) {
        uint32_t first;

        if (!parse_ipv4(val, &v)) {
            set_err(err, errlen, "bad IPv4 address '%s'", val);
            return false;
        }
        first = v >> 24;
        if (v == 0 || first == 0 || first == 127 || first >= 224) {
            set_err(err, errlen, "'%s' is not a unicast host address", val);
            return false;
        }
        cfg->ip = v;
    } else if (strcmp(key, "mac") == 0) {
        static const uint8_t zero[6] = {0};

        if (!parse_mac(val, cfg->mac) || (cfg->mac[0] & 1u) != 0 ||
            memcmp(cfg->mac, zero, 6) == 0) {
            set_err(err, errlen, "bad unicast MAC address '%s'", val);
            return false;
        }
        cfg->mac_set = true;
    } else if (strcmp(key, "job") == 0) {
        if (!parse_u32_range(val, 0, MAX_JOB_ID, &cfg->job_id)) {
            set_err(err, errlen, "job must be 0..%u (got '%s')", MAX_JOB_ID,
                    val);
            return false;
        }
    } else if (strcmp(key, "pid") == 0) {
        if (!parse_u32_range(val, 0, MAX_PID, &v)) {
            set_err(err, errlen, "pid must be 0..%u (got '%s')", MAX_PID, val);
            return false;
        }
        cfg->pid_on_fep = (uint16_t)v;
    } else if (strcmp(key, "index") == 0) {
        if (!parse_u32_range(val, 0, MAX_INDEX, &v)) {
            set_err(err, errlen, "index must be 0..%u (got '%s')", MAX_INDEX,
                    val);
            return false;
        }
        cfg->resource_index = (uint16_t)v;
    } else if (strcmp(key, "initiator") == 0) {
        if (!parse_u32_range(val, 0, UINT32_MAX, &cfg->initiator_id)) {
            set_err(err, errlen, "bad initiator '%s'", val);
            return false;
        }
    } else if (strcmp(key, "pds") == 0) {
        if (strcmp(val, "pds") == 0) {
            cfg->pds = UET_ENGINE_PDS_FULL;
        } else if (strcmp(val, "sng") == 0) {
            cfg->pds = UET_ENGINE_PDS_SNG;
        } else {
            set_err(err, errlen, "pds must be pds or sng (got '%s')", val);
            return false;
        }
    } else if (strcmp(key, "sec") == 0) {
        if (strcmp(val, "none") == 0) {
            cfg->sec = UET_ENGINE_SEC_NONE;
        } else if (strcmp(val, "direct") == 0) {
            cfg->sec = UET_ENGINE_SEC_DIRECT;
        } else if (strcmp(val, "cluster") == 0) {
            cfg->sec = UET_ENGINE_SEC_CLUSTER;
        } else {
            set_err(err, errlen,
                    "sec must be none, direct or cluster (got '%s')", val);
            return false;
        }
    } else if (strcmp(key, "ssi") == 0) {
        if (!parse_u32_range(val, 1, UINT32_MAX, &cfg->ssi)) {
            set_err(err, errlen, "ssi must be 1..%u (got '%s')", UINT32_MAX,
                    val);
            return false;
        }
    } else if (strcmp(key, "rto") == 0) {
        if (!parse_u32_range(val, 1, 60000, &cfg->rto_ms)) {
            set_err(err, errlen, "rto must be 1..60000 ms (got '%s')", val);
            return false;
        }
    } else if (strcmp(key, "retries") == 0) {
        if (!parse_u32_range(val, 1, 1000, &cfg->max_retries)) {
            set_err(err, errlen, "retries must be 1..1000 (got '%s')", val);
            return false;
        }
    } else if (strcmp(key, "drop") == 0) {
        if (!parse_u32_range(val, 0, 9999, &cfg->drop_thresh)) {
            set_err(err, errlen, "drop must be 0..9999 (got '%s')", val);
            return false;
        }
    } else if (strcmp(key, "mtu") == 0) {
        if (!parse_u32_range(val, 576, 9000, &v)) {
            set_err(err, errlen, "mtu must be 576..9000 (got '%s')", val);
            return false;
        }
        cfg->mtu = (uint16_t)v;
    } else {
        set_err(err, errlen, "unknown option '%s'", key);
        return false;
    }
    return true;
}

bool uet_engine_cfg_parse(struct uet_engine_cfg *cfg, const char *opts,
                          char *err, size_t errlen)
{
    if (opts != NULL && *opts != '\0') {
        char *dup = strdup(opts);
        if (dup == NULL) {
            set_err(err, errlen, "out of memory");
            return false;
        }

        bool ok = true;
        char *save = NULL;
        for (char *tok = strtok_r(dup, ",", &save); tok != NULL && ok;
             tok = strtok_r(NULL, ",", &save)) {
            /* strcspn rather than strchr, which glibc makes a macro */
            char *eq = tok + strcspn(tok, "=");
            if (*eq == '\0') {
                set_err(err, errlen, "option '%s' is not key=value", tok);
                ok = false;
                break;
            }
            *eq = '\0';
            ok = parse_one(cfg, tok, eq + 1, err, errlen);
        }
        free(dup);
        if (!ok)
            return false;
    }

    if (cfg->ip == 0) {
        set_err(err, errlen, "ip= is required (the engine's own address)");
        return false;
    }
    if (cfg->sec != UET_ENGINE_SEC_NONE && cfg->pds != UET_ENGINE_PDS_FULL) {
        set_err(err, errlen, "sec= needs pds=pds");
        return false;
    }
    return true;
}

static void engine_mac(const struct uet_engine_cfg *cfg, uint8_t mac[6])
{
    if (cfg->mac_set) {
        memcpy(mac, cfg->mac, 6);
        return;
    }
    /* 02 (locally administered) 55 ('U') and the address, so every
     * instance on a segment gets a distinct, predictable MAC. */
    mac[0] = 0x02;
    mac[1] = 0x55;
    mac[2] = (uint8_t)(cfg->ip >> 24);
    mac[3] = (uint8_t)(cfg->ip >> 16);
    mac[4] = (uint8_t)(cfg->ip >> 8);
    mac[5] = (uint8_t)cfg->ip;
}

static const char *pds_name(enum uet_engine_pds pds)
{
    switch (pds) {
    case UET_ENGINE_PDS_SNG:
        return "sng";
    case UET_ENGINE_PDS_FULL:
    default:
        return "pds";
    }
}

static const char *sec_name(enum uet_engine_sec sec)
{
    switch (sec) {
    case UET_ENGINE_SEC_DIRECT:
        return "direct";
    case UET_ENGINE_SEC_CLUSTER:
        return "cluster";
    case UET_ENGINE_SEC_NONE:
    default:
        return "none";
    }
}

void uet_engine_cfg_describe(const struct uet_engine_cfg *cfg, char *buf,
                             size_t len)
{
    uint8_t mac[6];

    engine_mac(cfg, mac);
    snprintf(buf, len,
             "ip %u.%u.%u.%u mac %02x:%02x:%02x:%02x:%02x:%02x job %u pid %u "
             "index %u pds %s sec %s mtu %u",
             (unsigned)(cfg->ip >> 24), (unsigned)((cfg->ip >> 16) & 0xffu),
             (unsigned)((cfg->ip >> 8) & 0xffu), (unsigned)(cfg->ip & 0xffu),
             (unsigned)mac[0], (unsigned)mac[1], (unsigned)mac[2],
             (unsigned)mac[3], (unsigned)mac[4], (unsigned)mac[5],
             (unsigned)cfg->job_id, (unsigned)cfg->pid_on_fep,
             (unsigned)cfg->resource_index, pds_name(cfg->pds),
             sec_name(cfg->sec), (unsigned)cfg->mtu);
}

/*
 * The provider reads its configuration from the environment, some of it on
 * every packet (UET_SEC_MODE), so what is set here has to stay set.  The
 * variables that decide what the engine is are owned outright: set from the
 * configuration or removed.  Tuning knobs the configuration leaves at 0 are
 * not touched, so the provider's own variables still work for experiments.
 */
static bool set_env_u32(const char *name, uint32_t v, char *err, size_t errlen)
{
    char buf[16];

    snprintf(buf, sizeof(buf), "%u", (unsigned)v);
    if (setenv(name, buf, 1) != 0) {
        set_err(err, errlen, "setenv %s: %s", name, strerror(errno));
        return false;
    }
    return true;
}

static bool engine_set_env(const struct uet_engine_cfg *cfg, char *err,
                           size_t errlen)
{
    /* The impairment shim transmits from a thread of its own; every frame
     * must leave from the caller's thread.  The client/server TSS mode and
     * the provider-wide delivery overrides are not engine features. */
    static const char *const owned_unset[] = {
        "UET_IMPAIRMENT_SHIM", "UET_FORCE_RUDI",     "UET_FORCE_UUD",
        "UET_SEC_SERVER",      "UET_SEC_CLIENT_SSI",
    };

    for (size_t i = 0; i < sizeof(owned_unset) / sizeof(owned_unset[0]); i++)
        unsetenv(owned_unset[i]);

    if (setenv("UET_NIC_SHIM", UET_NIC_ERNIC_NAME, 1) != 0 ||
        setenv("UET_PDS", pds_name(cfg->pds), 1) != 0) {
        set_err(err, errlen, "setenv: %s", strerror(errno));
        return false;
    }

    if (cfg->sec == UET_ENGINE_SEC_NONE) {
        unsetenv("UET_SEC_MODE");
        unsetenv("UET_SEC_SSI");
    } else {
        if (setenv("UET_SEC_MODE", sec_name(cfg->sec), 1) != 0) {
            set_err(err, errlen, "setenv: %s", strerror(errno));
            return false;
        }
        if (cfg->ssi != 0) {
            if (!set_env_u32("UET_SEC_SSI", cfg->ssi, err, errlen))
                return false;
        } else {
            unsetenv("UET_SEC_SSI");
        }
    }

    if (cfg->rto_ms != 0 &&
        !set_env_u32("UET_PDS_TX_TIMEOUT", cfg->rto_ms, err, errlen))
        return false;
    if (cfg->max_retries != 0 &&
        !set_env_u32("UET_PDS_MAX_TX_RETRIES", cfg->max_retries, err, errlen))
        return false;
    if (cfg->drop_thresh != 0 &&
        !set_env_u32("UET_PKT_DROP_THRESH", cfg->drop_thresh, err, errlen))
        return false;
    return true;
}

/* ------------------------------------------------------------------ */
/* Plumbing between the provider and the owner                        */
/* ------------------------------------------------------------------ */

static uint64_t now_ms(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

static int engine_wire_tx(void *ctx, const void *frame, size_t len)
{
    struct uet_engine *e = ctx;

    return e->wire.tx(e->wire.ctx, frame, len);
}

static void *engine_dma_translate(void *ctx, uet_dma_addr_t addr, size_t len,
                                  bool write)
{
    struct uet_engine *e = ctx;
    void *p = e->dma.map(e->dma.ctx, addr, len, write);

    if (p == NULL)
        e->stats.dma_faults++;
    else if (write)
        e->stats.dma_write_maps++;
    else
        e->stats.dma_read_maps++;
    return p;
}

/* Fabric errnos are errnos for every value the provider returns here. */
static int fi_to_errno(ssize_t rc)
{
    if (rc >= 0)
        return 0;
    if (rc < -4095)
        return -EIO;
    return (int)rc;
}

static int set_rudi(struct uet_engine *e, bool rudi)
{
    if (e->rudi == rudi)
        return 0;

    int rc = uet_ep_setopt(e->ep, FI_OPT_ENDPOINT, UET_OPT_FORCE_RUDI, &rudi,
                           sizeof(rudi));
    if (rc != 0)
        return fi_to_errno(rc);
    e->rudi = rudi;
    return 0;
}

/* ------------------------------------------------------------------ */
/* Lifecycle                                                          */
/* ------------------------------------------------------------------ */

struct uet_engine *uet_engine_create(const struct uet_engine_cfg *cfg,
                                     const struct uet_engine_wire *wire,
                                     const struct uet_engine_dma *dma,
                                     char *err, size_t errlen)
{
    struct uet_engine *e;
    struct uet_nic_ernic_cfg ncfg;
    struct uet_addr node;
    int rc;

    if (cfg == NULL || wire == NULL || wire->tx == NULL || cfg->ip == 0) {
        set_err(err, errlen, "incomplete engine configuration");
        return NULL;
    }

    e = calloc(1, sizeof(*e));
    if (e == NULL) {
        set_err(err, errlen, "out of memory");
        return NULL;
    }
    e->cfg = *cfg;
    e->wire = *wire;
    if (dma != NULL)
        e->dma = *dma;

    memset(&ncfg, 0, sizeof(ncfg));
    ncfg.ip = cfg->ip;
    engine_mac(cfg, ncfg.mac);
    ncfg.mtu = cfg->mtu;
    ncfg.name = "ernic-uet";
    ncfg.tx = engine_wire_tx;
    ncfg.tx_ctx = e;
    e->nic = uet_nic_ernic_create(&ncfg);
    if (e->nic == NULL) {
        set_err(err, errlen, "cannot create the wire port");
        goto fail;
    }

    if (!engine_set_env(cfg, err, errlen))
        goto fail;

    rc = uet_nic_ernic_register(e->nic);
    if (rc != 0) {
        set_err(err, errlen, "cannot register the NIC shim: %s", strerror(-rc));
        goto fail;
    }
    e->shim_registered = true;

    rc = uet_initialize(&e->uet);
    if (rc != 0) {
        set_err(err, errlen, "uet_initialize: %s", strerror(-rc));
        e->uet = NULL;
        goto fail;
    }

    if (e->dma.map != NULL) {
        rc = uet_set_dma_translate(e->uet, engine_dma_translate, e);
        if (rc != 0) {
            set_err(err, errlen, "uet_set_dma_translate: %s", strerror(-rc));
            goto fail;
        }
    }

    /* uet_domain() and uet_endpoint() read the fi_info even in a verbs
     * build, so it comes from uet_getinfo() like any other caller's. */
    memset(&node, 0, sizeof(node));
    node.flags = UET_ADDR_IPV4;
    rc = uet_getinfo(e->uet, &node, NULL, &e->info);
    if (rc != 0) {
        set_err(err, errlen, "uet_getinfo: %s", strerror(-rc));
        e->info = NULL;
        goto fail;
    }
    e->info->domain_attr->mr_mode |= FI_MR_PROV_KEY;
    e->info->domain_attr->mr_cnt = UET_ENGINE_MAX_MRS;
    e->info->rx_attr->size = EP_QUEUE_DEPTH;
    e->info->tx_attr->size = EP_QUEUE_DEPTH;
    /* No ordering, so RMA goes RUD rather than ROD. */
    e->info->tx_attr->msg_order = FI_ORDER_NONE;

    rc = uet_domain(e->uet, NULL, e->info, NULL, e, NULL, NULL, &e->dom);
    if (rc != 0) {
        set_err(err, errlen, "uet_domain: %s", strerror(-rc));
        e->dom = NULL;
        goto fail;
    }

    rc = uet_endpoint(e->dom, e->info, NULL, e, &e->ep, cfg->pid_on_fep,
                      cfg->resource_index, cfg->initiator_id, cfg->job_id,
                      false, false);
    if (rc != 0) {
        set_err(err, errlen, "uet_endpoint: %s", strerror(-rc));
        e->ep = NULL;
        goto fail;
    }

    e->cq_attr.format = FI_CQ_FORMAT_CONTEXT;
    e->cq_attr.size = EP_QUEUE_DEPTH * 2u;
    rc = uet_ep_bind_cq(e->ep, &e->cq_attr, NULL, FI_SEND, e, &e->tx_cq);
    if (rc == 0)
        rc = uet_ep_bind_cq(e->ep, &e->cq_attr, NULL, FI_RECV, e, &e->rx_cq);
    if (rc == 0)
        rc = uet_ep_enable(e->ep);
    if (rc != 0) {
        set_err(err, errlen, "endpoint setup: %s", strerror(-rc));
        goto fail;
    }

    return e;

fail:
    uet_engine_destroy(e);
    return NULL;
}

void uet_engine_destroy(struct uet_engine *e)
{
    if (e == NULL)
        return;

    for (unsigned i = 0; i < UET_ENGINE_MAX_MRS; i++) {
        if (e->mrs[i].used)
            (void)uet_engine_mr_dereg(e, i);
    }
    for (unsigned i = 0; i < UET_ENGINE_MAX_PEERS; i++) {
        if (e->peers[i].used)
            (void)uet_av_remove(e->peers[i].av);
    }
    if (e->ep != NULL)
        (void)uet_ep_close(e->ep);
    if (e->dom != NULL)
        (void)uet_domain_close(e->dom);
    /* Finalizing the instance calls back into the shim, so the shim goes
     * after it. */
    if (e->uet != NULL)
        (void)uet_finalize(e->uet);
    if (e->info != NULL)
        uet_verbs_fi_freeinfo(e->info);
    if (e->shim_registered)
        uet_nic_ernic_unregister();
    uet_nic_ernic_destroy(e->nic);
    free(e);
}

/* ------------------------------------------------------------------ */
/* Datapath                                                           */
/* ------------------------------------------------------------------ */

bool uet_engine_rx_frame(struct uet_engine *e, const void *frame, size_t len)
{
    return e != NULL && uet_nic_ernic_rx_frame(e->nic, frame, len);
}

/* Target-side completions carry nothing the engine reports (there are no
 * target-side events), but they hold descriptors until read. */
static void drain_rx_cq(struct uet_engine *e)
{
    struct fi_cq_entry ent[8];
    struct fi_cq_err_entry err;
    ssize_t n;

    do {
        n = uet_cq_read(e->rx_cq, ent, sizeof(ent) / sizeof(ent[0]));
        if (n == -FI_EAVAIL)
            n = uet_cq_readerr(e->rx_cq, &err);
    } while (n > 0);
}

void uet_engine_poll(struct uet_engine *e)
{
    if (e == NULL)
        return;

    uet_nic_ernic_tick(e->nic, now_ms());

    for (unsigned i = 0; i < POLL_BUDGET; i++) {
        (void)uet_progress(e->dom);
        if (!uet_nic_ernic_rx_pending(e->nic))
            break;
    }

    drain_rx_cq(e);
}

bool uet_engine_has_work(const struct uet_engine *e)
{
    return e != NULL &&
           (uet_nic_ernic_rx_pending(e->nic) || e->ops_in_flight > 0);
}

int uet_engine_mr_reg(struct uet_engine *e, const struct uet_engine_mr_desc *d,
                      uint32_t *mr, uint64_t *rkey)
{
    unsigned slot;
    uint64_t access = FI_READ | FI_WRITE;
    uet_mr_handle_t h;
    int rc;

    if (e == NULL || d == NULL || mr == NULL || rkey == NULL)
        return -EINVAL;
    if (d->level > UET_PBL_LEVEL_2 || d->len == 0)
        return -EINVAL;

    for (slot = 0; slot < UET_ENGINE_MAX_MRS; slot++) {
        if (!e->mrs[slot].used)
            break;
    }
    if (slot == UET_ENGINE_MAX_MRS)
        return -ENOSPC;

    if (d->remote_read)
        access |= FI_REMOTE_READ;
    if (d->remote_write)
        access |= FI_REMOTE_WRITE;

    /* The provider assigns the key and keeps the IDEMPOTENT_SAFE bit asked
     * for here.  base_va 0 makes addresses within the region offsets. */
    rc = uet_mr_reg_pbl(
        e->dom, d->root, d->page_size, (uet_pbl_level_t)d->level,
        d->page_offset, 0, (size_t)d->len, access,
        d->idempotent_safe ? UET_MR_KEY_IDEMPOTENT_SAFE : UET_MR_KEY_NONE,
        UET_FLAGS_NONE, NULL, &h);
    if (rc != 0)
        return fi_to_errno(rc);

    rc = uet_ep_bind_mr(e->ep, h, UET_FLAGS_NONE);
    if (rc == 0)
        rc = uet_mr_enable(h);
    if (rc != 0) {
        (void)uet_mr_close(h);
        return fi_to_errno(rc);
    }

    e->mrs[slot].used = true;
    e->mrs[slot].h = h;
    *mr = slot;
    *rkey = uet_mr_key(h);
    return 0;
}

int uet_engine_mr_dereg(struct uet_engine *e, uint32_t mr)
{
    int rc;

    if (e == NULL || mr >= UET_ENGINE_MAX_MRS || !e->mrs[mr].used)
        return -EINVAL;

    rc = uet_mr_disable(e->mrs[mr].h);
    if (rc == 0)
        rc = uet_mr_close(e->mrs[mr].h);
    if (rc != 0)
        return fi_to_errno(rc);
    e->mrs[mr].used = false;
    return 0;
}

int uet_engine_peer_add(struct uet_engine *e, uint32_t ip, uint16_t pid_on_fep,
                        uint16_t resource_index, uint32_t *peer)
{
    unsigned slot;
    struct engine_peer *p;
    int rc;

    if (e == NULL || peer == NULL || ip == 0 || pid_on_fep > MAX_PID ||
        resource_index > MAX_INDEX)
        return -EINVAL;

    for (slot = 0; slot < UET_ENGINE_MAX_PEERS; slot++) {
        if (!e->peers[slot].used)
            break;
    }
    if (slot == UET_ENGINE_MAX_PEERS)
        return -ENOSPC;

    p = &e->peers[slot];
    memset(p, 0, sizeof(*p));
    p->resource_index = resource_index;
    p->addr.ver = UET_ADDR_VERSION;
    p->addr.flags = UET_ADDR_FEP_CAP_V | UET_ADDR_FA_V | UET_ADDR_PID_ON_FEP_V |
                    UET_ADDR_INDEX_V | UET_ADDR_RELATIVE_MODE | UET_ADDR_IPV4 |
                    UET_ADDR_BIG_MSG_SIZE;
    /* Peers are other engines, which take RUDI (the HPC profile). */
    p->addr.fep_cap = UET_FEP_CAP_AI_FULL | UET_FEP_CAP_HPC;
    p->addr.fa.v4 = ip;
    p->addr.pid_on_fep = pid_on_fep;
    p->addr.start_index = resource_index;
    p->addr.num_indices = 1;

    /* Starts ARP for the peer; the address is usable once it answers. */
    rc = uet_av_insert(e->dom, &p->addr, &p->av);
    if (rc != 0)
        return fi_to_errno(rc);

    p->used = true;
    *peer = slot;
    return 0;
}

int uet_engine_peer_remove(struct uet_engine *e, uint32_t peer)
{
    int rc;

    if (e == NULL || peer >= UET_ENGINE_MAX_PEERS || !e->peers[peer].used)
        return -EINVAL;
    rc = uet_av_remove(e->peers[peer].av);
    if (rc != 0)
        return fi_to_errno(rc);
    e->peers[peer].used = false;
    return 0;
}

int uet_engine_post_write(struct uet_engine *e,
                          const struct uet_engine_write *w)
{
    unsigned slot;
    struct uet_mr_seg seg;
    struct engine_peer *p;
    ssize_t rc;
    int erc;

    if (e == NULL || w == NULL || w->peer >= UET_ENGINE_MAX_PEERS ||
        !e->peers[w->peer].used || w->mr >= UET_ENGINE_MAX_MRS ||
        !e->mrs[w->mr].used || w->len == 0)
        return -EINVAL;

    for (slot = 0; slot < UET_ENGINE_MAX_OPS; slot++) {
        if (!e->ops[slot].used)
            break;
    }
    if (slot == UET_ENGINE_MAX_OPS)
        return -EAGAIN;

    p = &e->peers[w->peer];
    seg.mr = e->mrs[w->mr].h;
    seg.addr = w->offset;
    seg.len = (size_t)w->len;

    /* The endpoint's RUDI setting is read when the operation is posted,
     * which makes it a per-operation choice here. */
    erc = set_rudi(e, w->rudi);
    if (erc != 0)
        return erc;

    rc =
        uet_writeseg(e->ep, e->cfg.job_id, &seg, 1, NULL, p->av, w->remote_addr,
                     w->rkey, &e->ops[slot], p->resource_index);
    if (rc != 0)
        return fi_to_errno(rc);

    e->ops[slot].used = true;
    e->ops[slot].cookie = w->cookie;
    e->ops_in_flight++;
    e->stats.ops_posted++;
    return 0;
}

/* The op_context the provider hands back, if it is one of ours. */
static struct engine_op *op_of(struct uet_engine *e, void *ctx)
{
    for (unsigned i = 0; i < UET_ENGINE_MAX_OPS; i++) {
        if (ctx == &e->ops[i] && e->ops[i].used)
            return &e->ops[i];
    }
    return NULL;
}

static bool comp_add(struct uet_engine *e, void *ctx, int status,
                     struct uet_engine_comp *out)
{
    struct engine_op *op = op_of(e, ctx);

    if (op == NULL)
        return false;
    out->cookie = op->cookie;
    out->status = status;
    op->used = false;
    e->ops_in_flight--;
    if (status == 0)
        e->stats.ops_completed++;
    else
        e->stats.ops_failed++;
    return true;
}

size_t uet_engine_poll_comp(struct uet_engine *e, struct uet_engine_comp *out,
                            size_t max)
{
    size_t got = 0;

    if (e == NULL || out == NULL)
        return 0;

    while (got < max) {
        struct fi_cq_entry ent;
        ssize_t n = uet_cq_read(e->tx_cq, &ent, 1);

        if (n == 1) {
            if (comp_add(e, ent.op_context, 0, &out[got]))
                got++;
            continue;
        }
        if (n == -FI_EAVAIL) {
            struct fi_cq_err_entry err;

            memset(&err, 0, sizeof(err));
            if (uet_cq_readerr(e->tx_cq, &err) != 1)
                break;
            int status = err.err > 0 && err.err <= 4095 ? -err.err : -EIO;
            if (comp_add(e, err.op_context, status, &out[got]))
                got++;
            continue;
        }
        break;
    }
    return got;
}

void uet_engine_get_stats(const struct uet_engine *e,
                          struct uet_engine_stats *out)
{
    struct uet_nic_ernic_stats ns;

    if (e == NULL || out == NULL)
        return;

    *out = e->stats;
    uet_nic_ernic_get_stats(e->nic, &ns);
    out->rx_frames = ns.rx_frames;
    out->rx_dropped = ns.rx_dropped;
    out->tx_frames = ns.tx_frames;
    out->tx_dropped = ns.tx_dropped;
    out->arp_requests = ns.arp_requests;
    out->arp_replies = ns.arp_replies;
    out->nh_pending = ns.nh_pending;
}
