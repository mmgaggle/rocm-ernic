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
#include "uet_payload.h"

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
#define DEFAULT_MTU          1500u /* when neither mtu= nor the wire says */
#define MIN_MTU              576u
#define MAX_MTU              9000u

#define MAX_JOB_ID 0xffffffu /* 24-bit SES field */

/* Region lengths and offsets are 64-bit on the wire and size_t inside the
 * provider. */
_Static_assert(SIZE_MAX >= UINT64_MAX, "size_t must hold a 64-bit length");
#define MAX_PID   0xfffu /* 12-bit SES field */
#define MAX_INDEX 0xfffu /* 12-bit SES field */

/*
 * Page lists from uet_engine_mr_reg_pages() live in the engine and are
 * handed to the provider as DMA addresses in a window no guest memory can
 * occupy: WINDOW_BASE, plus the region's slot in bits 32 and up, plus the
 * byte offset into its list.  The translator serves that window itself.
 */
#define WINDOW_BASE  UINT64_C(0xffff000000000000)
#define WINDOW_SHIFT 32u

#define DEFAULT_QUARANTINE_MS 6000u

struct engine_mr {
    bool used;
    uet_mr_handle_t h;
    uint64_t *dir; /* engine-owned page list, or NULL */
    uint32_t ndir; /* entries in it */
    bool revoked;  /* the page list is no longer served */
    bool closing;  /* deregistered: close once idle and quarantined */
    uint32_t refs; /* operations in flight that use it */
    uint64_t close_after_ms;
};

struct engine_peer {
    bool used;
    bool removing; /* remove once no operation uses it */
    uint32_t refs;
    uint16_t resource_index;
    /* uet_av_insert() keeps a pointer to this, so it lives here. */
    struct uet_addr addr;
    uet_addr_handle_t av;
};

struct engine_op {
    bool used;
    uint64_t cookie;
    uint32_t mr;
    uint32_t peer;
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
    struct uet_wire_info wire_info; /* what the provider settled on */

    struct engine_mr mrs[UET_ENGINE_MAX_MRS];
    struct engine_peer peers[UET_ENGINE_MAX_PEERS];
    struct engine_op ops[UET_ENGINE_MAX_OPS];
    unsigned ops_in_flight;
    unsigned closing; /* regions and peers waiting to be released */

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
    cfg->mtu = 0;
    cfg->encap = UET_ENGINE_ENCAP_UDP;
    cfg->udp_port = UET_ENGINE_UDP_PORT;
    cfg->ipproto = UET_ENGINE_IPPROTO;
    cfg->payload = 0;
    cfg->mr_quarantine_ms = DEFAULT_QUARANTINE_MS;
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
    } else if (strcmp(key, "window") == 0) {
        if (!parse_u32_range(val, 128, 32640, &cfg->window) ||
            cfg->window % 128u != 0) {
            set_err(err, errlen,
                    "window must be a multiple of 128 up to 32640 packets "
                    "(got '%s')",
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
        if (!parse_u32_range(val, MIN_MTU, MAX_MTU, &v)) {
            set_err(err, errlen, "mtu must be %u..%u (got '%s')", MIN_MTU,
                    MAX_MTU, val);
            return false;
        }
        cfg->mtu = (uint16_t)v;
    } else if (strcmp(key, "encap") == 0) {
        if (strcmp(val, "udp") == 0) {
            cfg->encap = UET_ENGINE_ENCAP_UDP;
        } else if (strcmp(val, "ip") == 0) {
            cfg->encap = UET_ENGINE_ENCAP_IP;
        } else {
            set_err(err, errlen, "encap must be udp or ip (got '%s')", val);
            return false;
        }
    } else if (strcmp(key, "port") == 0) {
        if (!parse_u32_range(val, 1, 65535, &v)) {
            set_err(err, errlen, "port must be 1..65535 (got '%s')", val);
            return false;
        }
        cfg->udp_port = (uint16_t)v;
    } else if (strcmp(key, "proto") == 0) {
        /* Not UDP or TCP: the filter would take the guest's traffic.
         * Not ICMP: the engine answers pings with it. */
        if (!parse_u32_range(val, 2, 255, &v) || v == 6 || v == 17) {
            set_err(err, errlen,
                    "proto must be 2..255 and not TCP or UDP (got '%s')", val);
            return false;
        }
        cfg->ipproto = (uint8_t)v;
    } else if (strcmp(key, "wire") == 0) {
        if (strcmp(val, "tap") == 0) {
            cfg->wire = UET_ENGINE_WIRE_TAP;
        } else if (strcmp(val, "dpdk") == 0) {
            cfg->wire = UET_ENGINE_WIRE_DPDK;
        } else {
            set_err(err, errlen, "wire must be tap or dpdk (got '%s')", val);
            return false;
        }
    } else if (strcmp(key, "dpdk-dev") == 0 || strcmp(key, "dpdk-dma") == 0 ||
               strcmp(key, "dpdk-eal") == 0) {
        bool eal = strcmp(key, "dpdk-eal") == 0;
        char *dst = eal                            ? cfg->dpdk_eal
                    : strcmp(key, "dpdk-dev") == 0 ? cfg->dpdk_dev
                                                   : cfg->dpdk_dma;
        /* ';' cannot be confused with the option separator: it stands for
         * ',' in devargs and for ' ' between EAL arguments. */
        char sub = eal ? ' ' : ',';
        size_t n = strlen(val);

        if (n == 0 || n >= UET_ENGINE_DPDK_ARG_MAX) {
            set_err(err, errlen, "%s must be 1..%u characters", key,
                    UET_ENGINE_DPDK_ARG_MAX - 1u);
            return false;
        }
        for (size_t i = 0; i <= n; i++)
            dst[i] = val[i] == ';' ? sub : val[i];
    } else if (strcmp(key, "dpdk-map") == 0) {
        if (strcmp(val, "auto") == 0) {
            cfg->dpdk_map = UET_ENGINE_DPDK_MAP_AUTO;
        } else if (strcmp(val, "on") == 0) {
            cfg->dpdk_map = UET_ENGINE_DPDK_MAP_ON;
        } else if (strcmp(val, "off") == 0) {
            cfg->dpdk_map = UET_ENGINE_DPDK_MAP_OFF;
        } else {
            set_err(err, errlen, "dpdk-map must be auto, on or off (got '%s')",
                    val);
            return false;
        }
    } else if (strcmp(key, "dpdk-split") == 0) {
        if (strcmp(val, "on") == 0) {
            cfg->dpdk_split = true;
        } else if (strcmp(val, "off") == 0) {
            cfg->dpdk_split = false;
        } else {
            set_err(err, errlen, "dpdk-split must be on or off (got '%s')",
                    val);
            return false;
        }
    } else if (strcmp(key, "dpdk-queues") == 0) {
        if (!parse_u32_range(val, 1, 16, &v)) {
            set_err(err, errlen, "dpdk-queues must be 1..16 (got '%s')", val);
            return false;
        }
        cfg->dpdk_queues = (uint16_t)v;
    } else if (strcmp(key, "payload") == 0) {
        if (!parse_u32_range(val, UET_PAYLOAD_MTU_MIN, UET_PAYLOAD_MTU_MAX,
                             &v) ||
            !uet_payload_mtu_valid(v)) {
            set_err(err, errlen,
                    "payload must be 1024, 2048, 4096 or 8192 (got '%s')", val);
            return false;
        }
        cfg->payload = v;
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
    if (cfg->wire == UET_ENGINE_WIRE_DPDK && cfg->dpdk_dev[0] == '\0') {
        set_err(err, errlen, "wire=dpdk needs dpdk-dev=");
        return false;
    }
    /* With an explicit mtu=, an explicit payload= has to fit it; the
     * wire's own MTU is only known once the engine starts. */
    if (cfg->mtu != 0 && cfg->payload != 0 &&
        cfg->payload + UET_PAYLOAD_HDR_MAX > cfg->mtu) {
        set_err(
            err, errlen, "payload=%u needs an mtu of at least %u (mtu is %u)",
            (unsigned)cfg->payload,
            (unsigned)(cfg->payload + UET_PAYLOAD_HDR_MAX), (unsigned)cfg->mtu);
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

void uet_engine_cfg_mac(const struct uet_engine_cfg *cfg, uint8_t mac[6])
{
    engine_mac(cfg, mac);
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

static const char *encap_name(enum uet_engine_encap encap)
{
    return encap == UET_ENGINE_ENCAP_IP ? "ip" : "udp";
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

    char wire[48];
    char mtu[16] = "wire";
    char payload[16] = "auto";

    engine_mac(cfg, mac);
    if (cfg->encap == UET_ENGINE_ENCAP_IP)
        snprintf(wire, sizeof(wire), "encap ip proto %u",
                 (unsigned)cfg->ipproto);
    else
        snprintf(wire, sizeof(wire), "encap udp port %u",
                 (unsigned)cfg->udp_port);
    if (cfg->mtu != 0)
        snprintf(mtu, sizeof(mtu), "%u", (unsigned)cfg->mtu);
    if (cfg->payload != 0)
        snprintf(payload, sizeof(payload), "%u", (unsigned)cfg->payload);
    snprintf(buf, len,
             "ip %u.%u.%u.%u mac %02x:%02x:%02x:%02x:%02x:%02x job %u pid %u "
             "index %u pds %s sec %s mtu %s payload %s %s",
             (unsigned)(cfg->ip >> 24), (unsigned)((cfg->ip >> 16) & 0xffu),
             (unsigned)((cfg->ip >> 8) & 0xffu), (unsigned)(cfg->ip & 0xffu),
             (unsigned)mac[0], (unsigned)mac[1], (unsigned)mac[2],
             (unsigned)mac[3], (unsigned)mac[4], (unsigned)mac[5],
             (unsigned)cfg->job_id, (unsigned)cfg->pid_on_fep,
             (unsigned)cfg->resource_index, pds_name(cfg->pds),
             sec_name(cfg->sec), mtu, payload, wire);
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

    /* The wire format is the engine's, so these are owned outright. */
    if (setenv("UET_ENCAP", encap_name(cfg->encap), 1) != 0) {
        set_err(err, errlen, "setenv: %s", strerror(errno));
        return false;
    }
    if (!set_env_u32("UET_UDP_PORT", cfg->udp_port, err, errlen) ||
        !set_env_u32("UET_IPPROTO", cfg->ipproto, err, errlen))
        return false;
    if (cfg->payload != 0) {
        if (!set_env_u32("UET_MAX_PAYLOAD", cfg->payload, err, errlen))
            return false;
    } else {
        unsetenv("UET_MAX_PAYLOAD");
    }
    /* The window is the wire's to size (its queue has to hold a burst of
     * it), so it is owned as well. */
    if (cfg->window != 0) {
        if (!set_env_u32("UET_PDS_MP_RANGE", cfg->window, err, errlen))
            return false;
    } else {
        unsetenv("UET_PDS_MP_RANGE");
    }
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

static int engine_wire_tx_iov(void *ctx, const struct iovec *iov, unsigned n,
                              size_t len)
{
    struct uet_engine *e = ctx;

    return e->wire.tx_iov(e->wire.ctx, iov, n, len);
}

static int engine_dma_copy(void *ctx, void *dst, const void *src, size_t len)
{
    struct uet_engine *e = ctx;

    return e->dma.copy(e->dma.ctx, dst, src, len);
}

/* A read of an engine-owned page list.  Lists are never written through. */
static void *window_map(struct uet_engine *e, uint64_t addr, size_t len,
                        bool write)
{
    uint64_t rel = addr - WINDOW_BASE;
    uint64_t slot = rel >> WINDOW_SHIFT;
    uint64_t off = rel & ((UINT64_C(1) << WINDOW_SHIFT) - 1u);
    struct engine_mr *m;

    if (slot >= UET_ENGINE_MAX_MRS)
        return NULL;
    m = &e->mrs[slot];
    if (!m->used || m->dir == NULL || write)
        return NULL;
    if (m->revoked) {
        e->stats.revoked_hits++;
        return NULL;
    }
    if (off > (uint64_t)m->ndir * sizeof(uint64_t) ||
        len > (uint64_t)m->ndir * sizeof(uint64_t) - off)
        return NULL;
    return (uint8_t *)m->dir + off;
}

static void *engine_dma_translate(void *ctx, uet_dma_addr_t addr, size_t len,
                                  bool write)
{
    struct uet_engine *e = ctx;
    void *p;

    if (addr >= WINDOW_BASE)
        p = window_map(e, addr, len, write);
    else if (e->dma.map != NULL)
        p = e->dma.map(e->dma.ctx, addr, len, write);
    else
        p = (void *)(uintptr_t)addr;

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

void uet_engine_identity(const struct uet_engine *e, struct uet_engine_cfg *out)
{
    if (e == NULL || out == NULL)
        return;
    *out = e->cfg;
    engine_mac(&e->cfg, out->mac);
    out->mac_set = true;
    out->payload = e->wire_info.payload_mtu;
}

void uet_engine_describe(const struct uet_engine *e, char *buf, size_t len)
{
    struct uet_engine_cfg id;
    char cfg[256];

    if (e == NULL || buf == NULL || len == 0)
        return;
    uet_engine_identity(e, &id);
    uet_engine_cfg_describe(&id, cfg, sizeof(cfg));

    /* Composed in a buffer that holds it all, then cut to fit. */
    char out[sizeof(cfg) + 64];
    snprintf(out, sizeof(out), "%s window %u ack every %u bytes%s", cfg,
             (unsigned)(e->cfg.window != 0 ? e->cfg.window : 128u),
             (unsigned)e->wire_info.ack_gen_trigger,
             e->wire_info.tx_zero_copy ? " zero-copy tx" : "");
    size_t n = strlen(out);
    if (n >= len)
        n = len - 1;
    memcpy(buf, out, n);
    buf[n] = '\0';
}

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
    if (e->cfg.mtu == 0)
        e->cfg.mtu = DEFAULT_MTU;
    e->wire = *wire;
    if (dma != NULL)
        e->dma = *dma;
    cfg = &e->cfg;

    if (cfg->payload != 0 && cfg->payload + UET_PAYLOAD_HDR_MAX > cfg->mtu) {
        set_err(err, errlen, "payload=%u does not fit an mtu of %u",
                (unsigned)cfg->payload, (unsigned)cfg->mtu);
        free(e);
        return NULL;
    }

    memset(&ncfg, 0, sizeof(ncfg));
    ncfg.ip = cfg->ip;
    engine_mac(cfg, ncfg.mac);
    ncfg.mtu = cfg->mtu;
    ncfg.udp_port = cfg->udp_port;
    ncfg.ipproto = cfg->ipproto;
    ncfg.name = "ernic-uet";
    ncfg.tx = engine_wire_tx;
    ncfg.tx_iov = wire->tx_iov != NULL ? engine_wire_tx_iov : NULL;
    ncfg.tx_ctx = e;
    ncfg.tx_ipv4_csum = wire->tx_ipv4_csum;
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

    if (e->dma.copy != NULL) {
        rc = uet_set_dma_copy(e->uet, engine_dma_copy, e);
        if (rc != 0) {
            set_err(err, errlen, "uet_set_dma_copy: %s", strerror(-rc));
            goto fail;
        }
    }

    rc = uet_get_wire_info(e->uet, &e->wire_info);
    if (rc != 0) {
        set_err(err, errlen, "uet_get_wire_info: %s", strerror(-rc));
        goto fail;
    }

    /* Always installed: even with process addresses for region memory, the
     * engine-owned page lists are reached through it. */
    rc = uet_set_dma_translate(e->uet, engine_dma_translate, e);
    if (rc != 0) {
        set_err(err, errlen, "uet_set_dma_translate: %s", strerror(-rc));
        goto fail;
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

/* Close a region's provider descriptor and give its slot back. */
static void mr_release(struct uet_engine *e, uint32_t slot)
{
    struct engine_mr *m = &e->mrs[slot];

    (void)uet_mr_close(m->h);
    free(m->dir);
    if (m->closing)
        e->closing--;
    memset(m, 0, sizeof(*m));
}

static void peer_release(struct uet_engine *e, uint32_t slot)
{
    struct engine_peer *p = &e->peers[slot];

    if (p->removing)
        e->closing--;
    memset(p, 0, sizeof(*p));
}

void uet_engine_destroy(struct uet_engine *e)
{
    if (e == NULL)
        return;

    /* Nothing is left to wait for: whatever is in flight dies with the
     * instance. */
    for (uint32_t i = 0; i < UET_ENGINE_MAX_MRS; i++) {
        struct engine_mr *m = &e->mrs[i];

        if (!m->used)
            continue;
        if (!m->closing)
            (void)uet_mr_disable(m->h);
        mr_release(e, i);
    }
    for (uint32_t i = 0; i < UET_ENGINE_MAX_PEERS; i++) {
        if (e->peers[i].used) {
            (void)uet_av_remove(e->peers[i].av);
            peer_release(e, i);
        }
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

bool uet_engine_rx_frame_ext(struct uet_engine *e, const void *frame,
                             size_t len, bool csum_ok,
                             void (*release)(void *cookie), void *cookie)
{
    return e != NULL && uet_nic_ernic_rx_frame_ext(e->nic, frame, len, csum_ok,
                                                   release, cookie);
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

/* Finish releasing regions and peers whose last operation has gone. */
static void reap_closing(struct uet_engine *e)
{
    uint64_t now;

    if (e->closing == 0)
        return;
    now = now_ms();

    for (uint32_t i = 0; i < UET_ENGINE_MAX_MRS; i++) {
        struct engine_mr *m = &e->mrs[i];

        if (m->used && m->closing && m->refs == 0 && now >= m->close_after_ms)
            mr_release(e, i);
    }
    for (uint32_t i = 0; i < UET_ENGINE_MAX_PEERS; i++) {
        struct engine_peer *p = &e->peers[i];

        /* The provider counts its own references and refuses while any
         * remain, so a refusal is simply tried again on a later poll. */
        if (p->used && p->removing && p->refs == 0 && uet_av_remove(p->av) == 0)
            peer_release(e, i);
    }
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
    reap_closing(e);

    if (e->wire.flush != NULL)
        e->wire.flush(e->wire.ctx);
}

bool uet_engine_has_work(const struct uet_engine *e)
{
    return e != NULL &&
           (uet_nic_ernic_rx_pending(e->nic) || e->ops_in_flight > 0);
}

static int mr_slot_alloc(struct uet_engine *e, uint32_t *slot)
{
    for (uint32_t i = 0; i < UET_ENGINE_MAX_MRS; i++) {
        if (!e->mrs[i].used) {
            *slot = i;
            return 0;
        }
    }
    return -ENOSPC;
}

/* Register, bind and enable; the slot is filled in only on success. */
static int mr_finish_reg(struct uet_engine *e, uint32_t slot, uet_mr_handle_t h,
                         uint64_t *dir, uint32_t ndir, uint32_t *mr,
                         uint64_t *rkey)
{
    int rc = uet_ep_bind_mr(e->ep, h, UET_FLAGS_NONE);

    if (rc == 0)
        rc = uet_mr_enable(h);
    if (rc != 0) {
        (void)uet_mr_close(h);
        free(dir);
        return fi_to_errno(rc);
    }

    e->mrs[slot].used = true;
    e->mrs[slot].h = h;
    e->mrs[slot].dir = dir;
    e->mrs[slot].ndir = ndir;
    *mr = slot;
    *rkey = uet_mr_key(h);
    return 0;
}

static uint64_t mr_access(bool remote_read, bool remote_write)
{
    uint64_t access = FI_READ | FI_WRITE;

    if (remote_read)
        access |= FI_REMOTE_READ;
    if (remote_write)
        access |= FI_REMOTE_WRITE;
    return access;
}

int uet_engine_mr_reg(struct uet_engine *e, const struct uet_engine_mr_desc *d,
                      uint32_t *mr, uint64_t *rkey)
{
    uint32_t slot;
    uet_mr_handle_t h;
    int rc;

    if (e == NULL || d == NULL || mr == NULL || rkey == NULL)
        return -EINVAL;
    if (d->level > UET_PBL_LEVEL_2 || d->len == 0)
        return -EINVAL;
    rc = mr_slot_alloc(e, &slot);
    if (rc != 0)
        return rc;

    /* The provider assigns the key and keeps the IDEMPOTENT_SAFE bit asked
     * for here.  base_va 0 makes addresses within the region offsets. */
    rc = uet_mr_reg_pbl(
        e->dom, d->root, d->page_size, (uet_pbl_level_t)d->level,
        d->page_offset, 0, (size_t)d->len,
        mr_access(d->remote_read, d->remote_write),
        d->idempotent_safe ? UET_MR_KEY_IDEMPOTENT_SAFE : UET_MR_KEY_NONE,
        UET_FLAGS_NONE, NULL, &h);
    if (rc != 0)
        return fi_to_errno(rc);
    return mr_finish_reg(e, slot, h, NULL, 0, mr, rkey);
}

int uet_engine_mr_reg_pages(struct uet_engine *e,
                            const struct uet_engine_pages *p, uint32_t *mr,
                            uint64_t *rkey)
{
    uint32_t slot;
    uint64_t *dir;
    uet_mr_handle_t h;
    int rc;

    if (e == NULL || p == NULL || mr == NULL || rkey == NULL ||
        p->pages == NULL || p->npages == 0 || p->len == 0)
        return -EINVAL;
    if (p->page_size < 512 || (p->page_size & (p->page_size - 1u)) != 0 ||
        p->page_offset >= p->page_size)
        return -EINVAL;
    /* The list has to cover the region, and fit its window. */
    if (p->len > (uint64_t)p->npages * p->page_size - p->page_offset ||
        (uint64_t)p->npages * sizeof(uint64_t) > (UINT64_C(1) << WINDOW_SHIFT))
        return -EINVAL;

    rc = mr_slot_alloc(e, &slot);
    if (rc != 0)
        return rc;

    dir = malloc((size_t)p->npages * sizeof(uint64_t));
    if (dir == NULL)
        return -ENOMEM;
    memcpy(dir, p->pages, (size_t)p->npages * sizeof(uint64_t));

    rc = uet_mr_reg_pbl(
        e->dom, WINDOW_BASE + ((uint64_t)slot << WINDOW_SHIFT), p->page_size,
        UET_PBL_LEVEL_1, p->page_offset, 0, (size_t)p->len,
        mr_access(p->remote_read, p->remote_write),
        p->idempotent_safe ? UET_MR_KEY_IDEMPOTENT_SAFE : UET_MR_KEY_NONE,
        UET_FLAGS_NONE, NULL, &h);
    if (rc != 0) {
        free(dir);
        return fi_to_errno(rc);
    }
    return mr_finish_reg(e, slot, h, dir, p->npages, mr, rkey);
}

int uet_engine_mr_dereg(struct uet_engine *e, uint32_t mr)
{
    struct engine_mr *m;

    if (e == NULL || mr >= UET_ENGINE_MAX_MRS || !e->mrs[mr].used ||
        e->mrs[mr].closing)
        return -EINVAL;
    m = &e->mrs[mr];

    /* Peers stop finding it, and its page list stops resolving, now; the
     * descriptor itself waits until nothing can still point at it. */
    (void)uet_mr_disable(m->h);
    m->revoked = true;
    m->closing = true;
    m->close_after_ms = now_ms() + e->cfg.mr_quarantine_ms;
    e->closing++;
    reap_closing(e);
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
    struct engine_peer *p;

    if (e == NULL || peer >= UET_ENGINE_MAX_PEERS || !e->peers[peer].used ||
        e->peers[peer].removing)
        return -EINVAL;
    p = &e->peers[peer];
    p->removing = true;
    e->closing++;
    reap_closing(e);
    return 0;
}

static int post_rma(struct uet_engine *e, const struct uet_engine_rma *w,
                    bool write)
{
    unsigned slot;
    struct uet_mr_seg seg;
    struct engine_peer *p;
    struct engine_mr *m;
    ssize_t rc;
    int erc;

    if (e == NULL || w == NULL || w->peer >= UET_ENGINE_MAX_PEERS ||
        !e->peers[w->peer].used || w->mr >= UET_ENGINE_MAX_MRS ||
        !e->mrs[w->mr].used || w->len == 0)
        return -EINVAL;
    p = &e->peers[w->peer];
    m = &e->mrs[w->mr];
    if (p->removing || m->closing)
        return -ECANCELED;

    for (slot = 0; slot < UET_ENGINE_MAX_OPS; slot++) {
        if (!e->ops[slot].used)
            break;
    }
    if (slot == UET_ENGINE_MAX_OPS)
        return -EAGAIN;

    seg.mr = m->h;
    seg.addr = w->local_addr;
    seg.len = (size_t)w->len;

    /* The endpoint's RUDI setting is read when the operation is posted,
     * which makes it a per-operation choice here. */
    erc = set_rudi(e, w->rudi);
    if (erc != 0)
        return erc;

    if (write)
        rc = uet_writeseg(e->ep, e->cfg.job_id, &seg, 1, NULL, p->av,
                          w->remote_addr, w->rkey, &e->ops[slot],
                          p->resource_index);
    else
        rc = uet_readseg(e->ep, e->cfg.job_id, &seg, 1, p->av, w->remote_addr,
                         w->rkey, &e->ops[slot], p->resource_index);
    if (rc != 0)
        return fi_to_errno(rc);

    /* Posting sent the first packets; a batching wire sends them now. */
    if (e->wire.flush != NULL)
        e->wire.flush(e->wire.ctx);

    e->ops[slot].used = true;
    e->ops[slot].cookie = w->cookie;
    e->ops[slot].mr = w->mr;
    e->ops[slot].peer = w->peer;
    m->refs++;
    p->refs++;
    e->ops_in_flight++;
    e->stats.ops_posted++;
    return 0;
}

int uet_engine_post_write(struct uet_engine *e, const struct uet_engine_rma *w)
{
    return post_rma(e, w, true);
}

int uet_engine_post_read(struct uet_engine *e, const struct uet_engine_rma *r)
{
    return post_rma(e, r, false);
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
    /* A region taken away underneath the operation is why it failed,
     * whatever the provider made of the missing page list. */
    out->status = (status != 0 && e->mrs[op->mr].revoked) ? -ECANCELED : status;
    e->mrs[op->mr].refs--;
    e->peers[op->peer].refs--;
    op->used = false;
    e->ops_in_flight--;
    if (out->status == 0)
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
    if (got > 0)
        reap_closing(e);
    return got;
}

bool uet_engine_can_abort(const struct uet_engine *e)
{
    /* The stop-and-go PDS cannot discard what it has sent. */
    return e != NULL && e->cfg.pds == UET_ENGINE_PDS_FULL;
}

int uet_engine_abort(struct uet_engine *e, uint64_t cookie)
{
    struct engine_op *op = NULL;
    int rc;

    if (e == NULL)
        return -EINVAL;
    if (!uet_engine_can_abort(e))
        return -EOPNOTSUPP;

    for (unsigned i = 0; i < UET_ENGINE_MAX_OPS; i++) {
        if (e->ops[i].used && e->ops[i].cookie == cookie) {
            op = &e->ops[i];
            break;
        }
    }
    if (op == NULL)
        return -ENOENT;

    /* The provider finds the operation by the context it was posted with,
     * which is the slot. */
    rc = uet_ep_abort_op(e->ep, op);
    if (rc == -FI_ENOENT)
        return -ENOENT; /* done; its completion is still in the queue */
    if (rc == -FI_ENOSYS)
        return -EOPNOTSUPP;
    if (rc != 0)
        return fi_to_errno(rc);

    e->mrs[op->mr].refs--;
    e->peers[op->peer].refs--;
    op->used = false;
    e->ops_in_flight--;
    e->stats.ops_aborted++;
    reap_closing(e);

    /* A PDC the abort closed sends its CLOSE now, on a batching wire too. */
    if (e->wire.flush != NULL)
        e->wire.flush(e->wire.ctx);
    return 0;
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
    out->rx_frames_ext = ns.rx_frames_ext;
    out->rx_dropped = ns.rx_dropped;
    out->tx_frames = ns.tx_frames;
    out->tx_frames_iov = ns.tx_frames_iov;
    out->tx_loopback = ns.tx_loopback;
    out->tx_dropped = ns.tx_dropped;
    out->arp_requests = ns.arp_requests;
    out->arp_replies = ns.arp_replies;
    out->nh_pending = ns.nh_pending;
    out->icmp_echo_replies = ns.icmp_echo_replies;

    out->mrs = 0;
    for (unsigned i = 0; i < UET_ENGINE_MAX_MRS; i++)
        out->mrs += e->mrs[i].used ? 1u : 0u;
    out->peers = 0;
    for (unsigned i = 0; i < UET_ENGINE_MAX_PEERS; i++)
        out->peers += e->peers[i].used ? 1u : 0u;
    out->ops_in_flight = e->ops_in_flight;
}
