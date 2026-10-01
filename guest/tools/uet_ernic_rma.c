/*
 * uet_ernic_rma.c -- Slice A between two guests, through libuet_ernic
 *
 * Copyright (c) Advanced Micro Devices, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: MIT
 *
 * Run it in two VMs whose ionic NICs are rocm-ernic instances started with
 * --uet, their TAPs on one bridge:
 *
 *   vm2$ uet_ernic_rma target [-p PORT] [-l LEN]
 *   vm1$ uet_ernic_rma initiator VM2_ADDR [-p PORT] [-l LEN] [-r]
 *
 * The target registers a window and sends its UET address and key to the
 * initiator over TCP (the guests' own network, not UET). The initiator
 * WRITEs LEN bytes of a known pattern into the window, over RUDI with -r and
 * RUD without, reads the first 64 KiB back, and the target compares every
 * byte. The exit status is 0 only if both ends agree.
 */

#include <arpa/inet.h>
#include <errno.h>
#include <getopt.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include <rdma/fi_errno.h>

#include "uet_ernic.h"

#define DEFAULT_PORT 18515
#define DEFAULT_LEN  (1024u * 1024u)
#define READ_BACK    (64u * 1024u)

struct hello {
    struct uet_addr addr;
    uint64_t key;
    uint64_t len;
};

struct side {
    uet_handle_t h;
    uet_domain_handle_t dom;
    uet_ep_handle_t ep;
    uet_cq_handle_t txcq;
    uet_mr_handle_t mr;
    uint8_t *buf;
    size_t len;
};

static uint8_t pattern(size_t off)
{
    uint64_t z = (uint64_t)(off / 8) + UINT64_C(0x9e3779b97f4a7c15);

    z = (z ^ (z >> 30)) * UINT64_C(0xbf58476d1ce4e5b9);
    z = (z ^ (z >> 27)) * UINT64_C(0x94d049bb133111eb);
    z ^= z >> 31;
    return (uint8_t)(z >> ((off % 8) * 8));
}

static double now_s(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

static int die(const char *what, int rc)
{
    fprintf(stderr, "uet_ernic_rma: %s: %s\n", what,
            strerror(rc < 0 ? -rc : rc));
    return 1;
}

static int open_side(struct side *s, size_t len, uint64_t access, uint64_t key)
{
    struct fi_cq_attr attr = {.format = FI_CQ_FORMAT_DATA, .size = 64};
    uet_cq_handle_t rxcq;
    int rc;

    s->len = len;
    s->buf = aligned_alloc(4096, (len + 4095u) & ~(size_t)4095u);
    if (s->buf == NULL)
        return -ENOMEM;
    memset(s->buf, 0, len);

    if ((rc = uet_initialize(&s->h)) != 0 ||
        (rc = uet_domain(s->h, NULL, NULL, NULL, NULL, NULL, NULL, &s->dom)) !=
            0 ||
        (rc = uet_endpoint(s->dom, NULL, NULL, NULL, &s->ep)) != 0 ||
        (rc = uet_ep_bind_cq(s->ep, &attr, NULL, FI_SEND, NULL, &s->txcq)) !=
            0 ||
        (rc = uet_ep_bind_cq(s->ep, &attr, NULL, FI_RECV, NULL, &rxcq)) != 0 ||
        (rc = uet_mr_reg(s->dom, s->buf, len, access, key, 0, NULL, &s->mr)) !=
            0 ||
        (rc = uet_ep_bind_mr(s->ep, s->mr, 0)) != 0 ||
        (rc = uet_mr_enable(s->mr)) != 0 || (rc = uet_ep_enable(s->ep)) != 0)
        return rc;
    return 0;
}

static void close_side(struct side *s)
{
    (void)uet_mr_disable(s->mr);
    (void)uet_mr_close(s->mr);
    (void)uet_ep_close(s->ep);
    (void)uet_domain_close(s->dom);
    (void)uet_finalize(s->h);
    free(s->buf);
}

/* One completion: 0, or the failed operation's errno. */
static int reap(struct side *s)
{
    struct fi_cq_data_entry c;
    struct fi_cq_err_entry e;
    ssize_t n;

    for (;;) {
        n = uet_cq_read(s->txcq, &c, 1);
        if (n == 1)
            return 0;
        if (n == -FI_EAVAIL) {
            memset(&e, 0, sizeof(e));
            return uet_cq_readerr(s->txcq, &e) == 1 && e.err ? e.err : EIO;
        }
        if (n < 0)
            return (int)-n;
        (void)uet_ep_progress(s->ep);
    }
}

static bool io_all(int fd, void *p, size_t len, bool out)
{
    uint8_t *b = p;

    while (len > 0) {
        ssize_t n = out ? send(fd, b, len, 0) : recv(fd, b, len, 0);
        if (n <= 0)
            return false;
        b += n;
        len -= (size_t)n;
    }
    return true;
}

static int run_target(uint16_t port, size_t len)
{
    struct side s;
    struct hello hi;
    struct sockaddr_in sa = {.sin_family = AF_INET,
                             .sin_port = htons(port),
                             .sin_addr.s_addr = htonl(INADDR_ANY)};
    int one = 1, lfd, fd, rc;
    char done;

    rc = open_side(&s, len, FI_REMOTE_READ | FI_REMOTE_WRITE,
                   UET_MR_KEY_IDEMPOTENT_SAFE);
    if (rc != 0)
        return die("opening the window", rc);

    memset(&hi, 0, sizeof(hi));
    if ((rc = uet_getname(s.ep, &hi.addr)) != 0)
        return die("uet_getname", rc);
    hi.key = uet_mr_key(s.mr);
    hi.len = len;

    lfd = socket(AF_INET, SOCK_STREAM, 0);
    if (lfd < 0 ||
        setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) != 0 ||
        bind(lfd, (struct sockaddr *)&sa, sizeof(sa)) != 0 ||
        listen(lfd, 1) != 0)
        return die("listening", errno);
    printf("target: window of %zu bytes, key %#llx, waiting on port %u\n", len,
           (unsigned long long)hi.key, port);
    fflush(stdout);
    fd = accept(lfd, NULL, NULL);
    if (fd < 0 || !io_all(fd, &hi, sizeof(hi), true) ||
        !io_all(fd, &done, 1, false))
        return die("talking to the initiator", errno ? errno : EPROTO);

    size_t wrong = 0;
    for (size_t i = 0; i < len; i++)
        wrong += s.buf[i] != pattern(i) ? 1u : 0u;
    done = wrong == 0 ? 'y' : 'n';
    (void)io_all(fd, &done, 1, true);
    printf("target: compared %zu bytes, %zu wrong\n", len, wrong);

    close(fd);
    close(lfd);
    close_side(&s);
    return wrong == 0 ? 0 : 1;
}

static int run_initiator(const char *host, uint16_t port, size_t len, bool rudi)
{
    struct side s;
    struct hello hi;
    struct addrinfo hints = {.ai_family = AF_INET, .ai_socktype = SOCK_STREAM};
    struct addrinfo *ai = NULL;
    uet_addr_handle_t ah;
    char portstr[8];
    int fd, rc;
    char done = 'd';

    rc = open_side(&s, len, 0, UET_MR_KEY_NONE);
    if (rc != 0)
        return die("opening the source", rc);
    for (size_t i = 0; i < len; i++)
        s.buf[i] = pattern(i);

    snprintf(portstr, sizeof(portstr), "%u", port);
    if (getaddrinfo(host, portstr, &hints, &ai) != 0 || ai == NULL)
        return die("resolving the target", EHOSTUNREACH);
    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0 || connect(fd, ai->ai_addr, ai->ai_addrlen) != 0 ||
        !io_all(fd, &hi, sizeof(hi), false))
        return die("reaching the target", errno ? errno : EPROTO);
    freeaddrinfo(ai);
    if (hi.len < len)
        return die("the target's window is too small", EMSGSIZE);

    if ((rc = uet_av_insert(s.dom, &hi.addr, &ah)) != 0)
        return die("uet_av_insert", rc);
    if ((rc = uet_ep_setopt(s.ep, FI_OPT_ENDPOINT, UET_OPT_FORCE_RUDI, &rudi,
                            sizeof(rudi))) != 0)
        return die("uet_ep_setopt", rc);

    double t0 = now_s();
    while ((rc = (int)uet_write(s.ep, UET_DEF_JOB_ID, s.buf, len, NULL, s.mr,
                                ah, 0, hi.key, NULL)) == -FI_EAGAIN)
        (void)uet_ep_progress(s.ep);
    if (rc != 0 || (rc = reap(&s)) != 0)
        return die("uet_write", rc);
    double dt = now_s() - t0;
    printf("initiator: %zu bytes over %s in %.3f ms (%.1f MiB/s)\n", len,
           rudi ? "RUDI" : "RUD", dt * 1e3,
           (double)len / (1024.0 * 1024.0) / dt);

    /* Read the start back into the (now overwritten) source buffer. */
    size_t back = len < READ_BACK ? len : READ_BACK;
    memset(s.buf, 0, back);
    while ((rc = (int)uet_read(s.ep, UET_DEF_JOB_ID, s.buf, back, s.mr, ah, 0,
                               hi.key, NULL)) == -FI_EAGAIN)
        (void)uet_ep_progress(s.ep);
    if (rc != 0 || (rc = reap(&s)) != 0)
        return die("uet_read", rc);
    for (size_t i = 0; i < back; i++) {
        if (s.buf[i] != pattern(i))
            return die("the bytes read back differ", EIO);
    }

    if (!io_all(fd, &done, 1, true) || !io_all(fd, &done, 1, false))
        return die("hearing from the target", EPROTO);
    printf("initiator: read back %zu bytes; target says %s\n", back,
           done == 'y' ? "every byte matches" : "MISMATCH");

    (void)uet_av_remove(ah);
    close(fd);
    close_side(&s);
    return done == 'y' ? 0 : 1;
}

static void usage(void)
{
    fprintf(stderr, "usage: uet_ernic_rma target [-p PORT] [-l LEN]\n"
                    "       uet_ernic_rma initiator HOST [-p PORT] [-l LEN] "
                    "[-r]\n");
}

int main(int argc, char **argv)
{
    unsigned long port = DEFAULT_PORT;
    unsigned long long len = DEFAULT_LEN;
    bool rudi = false;
    int opt;

    while ((opt = getopt(argc, argv, "p:l:rh")) != -1) {
        switch (opt) {
        case 'p':
            port = strtoul(optarg, NULL, 0);
            break;
        case 'l':
            len = strtoull(optarg, NULL, 0);
            break;
        case 'r':
            rudi = true;
            break;
        default:
            usage();
            return 2;
        }
    }
    if (optind >= argc || port == 0 || port > 65535 || len == 0 ||
        len > (1ull << 32)) {
        usage();
        return 2;
    }
    if (strcmp(argv[optind], "target") == 0 && optind + 1 == argc)
        return run_target((uint16_t)port, (size_t)len);
    if (strcmp(argv[optind], "initiator") == 0 && optind + 2 == argc)
        return run_initiator(argv[optind + 1], (uint16_t)port, (size_t)len,
                             rudi);
    usage();
    return 2;
}
