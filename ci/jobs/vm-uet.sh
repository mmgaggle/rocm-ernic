#!/bin/bash
# Copyright (c) Advanced Micro Devices, Inc. All rights reserved.
#
# SPDX-License-Identifier: MIT
#
# ci/jobs/vm-uet.sh -- UET between two guests through the
# engines inside their rocm-ernic instances (docs/uet.rst,
# phase 3).
#
# The instances must run with --uet and their TAPs must be on
# one bridge.  Bring the lane up with:
#
#   export CI_BUILD_DIR=<a build with -DERNIC_UET=ON>
#   export ERNIC_UET='ip=192.168.200.10%i'
#   bash ci/jobs/vm-up.sh
#   bash ci/jobs/vm-functional.sh   # guest setup
#   bash ci/jobs/vm-uet.sh
#
# Add sec=cluster (and a longer rto=, see docs/uet.rst) to
# ERNIC_UET for the TSS pass; vm-down.sh with
# CI_KEEP_OVERLAYS=true and vm-up.sh switch over without
# setting the guests up again.
#
# Both guests get copies of the guest-side sources, the
# tracked files of this tree and of the reference provider
# tree, and build them: libuet_ernic, uet_ernic_rma and,
# when UET_PROV_DIR names a tree with the libfabric "uet"
# provider in prov/, that provider over libuet_ernic
# ("make -C prov ernic") and its test_rma.
#
# Checks, each with its own result record:
#  - uet_ernic_rma in both directions, over RUDI and RUD;
#  - fi_info -p uet in each guest, test_rma writes in both
#    directions, one over RUD, and two writers into one window.
# With UET_PCAP=1, or UET_PCAP=auto (the default) and
# "sudo -n tcpdump" allowed, every transfer is captured on the
# bridge (ip proto 253 or arp) and the capture must show the
# expected PDS requests between the two engines, all wrapped
# in TSS when ERNIC_UET has sec=.
#
# Emits: $CI_RESULTS/vm-uet.jsonl, and logs and captures in
# $CI_RESULTS/vm-uet/<label>/.

# shellcheck source=/dev/null
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/../lib/common.sh"

ernic_env
mkdir -p "${CI_RESULTS}"

# ── Settings ──────────────────────────────────────

# The reference provider tree: uet_addr.h, and prov/ when it
# has the libfabric provider.
UET_PROV_DIR="${UET_PROV_DIR:-}"
UET_REF_DIR="${UET_REF_DIR:-${UET_PROV_DIR:-${ERNIC_UET_SOURCE_DIR:-}}}"
UET_LEN="${UET_LEN:-4194304}"
UET_PORT="${UET_PORT:-18515}"
UET_PCAP="${UET_PCAP:-auto}"
UET_CHECKS="${UET_CHECKS:-rma prov}"
UET_GUEST_DIR="${UET_GUEST_DIR:-phase3}" # under the guest user's home
UET_SEC="$(sed -n 's/.*\bsec=\([a-z]*\).*/\1/p' <<<"${ERNIC_UET:-}")"
UET_SEC="${UET_SEC:-none}"
UET_LABEL="${UET_LABEL:-sec-${UET_SEC}}"
UET_SUITE="${UET_SUITE:-vm-uet}"
OUT="${CI_RESULTS}/vm-uet/${UET_LABEL}"

start_suite "${UET_SUITE}"
mkdir -p "${OUT}"

[ -n "${UET_REF_DIR}" ] && [ -f "${UET_REF_DIR}/uet_addr.h" ] || \
    die "set UET_PROV_DIR or UET_REF_DIR to a reference provider tree"
case "${ERNIC_UET:-}" in
'') log_warn "ERNIC_UET is not set; the instances may not run engines" ;;
esac

# The engine of instance N, from ERNIC_UET's ip= (%i is N).
engine_ip() {
    local spec="${ERNIC_UET//%i/$1}"
    sed -n 's/.*\bip=\([0-9.]*\).*/\1/p' <<<"${spec}"
}

# No guest command may hang the job.
gssh() { vm_ssh_t "$@"; }

guest_ip() {
    gssh 30 "$1" "ip -4 -br addr show rocm-ernic0 \
        | awk '{print \$3}' | cut -d/ -f1" | tr -d '\r'
}

# ── Captures ──────────────────────────────────────

PCAP_ON=0
if [ "${UET_PCAP}" = "1" ] || { [ "${UET_PCAP}" = "auto" ] && \
        sudo -n true 2>/dev/null && command -v tcpdump >/dev/null; }; then
    PCAP_ON=1
fi
PCAP_SUMMARY="${PROJECT_ROOT}/scripts/uet-pcap-summary.py"

pcap_start() {
    local f="$1" i
    [ "${PCAP_ON}" = 1 ] || return 0
    rm -f "${f}" "${f}.log"
    sudo -n timeout -s INT 600 tcpdump -i "${CI_TAP_BRIDGE}" -U -n \
        -w "${f}" 'ip proto 253 or arp' 2>"${f}.log" &
    for i in $(seq 50); do
        grep -q 'listening on' "${f}.log" 2>/dev/null && return 0
        sleep 0.2
    done
    log_warn "tcpdump did not start: $(cat "${f}.log" 2>/dev/null)"
}

pcap_stop() {
    local f="$1" i
    [ "${PCAP_ON}" = 1 ] || return 0
    sleep 0.5 # let the last frames reach the bridge
    sudo -n pkill -INT -f "tcpdump -i ${CI_TAP_BRIDGE} -U -n -w ${f} " \
        2>/dev/null || true
    for i in $(seq 50); do
        pgrep -f "tcpdump -i ${CI_TAP_BRIDGE} -U -n -w ${f} " \
            >/dev/null || break
        sleep 0.2
    done
    sudo -n chown "$(id -u):$(id -g)" "${f}" 2>/dev/null || true
    python3 "${PCAP_SUMMARY}" "${f}" ${2:+--probe "$2"} \
        >"${f%.pcap}.summary" 2>&1 || true
    python3 "${PCAP_SUMMARY}" --json "${f}" ${2:+--probe "$2"} \
        >"${f%.pcap}.json" 2>/dev/null || true
    cat "${f%.pcap}.summary"
}

# The capture of a transfer from engine $2 to engine $3 must
# carry requests of kind $4 (RUDI_REQ or RUD_REQ) that way,
# and with sec= every UET frame must start with TSS and the
# payload probe must not be in the clear.
pcap_verify() {
    local f="$1" from="$2" to="$3" kind="$4"
    [ "${PCAP_ON}" = 1 ] || return 0
    python3 - "${f%.pcap}.json" "$(engine_ip "${from}")" \
        "$(engine_ip "${to}")" "${kind}" "${UET_SEC}" <<'PY'
import json, sys
path, src, dst, kind, sec = sys.argv[1:6]
s = json.load(open(path))
fl = s["flows"]
fwd = fl.get(f"{src} -> {dst}", {})
back = fl.get(f"{dst} -> {src}", {})
stray = [k for k in fl if k not in (f"{src} -> {dst}", f"{dst} -> {src}")]
ok = True
if stray:
    print(f"UET frames between other addresses: {stray}"); ok = False
if not fwd.get("frames") or not back.get("frames"):
    print(f"no UET frames both ways between {src} and {dst}"); ok = False
if sec == "none":
    if not fwd.get(kind):
        print(f"no {kind} from {src} to {dst}: {dict(fwd)}"); ok = False
    if not fwd.get("probe_in_clear"):
        print("the payload probe is not in the clear without TSS"); ok = False
else:
    for name, c in ((f"{src}->{dst}", fwd), (f"{dst}->{src}", back)):
        if c.get("TSS", 0) != c.get("frames", 0):
            print(f"{name}: {c.get('frames')} frames, only "
                  f"{c.get('TSS', 0)} TSS-wrapped"); ok = False
        if c.get("probe_in_clear"):
            print(f"{name}: payload in the clear under TSS"); ok = False
print("capture ok" if ok else "capture FAILED")
sys.exit(0 if ok else 1)
PY
}

# ── Staging and building in the guests ───────────

# The guest image pins the kernel and rdma-core, so the guest
# side is compiled there rather than shipped as binaries.
stage_and_build() {
    local n="$1" g="${UET_GUEST_DIR}"
    local tmp
    tmp="$(mktemp -d)"
    (cd "${PROJECT_ROOT}" && git ls-files -z guest/libuet_ernic \
        guest/tools shared/uet_ernic_abi.h | \
        tar --null -T - -cf "${tmp}/ernic.tar") || return 1
    if [ -n "${UET_PROV_DIR}" ]; then
        (cd "${UET_PROV_DIR}" && git ls-files -z | \
            tar --null -T - -cf "${tmp}/ref.tar") || return 1
    else
        tar -C "${UET_REF_DIR}" -cf "${tmp}/ref.tar" uet_addr.h
    fi
    gssh 60 "${n}" "rm -rf ~/${g} && mkdir -p ~/${g}/rocm-ernic \
        ~/${g}/uet-ref-prov ~/${g}/bin && \
        tar -C ~/${g}/rocm-ernic -xf -" <"${tmp}/ernic.tar" || return 1
    gssh 120 "${n}" "tar -C ~/${g}/uet-ref-prov -xf -" \
        <"${tmp}/ref.tar" || return 1
    rm -rf "${tmp}"

    # libfabric's headers come from the distro: libuet_ernic
    # uses its types, and the provider builds against it.
    gssh 400 "${n}" "dpkg -s libfabric-dev libfabric-bin >/dev/null \
        2>&1 || sudo -n env DEBIAN_FRONTEND=noninteractive \
        timeout 360 apt-get install -y -q --no-install-recommends \
        libfabric-dev libfabric-bin" >/dev/null || return 1

    gssh 600 "${n}" "set -e; cd ~/${g}
        R=rocm-ernic; U=uet-ref-prov
        CF='-O2 -g -Wall -Wextra -D_GNU_SOURCE'
        CF=\"\$CF -I\$R/guest/libuet_ernic -I\$R/shared -I\$U\"
        gcc \$CF -fPIC -shared -o bin/libuet_ernic.so \
            \$R/guest/libuet_ernic/uet_ernic.c -libverbs -lpthread
        gcc \$CF -o bin/uet_ernic_rma \$R/guest/tools/uet_ernic_rma.c \
            -Lbin -luet_ernic -Wl,-rpath,\$HOME/${g}/bin
        if [ -f \$U/prov/Makefile ]; then
            make -s -C \$U/prov ernic ERNIC=\$HOME/${g}/rocm-ernic
            test -f \$U/prov/ernic/libuet-fi.so
        fi
        ls bin \$U/prov/ernic 2>/dev/null"
}

# ── uet_ernic_rma ─────────────────────────────────

# rma_case <from> <to> <rudi|rud>
rma_case() {
    local from="$1" to="$2" mode="$3" tag f ip i rc=0 flag=""
    tag="rma-${from}to${to}-${mode}"
    f="${OUT}/${tag}"
    [ "${mode}" = rudi ] && flag="-r"
    ip="$(guest_ip "${to}")"
    [ -n "${ip}" ] || { echo "guest ${to} has no address"; return 1; }

    pcap_start "${f}.pcap"
    gssh 120 "${to}" "cd ~/${UET_GUEST_DIR} && timeout 100 \
        bin/uet_ernic_rma target -p ${UET_PORT} -l ${UET_LEN}" \
        >"${f}.target.log" 2>&1 &
    local tpid=$!
    for i in $(seq 100); do
        grep -q 'waiting on port' "${f}.target.log" && break
        sleep 0.2
    done
    gssh 120 "${from}" "cd ~/${UET_GUEST_DIR} && timeout 100 \
        bin/uet_ernic_rma initiator ${ip} -p ${UET_PORT} \
        -l ${UET_LEN} ${flag}" >"${f}.initiator.log" 2>&1 || rc=1
    wait "${tpid}" || rc=1
    cat "${f}.initiator.log" "${f}.target.log"
    pcap_stop "${f}.pcap" uet_ernic_rma:4096
    grep -q 'every byte matches' "${f}.initiator.log" || rc=1
    grep -q ', 0 wrong' "${f}.target.log" || rc=1
    if [ "${mode}" = rudi ]; then
        pcap_verify "${f}.pcap" "${from}" "${to}" RUDI_REQ || rc=1
    else
        pcap_verify "${f}.pcap" "${from}" "${to}" RUD_REQ || rc=1
    fi
    return "${rc}"
}

# ── The libfabric provider ────────────────────────

PROV_ENV="cd ~/${UET_GUEST_DIR}/uet-ref-prov/prov && \
export FI_PROVIDER_PATH=\$PWD/ernic"

prov_fi_info() {
    local out
    out="$(gssh 90 "$1" "${PROV_ENV} && timeout 60 fi_info -p uet")"
    echo "${out}"
    grep -q 'provider: uet' <<<"${out}" && \
        grep -q 'type: FI_EP_RDM' <<<"${out}"
}

# prov_case <tag> <target> <window> <env> <kind> <vm>:<offset>:<len>...
# Writers run at once, each its own test_rma process, and the
# capture must show requests of <kind> from the first one's engine.
prov_case() {
    local tag="$1" to="$2" size="$3" env="$4" kind="$5"; shift 5
    local f="${OUT}/${tag}" A K B S i rc=0 w n off len pids=()
    local wfrom="${1%%:*}"

    pcap_start "${f}.pcap"
    gssh 120 "${to}" "${PROV_ENV} && rm -f /tmp/uet-addr && ${env} \
        timeout 100 ./test_rma -o /tmp/uet-addr -t 90 target ${size} 0" \
        >"${f}.target.log" 2>&1 &
    local tpid=$!
    for i in $(seq 100); do
        grep -q '^SIZE' "${f}.target.log" && break
        sleep 0.2
    done
    read -r A K B S < <(gssh 30 "${to}" 'cat /tmp/uet-addr')
    [ -n "${S:-}" ] || { cat "${f}.target.log"; return 1; }

    i=0
    for w in "$@"; do
        IFS=: read -r n off len <<<"${w}"
        gssh 120 "${n}" "${PROV_ENV} && ${env} timeout 100 \
            ./test_rma -n -t 90 write ${A} ${K} ${B} ${off} ${len}" \
            >"${f}.w${i}.log" 2>&1 &
        pids+=($!)
        i=$((i + 1))
    done
    for i in "${!pids[@]}"; do
        wait "${pids[$i]}" || rc=1
        cat "${f}.w${i}.log"
        grep -q '^WROTE' "${f}.w${i}.log" || rc=1
    done
    wait "${tpid}" || rc=1
    cat "${f}.target.log"
    grep -q "^VERIFIED ${size} bytes" "${f}.target.log" || rc=1
    pcap_stop "${f}.pcap" test_rma:4096
    pcap_verify "${f}.pcap" "${wfrom}" "${to}" "${kind}" || rc=1
    return "${rc}"
}

# ── Run ───────────────────────────────────────────

log_info "label ${UET_LABEL}, sec ${UET_SEC}, ${UET_LEN} bytes," \
    "captures $([ "${PCAP_ON}" = 1 ] && echo on || echo off)," \
    "engines $(engine_ip 1) and $(engine_ip 2)"

group_start "Preflight"
run_check "${UET_SUITE}" "instances-alive" require_instances_alive
run_check "${UET_SUITE}" "guests-ready" require_guests_ready
group_end

group_start "Stage and build the guest side"
for n in 1 2; do
    run_check "${UET_SUITE}" "guest-build-vm${n}" stage_and_build "${n}"
done
group_end

if [[ " ${UET_CHECKS} " == *" rma "* ]]; then
    group_start "uet_ernic_rma, both ways, RUDI and RUD"
    for pair in "1 2" "2 1"; do
        for mode in rudi rud; do
            # shellcheck disable=SC2086
            set -- ${pair}
            run_check "${UET_SUITE}" "rma-${1}to${2}-${mode}" \
                rma_case "$1" "$2" "${mode}"
        done
    done
    group_end
fi

if [[ " ${UET_CHECKS} " == *" prov "* ]] && [ -n "${UET_PROV_DIR}" ]; then
    group_start "libfabric uet provider over libuet_ernic"
    for n in 1 2; do
        run_check "${UET_SUITE}" "prov-fi-info-vm${n}" prov_fi_info "${n}"
    done
    run_check "${UET_SUITE}" "prov-write-1to2" \
        prov_case prov-write-1to2 2 "${UET_LEN}" "" RUDI_REQ \
        "1:0:${UET_LEN}"
    run_check "${UET_SUITE}" "prov-write-2to1" \
        prov_case prov-write-2to1 1 "${UET_LEN}" "" RUDI_REQ \
        "2:0:${UET_LEN}"
    run_check "${UET_SUITE}" "prov-write-1to2-rud" \
        prov_case prov-write-1to2-rud 2 "${UET_LEN}" "FI_UET_RUDI=0" \
        RUD_REQ "1:0:${UET_LEN}"
    run_check "${UET_SUITE}" "prov-two-writers-1to2" \
        prov_case prov-two-writers-1to2 2 "$((2 * UET_LEN))" "" RUDI_REQ \
        "1:0:${UET_LEN}" "1:${UET_LEN}:${UET_LEN}"
    group_end
fi

group_start "Instance liveness"
run_check "${UET_SUITE}" "instances-survived" require_instances_alive
group_end

log_info "vm-uet job complete; results in ${CI_RESULTS}/${UET_SUITE}.jsonl"
