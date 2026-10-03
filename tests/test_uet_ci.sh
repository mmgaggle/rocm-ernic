#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later
# UET engine testing for CI.
#
# The engine talks to other engines over a TAP, which needs privileges CI
# does not have, and its datapath is covered by uet-engine-unit, which runs
# two engines over a socketpair. What is left to check here is the server
# side of it: that --uet starts a server whose engine announces the address
# and MAC its peers will ARP for, that the server shuts it down cleanly, and
# that a malformed --uet is refused before the guest ever attaches.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BUILD_DIR="${BUILD_DIR:-$PROJECT_ROOT/build}"
SERVER_BIN="${SERVER_BIN:-$BUILD_DIR/rocm-ernic}"
WORK_DIR="$(mktemp -d "/tmp/test-uet-ci-$$-XXXXXX")"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Each entry is "<--uet argument>|<substring the startup log must contain>".
declare -a CONFIGS=(
    "ip=192.168.200.101|UET engine ip 192.168.200.101 mac 02:55:c0:a8:c8:65 job 1 pid 0 index 15 pds pds sec none mtu 1500 payload 1024 encap udp port 4793 window 128 ack every 16384 bytes"
    "ip=10.0.0.7,job=42,pid=3,index=9|ip 10.0.0.7 mac 02:55:0a:00:00:07 job 42 pid 3 index 9"
    "ip=192.168.200.102,mac=02:00:00:00:00:44|mac 02:00:00:00:00:44"
    "ip=192.168.200.103,sec=cluster|sec cluster"
    "ip=192.168.200.104,sec=direct,ssi=7|sec direct"
    "ip=192.168.200.105,pds=sng|pds sng"
    "ip=192.168.200.106,mtu=9000,rto=25,retries=8|mtu 9000 payload 8192 encap udp port 4793 window 128 ack every 32768 bytes"
    "ip=192.168.200.107,encap=ip|payload 1024 encap ip proto 253"
    "ip=192.168.200.108,mtu=4500,port=5000|mtu 4500 payload 4096 encap udp port 5000"
    "ip=192.168.200.109,mtu=9000,payload=2048,encap=ip,proto=254|mtu 9000 payload 2048 encap ip proto 254"
)

# --uet spellings that must be refused before the server comes up.
declare -a BAD_CONFIGS=(
    ""
    "ip"
    "job=1"
    "ip=1.2.3"
    "ip=999.1.1.1"
    "ip=192.168.200.010"
    "ip=127.0.0.1"
    "ip=224.0.0.1"
    "ip=192.168.200.1,mac=01:00:5e:00:00:01"
    "ip=192.168.200.1,mac=02:00:00:00:00"
    "ip=192.168.200.1,job=16777216"
    "ip=192.168.200.1,pid=4096"
    "ip=192.168.200.1,index=-1"
    "ip=192.168.200.1,pds=rod"
    "ip=192.168.200.1,sec=server"
    "ip=192.168.200.1,sec=cluster,pds=sng"
    "ip=192.168.200.1,ssi=0"
    "ip=192.168.200.1,rto=0"
    "ip=192.168.200.1,mtu=100"
    "ip=192.168.200.1,encap=tcp"
    "ip=192.168.200.1,port=0"
    "ip=192.168.200.1,port=65536"
    "ip=192.168.200.1,proto=17"
    "ip=192.168.200.1,proto=1"
    "ip=192.168.200.1,payload=3000"
    "ip=192.168.200.1,mtu=1500,payload=8192"
    "ip=192.168.200.1,nonsense=1"
)

declare -a PASSED=()
declare -a FAILED=()

# shellcheck disable=SC2317  # Called via trap
cleanup() {
    local pid="${SERVER_PID:-}"
    if [ -n "$pid" ]; then
        kill "$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null || true
    fi
    rm -rf "$WORK_DIR"
}

trap cleanup EXIT

if [ ! -f "$SERVER_BIN" ]; then
    echo -e "${RED}Error: Server binary not found: $SERVER_BIN${NC}"
    exit 1
fi

# A server built without -DERNIC_UET=ON refuses --uet outright; that is not
# something this suite can test.
if "$SERVER_BIN" --help 2>&1 | grep -q "not in this build"; then
    echo -e "${YELLOW}Skipping: $SERVER_BIN was built without the UET engine${NC}"
    exit 77
fi

echo -e "${BLUE}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║  UET Engine CI Testing                                     ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo "Server binary: $SERVER_BIN"
echo "Configurations: ${#CONFIGS[@]} valid, ${#BAD_CONFIGS[@]} rejected"
echo ""
echo -e "${YELLOW}Note: the engine datapath is covered by uet-engine-unit.${NC}"
echo ""

# Start a server, wait for its socket, and return its log path in SERVER_LOG.
start_server() {
    local config="$1"
    SERVER_SEQ=$((${SERVER_SEQ:-0} + 1))
    local socket_path="$WORK_DIR/s${SERVER_SEQ}.sock"

    SERVER_LOG="$WORK_DIR/s${SERVER_SEQ}.log"
    "$SERVER_BIN" \
        --socket "$socket_path" \
        --uet "$config" \
        --log-level info >"$SERVER_LOG" 2>&1 &
    SERVER_PID=$!

    for _ in {1..20}; do
        if [ -S "$socket_path" ]; then
            return 0
        fi
        if ! kill -0 "$SERVER_PID" 2>/dev/null; then
            return 1
        fi
        sleep 0.25
    done
    return 1
}

# Stop the server and report whether it exited cleanly.
stop_server() {
    local rc=0
    kill "${SERVER_PID:-}" 2>/dev/null || true
    wait "${SERVER_PID:-}" 2>/dev/null || rc=$?
    SERVER_PID=""
    return "$rc"
}

test_config() {
    local config="${1%%|*}"
    local expect="${1#*|}"

    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BLUE}Testing: --uet ${config}${NC}"

    if ! start_server "$config"; then
        echo -e "${RED}✗ Server failed to start${NC}"
        tail -20 "$SERVER_LOG"
        FAILED+=("$config")
        stop_server || true
        return 1
    fi

    if ! grep -qF "$expect" "$SERVER_LOG"; then
        echo -e "${RED}✗ Startup log does not report: $expect${NC}"
        grep -i "uet" "$SERVER_LOG" || tail -20 "$SERVER_LOG"
        FAILED+=("$config")
        stop_server || true
        return 1
    fi

    if ! stop_server; then
        echo -e "${RED}✗ Server did not exit cleanly${NC}"
        tail -20 "$SERVER_LOG"
        FAILED+=("$config")
        return 1
    fi

    # The engine is torn down before the vfio-user context it maps guest
    # memory through, and says what it did on the way out.
    if ! grep -q "UET engine stats:" "$SERVER_LOG" ||
        ! grep -q "Shutdown complete" "$SERVER_LOG"; then
        echo -e "${RED}✗ Engine was not shut down${NC}"
        tail -20 "$SERVER_LOG"
        FAILED+=("$config")
        return 1
    fi

    echo -e "${GREEN}✓ Engine reported: $expect${NC}"
    PASSED+=("$config")
    return 0
}

test_rejected() {
    local config="$1"

    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BLUE}Testing rejection: --uet '${config}'${NC}"

    local out
    local rc=0
    out=$("$SERVER_BIN" --socket "$WORK_DIR/reject.sock" \
              --uet "$config" 2>&1) || rc=$?

    if [ "$rc" -eq 0 ] || ! grep -q "uet engine:" <<<"$out"; then
        echo -e "${RED}✗ Bad option was not refused${NC}"
        echo "$out" | head -10
        FAILED+=("reject '$config'")
        return 1
    fi
    if [ -S "$WORK_DIR/reject.sock" ]; then
        echo -e "${RED}✗ Server created its socket before refusing${NC}"
        FAILED+=("reject '$config'")
        return 1
    fi

    echo -e "${GREEN}✓ Refused: $(grep -m1 'uet engine:' <<<"$out")${NC}"
    PASSED+=("reject '$config'")
    return 0
}

# Without --tap the engine has nowhere to send, and says so.
test_no_wire() {
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BLUE}Testing the no-TAP warning${NC}"

    if ! start_server "ip=192.168.200.101"; then
        echo -e "${RED}✗ Server failed to start${NC}"
        FAILED+=("no wire")
        stop_server || true
        return 1
    fi
    stop_server || true

    if ! grep -q "no --tap: the engine has no wire" "$SERVER_LOG"; then
        echo -e "${RED}✗ No warning that the engine has no wire${NC}"
        FAILED+=("no wire")
        return 1
    fi

    echo -e "${GREEN}✓ Engine without a TAP is reported${NC}"
    PASSED+=("no wire")
    return 0
}

test_usage() {
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BLUE}Testing usage text${NC}"

    local out
    out=$("$SERVER_BIN" --help 2>&1 || true)
    if ! grep -q -- "--uet OPTIONS" <<<"$out" ||
        ! grep -q "sec=none|direct|cluster" <<<"$out"; then
        echo -e "${RED}✗ --uet missing from the usage text${NC}"
        FAILED+=("usage text")
        return 1
    fi

    echo -e "${GREEN}✓ Usage text documents --uet${NC}"
    PASSED+=("usage text")
    return 0
}

for entry in "${CONFIGS[@]}"; do
    test_config "$entry" || true
    echo ""
done

for config in "${BAD_CONFIGS[@]}"; do
    test_rejected "$config" || true
    echo ""
done

test_no_wire || true
echo ""
test_usage || true
echo ""

echo -e "${BLUE}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║  Test Summary                                               ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${GREEN}Passed: ${#PASSED[@]}${NC}"

if [ ${#FAILED[@]} -gt 0 ]; then
    echo -e "${RED}Failed: ${#FAILED[@]}${NC}"
    for name in "${FAILED[@]}"; do
        echo -e "  ${RED}✗${NC} $name"
    done
    echo ""
    echo -e "${RED}Some UET engine tests failed!${NC}"
    exit 1
fi

echo ""
echo -e "${GREEN}All UET engine tests passed!${NC}"
exit 0
