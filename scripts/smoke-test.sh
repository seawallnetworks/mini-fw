#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
# End-to-end smoke test: real traffic through mfwd in two network
# namespaces.
#
#   [mfw-cli 10.200.0.1] --veth-- [mfw-fw 10.200.0.2  veth-fw ]
#   [mfw-cli 10.201.0.1] --veth-- [mfw-fw 10.201.0.2  veth-fw2]
#
# mfwd runs in mfw-fw with its own pin root, socket and state directory,
# so this runs next to a live mini-fw without touching it. The second veth
# pair checks that each interface enforces only its own lists. Needs root
# and xdp-tools (xdp-loader); MFW_NO_XDP=1 filters at TC only, and needs no
# xdp-tools. "reply" ACEs are tested with sw_flowd recording fw's flows
# (SW_FLOWD, or ../sw_flowd/sw_flowd), and skipped without it.
set -u

ROOT=$(cd "$(dirname "$0")/.." && pwd)
MFWD=$ROOT/mfwd MFW=$ROOT/mfw
FLOWD=${SW_FLOWD:-$ROOT/../sw_flowd/sw_flowd}
CLI=mfw-cli-$$ FW=mfw-fw-$$
CLI_IP=10.200.0.1 FW_IP=10.200.0.2
CLI_IP2=10.201.0.1 FW_IP2=10.201.0.2
PINS=/sys/fs/bpf/mfw-smoke-$$
TMP=$(mktemp -d)
SOCK=$TMP/sock
PASS=0 FAIL=0 PID= FLOWD_PID=

[[ $EUID -eq 0 ]] || { echo "run as root"; exit 1; }
# Its own mount namespace and bpffs: libxdp pins each dispatcher under
# /sys/fs/bpf/xdp, and those pins would outlive the namespace's interfaces
# on the host's bpffs.
if [[ ${1:-} != --private ]]; then
    exec unshare --mount --propagation private "$0" --private "$@"
fi
shift
mount -t bpf bpf /sys/fs/bpf || { echo "cannot mount a private bpffs"; exit 1; }
[[ -x $MFWD && -x $MFW ]] || { echo "build first: make"; exit 1; }
command -v bpftool >/dev/null || { echo "needs bpftool"; exit 1; }
if [[ -z ${MFW_NO_XDP:-} ]] && ! command -v xdp-loader >/dev/null; then
    echo "needs xdp-tools (or MFW_NO_XDP=1)"; exit 1
fi

in_cli() { ip netns exec "$CLI" "$@"; }
in_fw()  { ip netns exec "$FW" "$@"; }
# ip link doesn't show tcx programs; bpftool does, and classic TC's
# (MFW_NO_TCX=1, or a kernel before 6.6) as clsact/<hook>
tcx_on() { in_fw bpftool net show dev "$1" | grep -Eq "(tcx|clsact)/${2:-ingress} mfw_tc[ :]"; }
xdp_on() { in_fw ip link show "$1" | grep -q ' xdp'; }
# mini-fw in the interface's XDP dispatcher; xdp-loader reads it from the
# test's bpffs, which ip netns exec hides
xdp_in() { nsenter --net=/var/run/netns/$FW xdp-loader status "$1" 2>/dev/null |
           grep -q ' mfw_xdp '; }
# mini-fw filters the interface, at XDP or TC
on()     { { [[ -z ${MFW_NO_XDP:-} ]] && xdp_in "$1"; } || tcx_on "$1"; }
mfw()    { "$MFW" -s "$SOCK" "$@"; }

start_mfwd() {
    # nsenter (not ip netns exec, which hides the test's bpffs) execs mfwd
    nsenter --net=/var/run/netns/$FW "$MFWD" -s "$SOCK" -p "$PINS" -d "$TMP/state" \
        >>"$TMP/log" 2>&1 &
    PID=$!
    for _ in $(seq 50); do mfw ping >/dev/null 2>&1 && return; sleep 0.1; done
    echo "mfwd did not start:"; cat "$TMP/log"; exit 1
}
stop_mfwd() { kill "$PID"; wait "$PID" 2>/dev/null; PID=; }

start_flowd() {
    printf 'interfaces = veth-fw veth-fw2\ntick_ms = 200\n' > "$TMP/sw_flowd.conf"
    nsenter --net=/var/run/netns/$FW "$FLOWD" -c "$TMP/sw_flowd.conf" \
        >>"$TMP/sw_flowd.log" 2>&1 &
    FLOWD_PID=$!
}
stop_flowd() { kill "$FLOWD_PID"; wait "$FLOWD_PID" 2>/dev/null; FLOWD_PID=; }
flows_is() { mfw status | grep -q "^flows  *$1\$"; }

cleanup() {
    [[ -n $PID ]] && stop_mfwd
    [[ -n $FLOWD_PID ]] && stop_flowd
    [[ -x $FLOWD ]] && nsenter --net=/var/run/netns/$FW "$FLOWD" -P >/dev/null 2>&1
    "$MFWD" -P -p "$PINS" -d "$TMP/state" >/dev/null 2>&1
    for ns in "$CLI" "$FW"; do
        ip netns pids "$ns" 2>/dev/null | xargs -r kill 2>/dev/null
        ip netns del "$ns" 2>/dev/null
    done
    rm -rf "$TMP"
}
trap cleanup EXIT

expect() {  # expect ok|fail "description" cmd...
    local want=$1 desc=$2 got; shift 2
    if "$@" >/dev/null 2>&1; then got=ok; else got=fail; fi
    if [[ $got == "$want" ]]; then
        PASS=$((PASS + 1)); echo "  ok   $desc"
    else
        FAIL=$((FAIL + 1)); echo "  FAIL $desc (expected $want, got $got)"
    fi
}

# the policy, one item per argument
policy() { printf '%s\n' "$@" | mfw apply >/dev/null; }

ping_fw()  { in_cli ping -c1 -W1 "$FW_IP"; }
ping_fw2() { in_cli ping -c1 -W1 "$FW_IP2"; }
tcp_to_fw()  { in_cli nc -z -w1 "$FW_IP" "$1"; }
tcp_to_cli() { in_fw  nc -z -w1 "$CLI_IP" "$1"; }
udp_echo_fw() { in_cli bash -c "echo hi | nc -u -w1 $FW_IP $1 | grep -q hi"; }
udp_echo_cli() { in_fw bash -c "echo hi | nc -u -w1 $CLI_IP $1 | grep -q hi"; }
# n bare ACKs from cli to fw's port: what an ACK flood sends
acks_to_fw() {
    in_cli python3 -c "
import socket, struct
s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
for i in range($2):
    s.sendto(struct.pack('!HHIIBBHHH', 40000 + i, $1, 1, 1, 5 << 4, 0x10,
                         1024, 0, 0), ('$FW_IP', 0))"
}
stat_of() { mfw stats --json | python3 -c "import json,sys; print(json.load(sys.stdin)['$1'])"; }

# ---- topology ----
ip netns add "$CLI"; ip netns add "$FW"
ip link add veth-cli netns "$CLI" type veth peer name veth-fw netns "$FW"
ip link add veth-cli2 netns "$CLI" type veth peer name veth-fw2 netns "$FW"
in_cli ip addr add $CLI_IP/24 dev veth-cli; in_cli ip addr add $CLI_IP2/24 dev veth-cli2
in_fw  ip addr add $FW_IP/24 dev veth-fw;   in_fw  ip addr add $FW_IP2/24 dev veth-fw2
for i in veth-cli veth-cli2 lo; do in_cli ip link set $i up; done
for i in veth-fw veth-fw2 lo; do in_fw ip link set $i up; done

# listeners: TCP 8080/8081 on fw, TCP 9090 on cli, UDP echo 5353 on fw
for port in 8080 8081; do
    in_fw bash -c "while :; do nc -l $port >/dev/null; done" &
done
in_cli bash -c "while :; do nc -l 9090 >/dev/null; done" &
in_cli python3 -c "
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(('$CLI_IP', 5354))
while True:
    d, a = s.recvfrom(2048); s.sendto(d, a)" &
in_fw python3 -c "
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(('$FW_IP', 5353))
while True:
    d, a = s.recvfrom(2048); s.sendto(d, a)" &
disown -a
sleep 0.5

echo "== baseline (no mini-fw)"
expect ok "ping" ping_fw

echo "== mfwd running, empty policy"
start_mfwd
expect ok "ping" ping_fw
expect fail "nothing attached" on veth-fw

echo "== standard list (blacklist)"
policy "acl 10 10 deny host $CLI_IP" "acl 10 20 permit any" "bind veth-fw in 10"
expect ok   "attached by the policy" on veth-fw
if [[ -z ${MFW_NO_XDP:-} ]]; then
    expect fail "at XDP, in a dispatcher: not at TC" tcx_on veth-fw
else
    expect fail "TC only: XDP left free" xdp_on veth-fw
fi
expect fail "ping from denied host" ping_fw
expect ok   "std_deny counted" test "$(stat_of std_deny)" -gt 0
policy "acl 10 20 permit any" "bind veth-fw in 10"
expect ok   "ping after removing the deny ACE" ping_fw
policy "acl 10 5 deny 10.200.0.0 0.0.0.255" "acl 10 20 permit any" "bind veth-fw in 10"
expect fail "ping denied by wildcard ACE at seq 5" ping_fw
policy "acl 10 10 deny host 192.0.2.1" "bind veth-fw in 10"
expect ok   "ping not on the blacklist (no implicit deny)" ping_fw
policy
expect ok   "empty policy: ping" ping_fw
expect fail "empty policy: detached" on veth-fw

echo "== extended list (implicit deny)"
EXT=("acl 100 10 permit tcp any host $FW_IP eq 8080"
     "acl 100 20 permit icmp any any"
     "acl 100 30 permit udp any any eq 5353")
policy "${EXT[@]}" "bind veth-fw in 100"
expect ok   "tcp 8080 permitted" tcp_to_fw 8080
expect fail "tcp 8081 implicit deny" tcp_to_fw 8081
expect ok   "ping permitted" ping_fw
expect ok   "udp 5353 echo (egress never filtered)" udp_echo_fw 5353
expect fail "outbound tcp: SYN-ACK hits implicit deny (stateless)" tcp_to_cli 9090
expect ok   "ext_implicit_deny counted" test "$(stat_of ext_implicit_deny)" -gt 0
policy "${EXT[@]}" "acl 100 40 permit tcp any any established" "bind veth-fw in 100"
expect ok   "outbound tcp with 'established'" tcp_to_cli 9090
expect fail "inbound SYN to 8081 still denied" tcp_to_fw 8081
policy "bind veth-fw in 101"
expect fail "bound empty extended list denies all IPv4" ping_fw

echo "== per-interface lists"
policy "acl 100 10 permit tcp any any eq 8080" "bind veth-fw in 100"
expect fail "veth-fw: ping hits list 100's implicit deny" ping_fw
expect ok   "veth-fw2: not bound, ping passes" ping_fw2
policy "acl 100 10 permit tcp any any eq 8080" "acl 20 10 deny host $CLI_IP2" \
       "bind veth-fw in 100" "bind veth-fw2 in 20"
expect fail "veth-fw2: its own blacklist" ping_fw2
expect ok   "veth-fw: list 20 not applied there" tcp_to_fw 8080
policy "acl 20 10 deny host $CLI_IP2" "bind veth-fw2 in 20"
expect ok   "veth-fw: unbound, ping passes" ping_fw
expect fail "veth-fw2: still blocked" ping_fw2

echo "== mfwd down: filtering goes on"
stop_mfwd
expect fail "veth-fw2 still blocked without mfwd" ping_fw2
start_mfwd
expect fail "veth-fw2 still blocked after restart" ping_fw2
expect ok   "policy kept" bash -c "$MFW -s $SOCK show | grep -q 'bind veth-fw2 in 20'"
policy

echo "== reply: replies to the flows fw opened (sw_flowd)"
if [[ -x $FLOWD ]]; then
    REPLY=("acl 100 10 permit tcp any host $FW_IP eq 8080"
           "acl 100 20 permit tcp any any reply"
           "acl 100 30 permit udp any any reply"
           "bind veth-fw in 100")
    policy "${REPLY[@]}"
    expect ok   "flows: none before sw_flowd" flows_is none
    expect fail "outbound tcp: reply matches nothing without sw_flowd" tcp_to_cli 9090
    start_flowd
    sleep 0.5   # sw_flowd's pins, and its first sync: the ephemeral port range
    expect ok   "flows: none until mfwd restarts" flows_is none
    stop_mfwd; start_mfwd   # mfwd binds sw_flowd's table when it starts
    expect ok   "flows: sw_flowd once mfwd starts after it" flows_is sw_flowd
    expect ok   "outbound tcp with 'reply'" tcp_to_cli 9090
    expect ok   "outbound udp with 'reply'" udp_echo_cli 5354
    expect fail "inbound SYN to 8081 still denied" tcp_to_fw 8081
    expect ok   "inbound tcp 8080 still permitted" tcp_to_fw 8080
    before=$(stat_of ext_implicit_deny)
    acks_to_fw 8081 100
    expect ok   "an ACK flood is dropped" test $(( $(stat_of ext_implicit_deny) - before )) -ge 100
    policy "${REPLY[@]}" "acl 100 40 permit tcp any any established"
    before=$(stat_of ext_permit)
    acks_to_fw 8081 100
    expect ok   "('established' lets the same flood in)" \
        test $(( $(stat_of ext_permit) - before )) -ge 100
    policy "${REPLY[@]}"
    stop_flowd
    expect ok   "sw_flowd stopped: its pinned link still records" tcp_to_cli 9090
    # mfwd keeps the table it bound, whose flows match until idle, until
    # it restarts: a layout change restarts the readers (0009)
    nsenter --net=/var/run/netns/$FW "$FLOWD" -P >/dev/null 2>&1
    stop_mfwd; start_mfwd
    expect ok   "flows: none for an mfwd started without sw_flowd" flows_is none
    expect fail "replies denied again" tcp_to_cli 9090
    policy
else
    echo "  skip: no sw_flowd at $FLOWD (set SW_FLOWD)"
fi

echo "== ingress only; egress is never filtered"
policy "acl 100 10 permit ip any any" "bind veth-fw in 100"
expect fail "nothing at TC egress" tcx_on veth-fw egress
expect fail "bind ... out refused" policy "bind veth-fw out 100"
expect fail "ports on a standard list refused" policy "acl 10 10 deny host 1.1.1.1 eq 22"
expect fail "non-contiguous wildcard refused" policy "acl 10 10 deny 10.0.0.0 0.0.2.255"
expect ok   "refusals left the policy in place" ping_fw

echo "== stats"
expect ok "stats json" bash -c "$MFW -s $SOCK stats --json | python3 -m json.tool"

echo "== purge"
stop_mfwd
expect ok "mfwd -P" "$MFWD" -P -p "$PINS" -d "$TMP/state"
expect ok "pins removed" test ! -e "$PINS"
expect ok "ping after purge" ping_fw
expect ok "tcp 8081 after purge" tcp_to_fw 8081

echo
echo "smoke: $PASS passed, $FAIL failed"
[[ $FAIL -eq 0 ]]
