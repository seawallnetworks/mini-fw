#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
# End-to-end smoke test for stateless mini-fw in two network namespaces:
#
#   [mfw-cli 10.200.0.1] --veth-- [mfw-fw 10.200.0.2, mfw attached on veth-fw]
#
# Uses nsenter --net (not "ip netns exec") so the host's /sys/fs/bpf stays
# visible and pins persist between mfw invocations. Needs root.
set -u

MFW=${MFW:-$(cd "$(dirname "$0")/.." && pwd)/mfw}
CLI=mfw-cli FW=mfw-fw
CLI_IP=10.200.0.1 FW_IP=10.200.0.2
PASS=0 FAIL=0

[[ $EUID -eq 0 ]] || { echo "run as root"; exit 1; }
[[ -x $MFW ]] || { echo "build first: make"; exit 1; }
if [[ -e /sys/fs/bpf/mfw ]]; then
    echo "/sys/fs/bpf/mfw already exists; refusing to clobber a live mini-fw"
    exit 1
fi

in_cli() { ip netns exec "$CLI" "$@"; }
in_fw()  { ip netns exec "$FW" "$@"; }
mfw()    { nsenter --net=/var/run/netns/$FW "$MFW" "$@"; }

cleanup() {
    for ns in "$CLI" "$FW"; do
        ip netns pids "$ns" 2>/dev/null | xargs -r kill 2>/dev/null
    done
    mfw detach -i veth-fw --purge-maps >/dev/null 2>&1
    ip netns del "$CLI" 2>/dev/null
    ip netns del "$FW" 2>/dev/null
}
trap cleanup EXIT

expect() {  # expect ok|fail "description" cmd...
    local want=$1 desc=$2; shift 2
    if "$@" >/dev/null 2>&1; then got=ok; else got=fail; fi
    if [[ $got == "$want" ]]; then
        PASS=$((PASS + 1)); echo "  ok   $desc"
    else
        FAIL=$((FAIL + 1)); echo "  FAIL $desc (expected $want, got $got)"
    fi
}

ping_fw()  { in_cli ping -c1 -W1 "$FW_IP"; }
tcp_to_fw()  { in_cli nc -z -w1 "$FW_IP" "$1"; }
tcp_to_cli() { in_fw  nc -z -w1 "$CLI_IP" "$1"; }
udp_echo_fw() { in_cli bash -c "echo hi | nc -u -w1 $FW_IP $1 | grep -q hi"; }
stat_of() { mfw stats --json | python3 -c "import json,sys; print(json.load(sys.stdin)['$1'])"; }

reset_policy() {
    mfw no ip access-group in veth-fw >/dev/null 2>&1
    for l in 10 20 100 101 110; do mfw no ip access-list $l >/dev/null 2>&1; done
}

# ---- topology ----
cleanup
ip netns add "$CLI"; ip netns add "$FW"
ip link add veth-cli netns "$CLI" type veth peer name veth-fw netns "$FW"
in_cli ip addr add $CLI_IP/24 dev veth-cli; in_cli ip link set veth-cli up; in_cli ip link set lo up
in_fw  ip addr add $FW_IP/24  dev veth-fw;  in_fw  ip link set veth-fw up;  in_fw  ip link set lo up
# GRO on the peer lets native veth XDP see normal frames; harmless otherwise.
in_cli ethtool -K veth-cli gro on >/dev/null 2>&1 || true

# listeners: TCP 8080/8081 on fw, TCP 9090 on cli, UDP echo 5353 on fw
for port in 8080 8081; do
    in_fw bash -c "while :; do nc -l $port >/dev/null; done" &
done
in_cli bash -c "while :; do nc -l 9090 >/dev/null; done" &
in_fw python3 -c "
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(('$FW_IP', 5353))
while True:
    d, a = s.recvfrom(2048); s.sendto(d, a)" &
disown -a
sleep 0.5

echo "== baseline (no mini-fw)"
expect ok "ping" ping_fw

echo "== attach, nothing bound (fail-open)"
expect ok "attach" mfw attach -i veth-fw
expect ok "ping" ping_fw
expect ok "tcp 8080" tcp_to_fw 8080
expect ok "re-attach replaces in place" mfw attach -i veth-fw
expect ok "ping after re-attach" ping_fw

echo "== standard ACL @ XDP (blacklist)"
mfw ip access-list 10 deny host $CLI_IP
mfw ip access-list 10 permit any
mfw ip access-group 10 in veth-fw
expect fail "ping from denied host" ping_fw
expect ok   "std_deny counted" test "$(stat_of std_deny)" -gt 0
mfw no ip access-list 10 10
expect ok   "ping after removing the deny ACE" ping_fw
mfw ip access-list 10 5 deny 10.200.0.0 0.0.0.255
expect fail "ping denied by wildcard ACE at seq 5" ping_fw
reset_policy
expect ok   "ping after unbinding" ping_fw

echo "== standard list, miss → pass (no implicit deny)"
mfw ip access-list 10 deny host 192.0.2.1
mfw ip access-group 10 in veth-fw
expect ok "ping (not on blacklist)" ping_fw
reset_policy

echo "== extended ACL @ XDP (implicit deny)"
mfw ip access-list 100 permit tcp any host $FW_IP eq 8080
mfw ip access-list 100 permit icmp any any
mfw ip access-list 100 permit udp any any eq 5353
mfw ip access-group 100 in veth-fw
expect ok   "tcp 8080 permitted" tcp_to_fw 8080
expect fail "tcp 8081 implicit deny" tcp_to_fw 8081
expect ok   "ping permitted" ping_fw
expect ok   "udp 5353 echo (egress never filtered)" udp_echo_fw 5353
expect fail "outbound tcp: SYN-ACK hits implicit deny (stateless)" tcp_to_cli 9090
expect ok   "ext_implicit_deny counted" test "$(stat_of ext_implicit_deny)" -gt 0
mfw ip access-list 100 permit tcp any any established
expect ok   "outbound tcp with 'established'" tcp_to_cli 9090
expect fail "inbound SYN to 8081 still denied" tcp_to_fw 8081
reset_policy

echo "== empty extended list bound = deny all IPv4"
mfw ip access-group 101 in veth-fw   # list 101 has no ACEs
expect fail "ping with bound empty list" ping_fw
reset_policy

echo "== XDP only; egress is never filtered"
expect ok   "no TC filters attached" \
    bash -c "! nsenter --net=/var/run/netns/$FW tc filter show dev veth-fw ingress | grep -q . &&
             ! nsenter --net=/var/run/netns/$FW tc filter show dev veth-fw egress | grep -q ."
expect ok   "XDP program attached" \
    bash -c "nsenter --net=/var/run/netns/$FW ip link show veth-fw | grep -q xdp"
expect fail "access-group out rejected" mfw ip access-group 100 out veth-fw

echo "== CLI validation"
expect fail "ports on standard list" mfw ip access-list 10 deny host 1.1.1.1 eq 22
expect fail "non-contiguous wildcard" mfw ip access-list 10 deny 10.0.0.0 0.0.2.255
expect fail "access-group on unattached iface" mfw ip access-group 10 in lo
expect fail "set-default allow" mfw set-default allow

echo "== stats: one outcome per packet"
expect ok "stats json" mfw stats --json

echo "== detach --purge-maps"
expect ok "detach" mfw detach -i veth-fw --purge-maps
expect ok "pins removed" test ! -e /sys/fs/bpf/mfw
expect ok "ping after detach" ping_fw
expect ok "tcp 8081 after detach" tcp_to_fw 8081

echo
echo "smoke: $PASS passed, $FAIL failed"
[[ $FAIL -eq 0 ]]
