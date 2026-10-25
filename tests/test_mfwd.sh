#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
# mfwd: protocol, attach/detach, refusals, restarts and purge, on dummy
# interfaces in a private network namespace. No traffic (see
# scripts/smoke-test.sh for that). Needs root, and xdp-tools (xdp-loader,
# xdp-filter) and clang; MFW_NO_XDP=1 attaches at TC only, and needs
# neither.
#
# Uses its own pin root, socket and state directory, so it runs next to a
# live mini-fw without touching it.
set -u

ROOT=$(cd "$(dirname "$0")/.." && pwd)
MFWD=$ROOT/mfwd MFW=$ROOT/mfw
NS=mfwt-$$
PINS=/sys/fs/bpf/mfwt-$$
TMP=$(mktemp -d)
SOCK=$TMP/sock STATE=$TMP/state LOG=$TMP/log
PASS=0 FAIL=0 PID=

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
if [[ -z ${MFW_NO_XDP:-} ]] && ! command -v xdp-loader clang >/dev/null; then
    echo "needs xdp-tools and clang (or MFW_NO_XDP=1)"; exit 1
fi

cleanup() {
    [[ -n $PID ]] && kill "$PID" 2>/dev/null && wait "$PID" 2>/dev/null
    "$MFWD" -P -p "$PINS" -d "$STATE" >/dev/null 2>&1
    ip netns del "$NS" 2>/dev/null
    rm -rf "$TMP"
}
trap cleanup EXIT

ok()   { PASS=$((PASS + 1)); echo "  ok   $1"; }
bad()  { FAIL=$((FAIL + 1)); echo "  FAIL $1"; }
expect() {  # expect ok|fail "description" cmd...
    local want=$1 desc=$2 got; shift 2
    if "$@" >/dev/null 2>&1; then got=ok; else got=fail; fi
    [[ $got == "$want" ]] && ok "$desc" || bad "$desc (expected $want, got $got)"
}
same() {  # same "description" actual expected
    [[ $2 == "$3" ]] && ok "$1" || bad "$1: got '$2', want '$3'"
}

mfw()  { "$MFW" -s "$SOCK" "$@"; }
in_ns() { nsenter --net=/var/run/netns/$NS "$@"; }
# mini-fw's programs in the interface's XDP dispatcher
xdp_in() { in_ns xdp-loader status "$1" 2>/dev/null | grep -c ' mfw_xdp '; }
# ip link doesn't show tcx programs; bpftool does, and classic TC's
# (MFW_NO_TCX=1, or a kernel before 6.6) as clsact/ingress
tc_on() { in_ns bpftool net show dev "$1" | grep -Eq '(tcx|clsact)/ingress mfw_tc[ :]'; }
# mini-fw filters the interface, at XDP or TC
on() { [[ -z ${MFW_NO_XDP:-} && $(xdp_in "$1") == 1 ]] || tc_on "$1"; }
field() { mfw status | awk -v k="$1" '$1 == k { print $2 }'; }

start() {
    # nsenter execs mfwd, so $! is mfwd itself
    nsenter --net=/var/run/netns/$NS "$MFWD" -s "$SOCK" -p "$PINS" -d "$STATE" "$@" \
        >>"$LOG" 2>&1 &
    PID=$!
    for _ in $(seq 50); do [[ -S $SOCK ]] && mfw ping >/dev/null 2>&1 && return; sleep 0.1; done
    echo "mfwd did not start:"; cat "$LOG"; exit 1
}
stop() { kill "$PID"; wait "$PID" 2>/dev/null; PID=; }

# one raw request; prints the reply
raw() {
    python3 - "$SOCK" "$1" "${2:-}" <<'EOF'
import socket, sys, time
s = socket.socket(socket.AF_UNIX); s.connect(sys.argv[1])
data = sys.argv[2].encode().decode('unicode_escape').encode('latin-1')
if sys.argv[3] == 'huge':
    data = b'APPLY\n' + b'# ' + b'x' * (1100 * 1024) + b'\nEND\n'
s.sendall(data)
if sys.argv[3] != 'hold':
    s.shutdown(socket.SHUT_WR)
out = b''
while True:
    b = s.recv(65536)
    if not b: break
    out += b
sys.stdout.write(out.decode())
EOF
}

ip netns add "$NS"
for i in d0 d1 d2 d3; do ip -n "$NS" link add $i type dummy; ip -n "$NS" link set $i up; done

POLICY="acl 10 10 deny host 192.0.2.1
acl 100 10 permit tcp any any eq 22
acl 110 10 permit icmp any any
bind d0 in 10
bind d0 in 100
bind d1 in 110"

echo "== start"
start -m 0660
expect ok "ping" mfw ping
same "socket mode" "$(stat -c %a "$SOCK")" 660
same "no generation yet" "$(field generation)" none
same "show: nothing applied" "$(mfw show)" ""

echo "== apply"
expect ok "apply" mfw apply <(echo "$POLICY")
same "generation 1" "$(field generation)" 1
same "attached d0,d1" "$(field attached)" d0,d1
expect ok "on d0" on d0
expect ok "on d1" on d1
expect fail "not on d2" on d2
same "show is canonical" "$(mfw show)" "acl 10 10 deny host 192.0.2.1
acl 100 10 permit tcp any any eq 22
acl 110 10 permit icmp any any
bind d0 in 10
bind d0 in 100
bind d1 in 110
set drop-ipv4-fragments 0
set reply-idle-tcp 86400
set reply-idle-udp 180"
expect ok "check accepts it" mfw check <(echo "$POLICY")
expect ok "stats" bash -c "$MFW -s $SOCK stats --json | python3 -c 'import json,sys; assert len(json.load(sys.stdin)) == 11'"

echo "== refusals leave the policy in place"
out=$(mfw apply <(printf 'acl 100 10 permit ip any any\nbind d0 in 100\nacl 10 10 deny 10.0.0.0 0.0.2.255\n') 2>&1)
same "exit status 1" "$?" 1
same "names the line" "$out" "mfw: line 3: non-contiguous wildcard '0.0.2.255' not supported"
same "generation unchanged" "$(field generation)" 1
same "still attached" "$(field attached)" d0,d1
out=$(mfw check <(printf 'bind d0 in 10\nbind d0 in 20\n') 2>&1)
same "check refuses locally" "$out" "mfw: line 2: d0 already has standard list 10"

echo "== missing interfaces"
out=$(mfw apply <(printf '%s\nbind d9 in 110\n' "$POLICY"))
same "apply reports d9" "$(echo "$out" | tail -1)" "not present, so not attached: d9"
same "status: missing d9" "$(field missing)" d9
same "status: attached unchanged" "$(field attached)" d0,d1

echo "== unbinding detaches"
expect ok "apply d0 only" mfw apply <(printf 'acl 100 10 permit ip any any\nbind d0 in 100\n')
same "attached d0" "$(field attached)" d0
expect fail "not on d1" on d1
expect ok "empty policy" mfw apply /dev/null
same "nothing attached" "$(field attached)" -
expect fail "not on d0" on d0

echo "== protocol errors"
same "unknown request" "$(raw 'FROB\n')" "ERR badreq unknown request 'FROB'"
same "lower case" "$(raw 'ping\n')" "ERR badreq unknown request 'ping'"
same "APPLY without END" "$(raw 'APPLY\nbind d0 in 10\n')" "ERR badreq request not complete"
same "no newline" "$(raw 'PING')" "ERR badreq request not complete"
same "too long" "$(raw '' huge)" "ERR badreq request too long"
same "too slow" "$(raw 'PI' hold)" "ERR badreq request not complete in time"
same "raw APPLY" "$(raw 'APPLY\nbind d2 in 100\nEND\n')" "OK 5"
same "SHOW framing" "$(raw 'SHOW\n')" "OK 4
bind d2 in 100
set drop-ipv4-fragments 0
set reply-idle-tcp 86400
set reply-idle-udp 180"
same "mfwd still serves" "$(raw 'PING\n')" "OK"

echo "== restart keeps the policy and the filtering"
expect ok "apply" mfw apply <(echo "$POLICY")
stop
expect ok "stays on d0 while mfwd is down" on d0
start
same "generation kept" "$(field generation)" 6
same "policy kept" "$(mfw show | head -1)" "acl 10 10 deny host 192.0.2.1"
grep -q "policy generation 6 is in place" "$LOG" && ok "log: in place" || bad "log: in place"

echo "== stats map from an older build is replaced"
stop
rm "$PINS/maps/stats"
bpftool map create "$PINS/maps/stats" type percpu_array key 4 value 8 entries 10 name stats
start
same "generation kept" "$(field generation)" 6
expect ok "stays on d0" on d0
expect ok "stats has every id" bash -c "$MFW -s $SOCK stats --json | python3 -c 'import json,sys; assert len(json.load(sys.stdin)) == 11'"

echo "== lost pins: the saved policy is applied again"
stop
rm -rf "$PINS"
start
same "attached again" "$(field attached)" d0,d1
expect ok "on d0" on d0
grep -q "applying it again" "$LOG" && ok "log: applied again" || bad "log: applied again"

echo "== re-created interface"
ip -n "$NS" link del d0
ip -n "$NS" link add d0 type dummy; ip -n "$NS" link set d0 up
same "d0 no longer attached" "$(field attached)" d1
expect ok "apply again" mfw apply <(echo "$POLICY")
same "d0 attached again" "$(field attached)" d0,d1

if [[ -z ${MFW_NO_XDP:-} ]]; then
echo "== sharing the XDP hook"
# dummy interfaces have no native XDP: mfwd fell back to skb
same "d0 in its dispatcher" "$(xdp_in d0)" 1
expect fail "not at TC on d0" tc_on d0
stop
start
same "one program in d0's after a restart" "$(xdp_in d0)" 1
# xdp-filter is libxdp's: mini-fw joins its dispatcher, and leaves it to it
in_ns xdp-filter load -m skb d2
# the customer's program on d3 is not: it stays, and mini-fw goes to TC
cat > "$TMP/pass.bpf.c" <<'EOF'
struct xdp_md;
__attribute__((section("xdp"), used)) int customer(struct xdp_md *ctx)
{
    return 2;  /* XDP_PASS */
}
char LICENSE[] __attribute__((section("license"), used)) = "GPL";
EOF
clang -O2 -target bpf -c "$TMP/pass.bpf.c" -o "$TMP/pass.bpf.o"
in_ns ip link set dev d3 xdpgeneric obj "$TMP/pass.bpf.o" sec xdp
xdp_id() { in_ns ip -d link show "$1" | sed -n 's/.*prog\/xdp id \([0-9]*\).*/\1/p'; }
customer=$(xdp_id d3)
expect ok "apply binding d2, d3" mfw apply <(printf '%s\nbind d2 in 110\nbind d3 in 110\n' "$POLICY")
same "attached d0..d3" "$(field attached)" d0,d1,d2,d3
same "d2 in xdp-filter's dispatcher" "$(xdp_in d2)" 1
expect ok "xdp-filter still there" bash -c "nsenter --net=/var/run/netns/$NS xdp-loader status d2 | grep -q xdpfilt_"
expect ok "TC on d3" tc_on d3
same "d3 degraded" "$(field degraded)" d3
same "the customer's program left alone" "$(xdp_id d3)" "$customer"
grep -q "d3: customer holds the XDP hook" "$LOG" && ok "log: degraded" || bad "log: degraded"
# once the hook is free, a restart moves d3 to XDP
in_ns ip link set dev d3 xdpgeneric off
stop
start
same "d3 in a dispatcher" "$(xdp_in d3)" 1
expect fail "not at TC on d3" tc_on d3
same "nothing degraded" "$(field degraded)" -
expect ok "apply without d2" mfw apply <(printf '%s\nbind d3 in 110\n' "$POLICY")
same "d2 left" "$(xdp_in d2)" 0
expect ok "xdp-filter stays" bash -c "nsenter --net=/var/run/netns/$NS xdp-loader status d2 | grep -q xdpfilt_"
in_ns xdp-filter unload d2 --all
# pins lost while attached: the program they named is taken out, not doubled
stop
rm -rf "$PINS"
start
same "one program in d0's after lost pins" "$(xdp_in d0)" 1
fi

echo "== sw_flowd's table"
# stand-ins for sw_flowd's pin, on the test's own bpffs; real traffic is
# in scripts/smoke-test.sh. mfwd binds the table when it starts.
FLOWS=/sys/fs/bpf/seawall/flows
# the ids of the maps mini-fw's loaded programs use
prog_maps() { bpftool -j prog show | python3 -c '
import json, sys
print(" ".join(str(m) for p in json.load(sys.stdin)
               if p.get("name") in ("mfw_tc", "mfw_xdp") for m in p.get("map_ids", [])))'; }
map_id() { bpftool -j map show pinned "$1" | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])'; }
grep -q 'no sw_flowd flow table' "$LOG" && ok "log: no table" || bad "log: no table"
same "flows: none" "$(field flows)" none
mkdir -p "$FLOWS"
bpftool map create "$FLOWS/outbound" type lru_hash key 24 value 8 entries 1024 name outbound
sleep 1.5
same "a table that comes later is not picked up" "$(field flows)" none
stop
start
same "flows: sw_flowd after a restart" "$(field flows)" sw_flowd
grep -q "reading sw_flowd's flow table (1024 flows)" "$LOG" && ok "log: reading" || bad "log: reading"
id=$(map_id "$FLOWS/outbound")
[[ " $(prog_maps) " == *" $id "* ]] && ok "the loaded programs use the pinned table" \
    || bad "the loaded programs use the pinned table ($id not in $(prog_maps))"
if [[ -z ${MFW_NO_XDP:-} ]]; then
    # each interface's copy in its dispatcher, not only the TC entry
    for i in d0 d1; do
        xid=$(in_ns xdp-loader status "$i" 2>/dev/null | awk '$3 == "mfw_xdp" { print $4 }')
        [[ -n $xid ]] && bpftool -j prog show id "$xid" | grep -q "\"map_ids\":\[[0-9,]*\b$id\b" \
            && ok "$i's XDP copy uses it" || bad "$i's XDP copy uses it (prog '$xid')"
    done
fi
rm "$FLOWS/outbound"
bpftool map create "$FLOWS/outbound" type lru_hash key 24 value 16 entries 1024 name outbound
stop
start
same "another layout is refused" "$(field flows)" none
grep -q "is not the layout this mfwd reads" "$LOG" && ok "log: refused" || bad "log: refused"
rm -rf "$FLOWS"

echo "== purge"
stop
# in the interfaces' namespace: a classic TC filter is removed there
expect ok "mfwd -P" nsenter --net=/var/run/netns/$NS "$MFWD" -P -p "$PINS" -d "$STATE"
expect ok "pins removed" test ! -e "$PINS"
expect ok "saved policy removed" test ! -e "$STATE/policy"
expect fail "not on d0" on d0
[[ -n ${MFW_NO_XDP:-} ]] || same "nothing in d3's dispatcher" "$(xdp_in d3)" 0

echo "== without mfwd"
out=$(mfw ping 2>&1)
same "exit status 2" "$?" 2
[[ $out == "mfw: cannot reach mfwd: "* ]] && ok "says why" || bad "says why: $out"

echo
echo "test_mfwd: $PASS passed, $FAIL failed"
[[ $FAIL -eq 0 ]]
