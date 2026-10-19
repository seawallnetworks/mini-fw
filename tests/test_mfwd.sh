#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
# mfwd: protocol, attach/detach, refusals, restarts and purge, on dummy
# interfaces in a private network namespace. No traffic (see
# scripts/smoke-test.sh for that). Needs root.
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
[[ -x $MFWD && -x $MFW ]] || { echo "build first: make"; exit 1; }
command -v bpftool >/dev/null || { echo "needs bpftool"; exit 1; }

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
# ip link doesn't show tcx programs; bpftool does
tc_on() {
    nsenter --net=/var/run/netns/$NS bpftool net show dev "$1" |
        grep -q 'tcx/ingress mfw_tc '
}
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
for i in d0 d1 d2; do ip -n "$NS" link add $i type dummy; ip -n "$NS" link set $i up; done

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
expect ok "TC on d0" tc_on d0
expect ok "TC on d1" tc_on d1
expect fail "no TC on d2" tc_on d2
same "show is canonical" "$(mfw show)" "acl 10 10 deny host 192.0.2.1
acl 100 10 permit tcp any any eq 22
acl 110 10 permit icmp any any
bind d0 in 10
bind d0 in 100
bind d1 in 110
set drop-ipv4-fragments 0"
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
expect fail "no TC on d1" tc_on d1
expect ok "empty policy" mfw apply /dev/null
same "nothing attached" "$(field attached)" -
expect fail "no TC on d0" tc_on d0

echo "== protocol errors"
same "unknown request" "$(raw 'FROB\n')" "ERR badreq unknown request 'FROB'"
same "lower case" "$(raw 'ping\n')" "ERR badreq unknown request 'ping'"
same "APPLY without END" "$(raw 'APPLY\nbind d0 in 10\n')" "ERR badreq request not complete"
same "no newline" "$(raw 'PING')" "ERR badreq request not complete"
same "too long" "$(raw '' huge)" "ERR badreq request too long"
same "too slow" "$(raw 'PI' hold)" "ERR badreq request not complete in time"
same "raw APPLY" "$(raw 'APPLY\nbind d2 in 100\nEND\n')" "OK 5"
same "SHOW framing" "$(raw 'SHOW\n')" "OK 2
bind d2 in 100
set drop-ipv4-fragments 0"
same "mfwd still serves" "$(raw 'PING\n')" "OK"

echo "== restart keeps the policy and the filtering"
expect ok "apply" mfw apply <(echo "$POLICY")
stop
expect ok "TC stays on d0 while mfwd is down" tc_on d0
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
expect ok "TC stays on d0" tc_on d0
expect ok "stats has every id" bash -c "$MFW -s $SOCK stats --json | python3 -c 'import json,sys; assert len(json.load(sys.stdin)) == 11'"

echo "== lost pins: the saved policy is applied again"
stop
rm -rf "$PINS"
start
same "attached again" "$(field attached)" d0,d1
expect ok "TC on d0" tc_on d0
grep -q "applying it again" "$LOG" && ok "log: applied again" || bad "log: applied again"

echo "== re-created interface"
ip -n "$NS" link del d0
ip -n "$NS" link add d0 type dummy; ip -n "$NS" link set d0 up
same "d0 no longer attached" "$(field attached)" d1
expect ok "apply again" mfw apply <(echo "$POLICY")
same "d0 attached again" "$(field attached)" d0,d1

echo "== purge"
stop
expect ok "mfwd -P" "$MFWD" -P -p "$PINS" -d "$STATE"
expect ok "pins removed" test ! -e "$PINS"
expect ok "saved policy removed" test ! -e "$STATE/policy"
expect fail "no TC on d0" tc_on d0

echo "== without mfwd"
out=$(mfw ping 2>&1)
same "exit status 2" "$?" 2
[[ $out == "mfw: cannot reach mfwd: "* ]] && ok "says why" || bad "says why: $out"

echo
echo "test_mfwd: $PASS passed, $FAIL failed"
[[ $FAIL -eq 0 ]]
