# mini-fw: Implementation (stateless XDP ACL, mfwd)

| Field | Value |
|-------|-------|
| **Document** | Implementation description — what is actually built |
| **Scope** | Step 1: stateless, ingress-only, XDP-only ACL for a local VM, per-interface lists, driven by the mfwd daemon |
| **Version** | mfwd / mfw 0.3.0, ABI 2 |
| **Date** | 2026-10-12 |
| **Target** | Linux ≥ 5.12 with BTF, libbpf ≥ 0.7, clang |
| **Related** | [`design.md`](design.md) (full v1 design, Rev 18), [`../README.md`](../README.md) (operator quick start) |

`design.md` describes the full v1 system: XDP and TC hooks, egress filtering,
Cilium-style conntrack and fragment tracking. Step 1 deliberately builds a
much smaller subset. **This document is the source of truth for what the code
does today.** Where the two disagree, §10 explains why.

---

## 1. Scope

### 1.1 What step 1 is

- An **IPv4 host firewall for a single local VM**: it protects the machine it runs on.
- **Inbound only.** Packets the host sends are never inspected.
- **One XDP program**, attached to every protected interface, with **one
  ruleset per interface**. Nothing is attached to TC.
- **Stateless.** Every packet is judged on its own headers. There is no connection table.
- **A daemon, mfwd, owns the kernel side.** Clients send it the whole policy
  over a Unix socket: the `mfw` tool, or a front end such as sw_configd
  through `libmfw.a`.
- **Cisco IOS-style numbered ACLs**:
  - standard lists 1–99 match source IP only, and act as a blacklist;
  - extended lists 100–199 match protocol, addresses, ports and TCP `established`, with implicit deny.

### 1.2 What step 1 is not

| Not included | Consequence |
|--------------|-------------|
| Router / forward mode | Not a goal: the host is an endpoint |
| Egress filtering | Outbound traffic always leaves untouched |
| Conntrack | Replies to outbound connections must be permitted by rules (§8.1) |
| IPv4 fragment tracking | Non-first fragments cannot match port rules (§8.2) |
| IPv6 / ARP filtering | Non-IPv4 always passes to the kernel |
| SYN cookies in XDP | Rely on the kernel's own `tcp_syncookies` (§8.6) |
| Rate limiting, logging per packet | Not implemented |

---

## 2. Architecture

```text
 sw_configd ──┐  libmfw.a: mfw_policy_parse() checks a policy locally,
 mfw tool  ───┤            mfw_apply() etc. send requests
              ▼
      /run/mfwd.sock  (one request per connection, line protocol, §7)
              │
 ┌────────────┴──────────────────────────────┐
 │ mfwd (root; CAP_BPF, CAP_NET_ADMIN)       │   /run/mfwd/policy
 │  parse + check → compile per interface →  │── applied policy, so a
 │  attach / swap rulesets / detach          │   restart knows it
 └────────────┬──────────────────────────────┘
              ▼
 /sys/fs/bpf/mfw/  (bpffs, mode 0700)
   maps/rulesets     HASH_OF_MAPS  ifindex → that  ─┐
                     interface's compiled lists     │ read by XDP
   maps/config       ARRAY  flags, generation      ─┤
   maps/stats        PERCPU counters               ─┘ written by XDP
   link/xdp_<if>     pinned bpf_link (keeps the program attached)

 NIC ──► XDP mfw_xdp ──► XDP_PASS ──► kernel stack ──► sockets
              │
              └──► XDP_DROP
```

Key properties:

- **One writer.** Only mfwd touches the maps and links. Everything else
  needs no privileges beyond the socket.
- **Whole-policy updates.** Every `APPLY` carries the complete desired
  state. mfwd checks all of it before changing anything (§6).
- **Pinned, so mfwd can stop.** The links and maps are pinned; filtering
  goes on while mfwd is stopped, restarting or upgraded.
- **One BPF object.** `bpf/mfw.bpf.c` is embedded in `mfwd` as a libbpf
  skeleton (`build/mfw.skel.h`), so there is no `.o` to install.
- **Rulesets are per interface.** Every attached interface runs the same
  program, which looks up the ruleset of the interface the packet arrived
  on (`ingress_ifindex`). An interface with no ruleset is fail-open. This
  replaces the design's shared maps (K14).

### 2.1 Source layout

```text
bpf/mfw.h              shared UAPI: mfw_rule, mfw_ruleset, mfw_config, stat ids
bpf/mfw.bpf.c          XDP program: parser, standard + extended matching
include/mfw_policy.h   libmfw: ACE and policy parsing, checks, compile, canonical form
include/mfw_client.h   libmfw: the mfwd client
src/acl_parse.c        libmfw: Cisco ACE parser and formatter
src/policy.c           libmfw: whole policies
src/client.c           libmfw: socket client
src/mfwd.c             the daemon: socket, requests, saved policy
src/dataplane.c/.h     mfwd's BPF side: load, pins, attach/detach, rulesets, counters
src/mfw.c              the command-line client
mfwd.service           systemd unit
tests/test_acl.c       ACE parser tests (no kernel)
tests/test_policy.c    policy tests (no kernel)
tests/test_bpf.c       dataplane tests via BPF_PROG_TEST_RUN (root)
tests/test_mfwd.sh     mfwd on dummy interfaces (root)
scripts/smoke-test.sh  real traffic through mfwd in two network namespaces (root)
```

`libmfw.a` (acl_parse, policy, client) links no libbpf and needs no
privileges; `make install` puts it and the three public headers under
`PREFIX`.

---

## 3. Packet processing (`mfw_xdp`)

### 3.1 Decision flow

```text
frame
  │
  ├─ parse Ethernet; peel up to 2 VLAN tags (802.1Q / 802.1AD)
  │     ├─ shorter than an Ethernet header ............. PASS   (non_ipv4)
  │     ├─ truncated VLAN tag ............................ DROP   (parse_err)
  │     └─ inner ethertype ≠ IPv4 (ARP, IPv6, 3rd tag) ... PASS   (non_ipv4)
  │
  ├─ parse IPv4 (+ TCP/UDP ports if present)
  │     └─ corrupt (§3.2) ................................ DROP   (parse_err)
  │
  ├─ fragment and config.drop_ipv4_fragments = 1 ........ DROP   (frag_drop)
  │
  ├─ 1. standard list (source IP)
  │     ├─ explicit deny ................................. DROP   (std_deny)
  │     └─ explicit permit, no match, or unbound ......... continue
  │
  └─ 2. extended list
        ├─ explicit permit ............................... PASS   (ext_permit)
        ├─ explicit deny ................................. DROP   (ext_deny)
        ├─ reached implicit deny ......................... DROP   (ext_implicit_deny)
        └─ unbound ....................................... PASS   (std_permit if the
                                                                    standard list permitted)
```

Rules to remember:

- **A standard `permit` does not bypass the extended list.** It only stops
  the standard scan. This is the same result as when the two lists ran on
  separate hooks (standard at XDP, extended at TC).
- **A standard `deny` is final**, even if the extended list would permit.
- **Unbound means open.** A list that is not bound never drops anything.
- Within each list, **the first matching ACE wins**, in sequence order.

### 3.2 Parsing details

| Check | Result |
|-------|--------|
| `version != 4` or `ihl < 5` | DROP (`parse_err`) |
| IPv4 header (including options) beyond packet end | DROP |
| TCP header (20 bytes) beyond packet end, offset-0 packet | DROP |
| UDP header (8 bytes) beyond packet end, offset-0 packet | DROP |
| `MF` set or fragment offset ≠ 0 | `is_frag = 1` |
| Fragment offset ≠ 0 (non-first fragment) | no ports parsed (`has_ports = 0`) |
| ICMP and other protocols | no ports; ACE port fields are ignored |

All parsing uses XDP direct packet access with explicit bounds checks. The
VLAN loop is unrolled (two iterations), so the verifier sees fixed code.

### 3.3 Matching semantics

**Standard ACE** (`match_std`): matches when `saddr` is inside `src`. Every
other field is ignored, so a standard ACE applies to all IPv4 protocols.

**Extended ACE** (`mfw_ext_ace_match`), all conditions must hold:

1. `proto` is 0 (`ip`, meaning any) or equals the packet's protocol.
2. `saddr` in `src` and `daddr` in `dst`.
3. For TCP and UDP only:
   - With ports (unfragmented or first fragment): `sport` and `dport` are in
     range. `(0,0)` means any. If the ACE has `established`, the TCP flags
     must include ACK or RST.
   - Non-first fragment (no ports): the ACE matches only if both port ranges
     are "any" and it has no `established`.
4. For ICMP and other protocols, port fields and flags are ignored.

**CIDR match:** `(addr & mask) == (rule.addr & mask)` in network byte order.
Prefix 0 matches everything. A prefix above 32 never matches (defensive; the
parser never produces one).

**Finding the ruleset:** the program looks up `ctx->ingress_ifindex` in
`maps/rulesets`, which yields that interface's inner map, and then entry 0
of the inner map, the interface's `struct mfw_ruleset` (§4.2). That is two
map lookups per packet, however many ACEs there are. Without a ruleset,
both lists count as unbound.

**Bound detection:** `std_acl` / `ext_acl` in the ruleset name the bound
lists; 0 means unbound (`MATCH_UNBOUND`). The scans stop at `n_std` /
`n_ext`. If a scan runs out without a match, the result is `MATCH_MISS`.

**Implicit deny:** running off the end of a bound extended list
(`ext_acl != 0`) returns `MATCH_MISS`, which the program drops and counts as
`ext_implicit_deny`, separately from explicit `deny` ACEs. A bound list with
no ACEs (`n_ext = 0`) therefore drops all IPv4.

### 3.4 Verifier strategy

A 128-iteration loop whose body contains every extended-match branch
exceeded the verifier's 1M-instruction limit. The fix is a **global
function for the per-ACE match**: `mfw_ext_ace_match` is non-static and
`__noinline`, so the verifier checks it **once**, independently, instead of
re-exploring its branches on every iteration. It must NULL-check its
pointer arguments for that reason.

The loops index the ruleset directly (`&rs->ext[i]`), bounded by the
`MFW_MAX_*_ACES` constants and cut short at `n_std` / `n_ext`, so there is
no map lookup inside them.

Result: the whole program (64-entry standard loop plus 128-entry extended
loop) verifies in about **16K instructions** (15,680 on kernel 6.8; read
`verified_insns` from `bpf_prog_get_info_by_fd()` after loading). Global
functions taking pointer arguments need **kernel 5.12+**, which is why the
minimum is above the design's 5.10.

---

## 4. Data structures and maps

All shared types are in `bpf/mfw.h`, fixed-width with explicit padding.

### 4.1 `struct mfw_rule` (44 bytes)

| Field | Type | Meaning |
|-------|------|---------|
| `acl_id` | `u16` | 1–99 standard, 100–199 extended |
| `seq` | `u16` | sequence number |
| `action` | `u8` | `MFW_ACTION_DENY` = 0, `MFW_ACTION_ALLOW` = 1 |
| `proto` | `u8` | 0 = any; otherwise the IPv4 protocol number |
| `direction` | `u8` | always `MFW_DIR_INGRESS` in step 1 (kept for ABI) |
| `enabled` | `u8` | set to 1 by the parser; BPF scans by `n_std` / `n_ext` instead |
| `kind` | `u8` | `MFW_ACL_STANDARD` = 1, `MFW_ACL_EXTENDED` = 2 |
| `flags` | `u8` | `MFW_RULE_F_ESTABLISHED` (bit 0) |
| `src`, `dst` | `mfw_cidr` | `addr` (network order) + `prefix` 0–32, normalized (host bits cleared) |
| `sport`, `dport` | `mfw_port_range` | inclusive `min..max`, host order; `(0,0)` = any |
| `rule_id` | `u32` | `(acl_id << 16) \| seq`, the same as the `acl_db` key |

Port 0 cannot be filtered, because `(0,0)` is the "any" sentinel. The parser
rejects `eq 0`.

### 4.2 `struct mfw_ruleset` (8,464 bytes)

Everything one interface enforces, compiled from its bindings:

| Field | Type | Meaning |
|-------|------|---------|
| `std_acl` | `u16` | bound standard list, 0 = none |
| `ext_acl` | `u16` | bound extended list, 0 = none (fail-open) |
| `n_std` | `u16` | `std[0 .. n_std)` are in use |
| `n_ext` | `u16` | `ext[0 .. n_ext)` are in use; a bound list may have 0 |
| `generation` | `u32` | `config.generation` when it was built |
| `std` | `mfw_rule[64]` | the standard list's ACEs, in `seq` order |
| `ext` | `mfw_rule[128]` | the extended list's ACEs, in `seq` order |

### 4.3 `struct mfw_config` (8 bytes)

| Field | Meaning |
|-------|---------|
| `default_action` | ABI only. Always DENY and ignored by BPF (design K10) |
| `drop_ipv4_fragments` | 1 drops every packet with MF set or offset ≠ 0 |
| `abi_version` | `MFW_ABI_VERSION` (2: per-interface rulesets). `attach` refuses pinned maps with another version |
| `generation` | bumped after each successful materialization |

### 4.4 Maps

| Pin | Type | Key → value | Max | Writer | Reader |
|-----|------|-------------|-----|--------|--------|
| `maps/rulesets` | HASH_OF_MAPS | ifindex → inner map | 64 (`MFW_MAX_IFACES`) | mfwd | XDP |
| (inner, not pinned) | ARRAY | `0` → `mfw_ruleset` | 1 | mfwd, once | XDP |
| `maps/config` | ARRAY | `0` → `mfw_config` | 1 | mfwd | XDP |
| `maps/stats` | PERCPU_ARRAY | stat id → `u64` | `MFW_STAT_MAX` | XDP | mfwd |

The maps are created by libbpf when mfwd first starts
(`LIBBPF_PIN_BY_NAME` with pin root `<pinroot>/maps`) and reused by every
later start. There is no userspace-only state in bpffs any more: the
policy itself lives in mfwd and in `/run/mfwd/policy` (§5).

An inner map is kept alive only by the outer map's reference: mfwd
creates it, fills it, stores its fd in `maps/rulesets` and closes it. It
is never written again (§6). The inner maps are created without BTF,
and the BPF object declares their template with `key_size` /
`value_size`, because clang emits `struct mfw_ruleset` there only as a
forward declaration.

### 4.5 Stats

Each packet increments **exactly one outcome** and **at most one reason**.

| Id | Name | Kind | Meaning |
|----|------|------|---------|
| 0 | `xdp_pass` | outcome | returned `XDP_PASS` |
| 1 | `xdp_drop` | outcome | returned `XDP_DROP` |
| 2 | `std_deny` | reason | standard explicit deny |
| 3 | `std_permit` | reason | standard explicit permit, extended unbound |
| 4 | `ext_permit` | reason | extended explicit permit |
| 5 | `ext_deny` | reason | extended explicit deny |
| 6 | `ext_implicit_deny` | reason | extended list bound, nothing matched |
| 7 | `parse_err` | reason | corrupt IPv4 / VLAN / L4 header |
| 8 | `frag_drop` | reason | `drop_ipv4_fragments = 1` |
| 9 | `non_ipv4` | reason | passed without inspection |

Packets passed with no list deciding (both unbound, or a standard miss with
extended unbound) get an outcome but no reason. **New ids must be appended
at the end** so existing pinned maps keep their layout.

---

## 5. mfwd: lifecycle and pins

```text
<pinroot>/                0700, root only (default /sys/fs/bpf/mfw, mfwd -p)
  maps/{rulesets,config,stats}
  link/xdp_<ifname>
<statedir>/policy         default /run/mfwd (mfwd -d): "# generation N", then
                          the applied policy in canonical form
```

### 5.1 Start

1. Check that the pin root's parent is on bpffs (`statfs` magic).
2. Create `maps/` and `link/` with mode 0700.
3. Open the embedded skeleton with pin root `maps/` and load it. libbpf
   reuses existing map pins, or creates and pins new ones.
4. Initialize `config` if `abi_version` is 0. If it holds a different ABI
   version, refuse to start (`mfwd -P` removes the old pins).
5. **Upgrade attached interfaces:** every live link in `link/` gets the
   program just loaded, with `bpf_link_update` (atomic). Upgrading mfwd
   therefore upgrades the BPF code without a gap.
6. **Restore** the saved policy, if there is one. If the kernel still runs
   its generation (`config.generation`), it is simply taken over. If not
   (the pins were removed, e.g. by hand), it is applied again.
7. Listen on the socket (default `0600`; `-m`, `-g`).

### 5.2 Stop

SIGTERM or SIGINT: mfwd closes and removes its socket and exits. **The
pinned links and maps stay**, so the interfaces keep their rulesets.

### 5.3 Attach and detach

mfwd attaches and detaches as `APPLY` requires (§6):

- **Attach:** `bpf_link_create(BPF_XDP)`, driver mode first, then generic
  for `-x auto`, and pin the link as `link/xdp_<if>`.
- **A link is live** when its pin exists and `bpf_link_get_info_by_fd()`
  reports the interface's current ifindex. A pin whose interface was
  deleted (or deleted and re-created) is removed and, if still bound,
  attached again.
- **Detach:** remove the interface's ruleset, then unlink the pin. With the
  last reference gone, the kernel detaches the program.

### 5.4 Purge and emergency removal

`mfwd -P` unlinks every link pin (detaching XDP), then removes the maps,
the pin root and the saved policy. Without mfwd:

```bash
rm -r /sys/fs/bpf/mfw                  # detaches everything, removes all state
```

---

## 6. Applying a policy

`APPLY` carries the whole desired state (format in `include/mfw_policy.h`
and the user manual). mfwd:

1. **Parses and checks** it with `mfw_policy_parse()` — the same code
   front ends link from `libmfw.a`. Errors name the line. Checks: syntax
   of every line, the ACE grammar (§7.3), duplicate `(list, seq)`, at most
   one standard and one extended list per interface, at most 64
   interfaces and 4096 ACEs, and that every **bound** list fits its half
   of the ruleset (64 standard, 128 extended ACEs). Rules are sorted by
   `(list, seq)` and bindings by interface name.
2. **Attaches** every bound interface that exists and isn't attached yet.
   If an attach fails, the ones attached by this request are detached
   again and the request is refused (`ERR kernel`). Bound interfaces that
   don't exist are skipped and reported as `missing`.
3. Increments `config.generation` and sets `drop_ipv4_fragments`.
4. **Installs** a ruleset for each bound, existing interface
   (`mfw_policy_compile()`, stamped with the generation): a new inner map,
   filled, then stored in `maps/rulesets` under the ifindex. That last
   update is the switch.
5. Removes every other entry of `maps/rulesets` and **detaches** attached
   interfaces that are no longer bound.
6. Saves the policy (canonical form, `mfw_policy_format()`) to
   `<statedir>/policy`, written to a temporary file, fsynced and renamed.

Nothing in the kernel changes before step 2, so a refused policy leaves
the running one in place.

**Atomic per interface.** An installed inner map is never written again,
and the switch in step 4 is one map update. A packet holds the inner map
it looked up until it is done (RCU), and the kernel frees the old one only
after that, so each packet sees the old ruleset or the new one, never a
mix. Different interfaces switch one after another, so for a few
microseconds they may run different generations.

A bound list that has no ACEs is allowed, as on IOS: a bound standard list
with no ACEs is open; a bound extended list with no ACEs denies all IPv4.

---

## 7. Interfaces

### 7.1 Protocol

One request per connection on mfwd's Unix socket. The client sends the
request; mfwd sends the whole reply and closes. Requests are
case-sensitive.

| Request | Reply |
|---------|-------|
| `PING` | `OK` |
| `STATUS` | `OK generation=N drop-ipv4-fragments=0\|1 attached=a,b missing=c` |
| `STATS` | `OK xdp_pass=N xdp_drop=N …`, every counter by name |
| `SHOW` | `OK <n>` then the applied policy, n lines, canonical form |
| `APPLY`, the policy lines, `END` | `OK <generation>[ missing=a,b]` |

Errors are one line, `ERR <code> <message>`:

| Code | When |
|------|------|
| `badreq` | unknown request, no complete request within 3 s, more than 1 MiB, a NUL byte |
| `invalid` | the policy was refused; the message starts with `line N:` |
| `kernel` | an attach, a map update or a counter read failed |
| `internal` | out of memory |

`generation` in `STATUS` is 0 before the first `APPLY` since the pins were
created. Lists in `attached` / `missing` are comma-separated and empty when
there are none.

mfwd handles one request at a time. A client that is slow to send holds
others up for at most 3 s. After replying, mfwd drains input it has not
read (for at most a second) before closing, because closing a Unix socket
with unread data resets the connection and the client would lose the reply.
Every `APPLY` is logged with the caller's uid (`SO_PEERCRED`).

### 7.2 libmfw

| Header | Functions |
|--------|-----------|
| `mfw_policy.h` | `mfw_parse_ace()`, `mfw_parse_ace_line()`, `mfw_format_ace()`, `mfw_policy_parse()`, `mfw_policy_compile()`, `mfw_policy_format()`, `mfw_policy_free()` |
| `mfw_client.h` | `mfw_ping()`, `mfw_apply()`, `mfw_status()`, `mfw_stats()`, `mfw_show()`, `mfw_request()`, `mfw_strerror()`, `mfw_stat_name()` |

Client calls return `mfw_ok` (0) or a negative `enum mfw_rc`: `io` (cannot
reach mfwd; see `errno`), `reply`, and one per `ERR` code. Each call opens
one connection, with a timeout on each step (5 s by default); there is no
global state, and no `SIGPIPE`. `mfw_apply()` refuses a policy containing a
line `END`, which would end the block early.

### 7.3 Grammar

| Operand | Accepted forms | Stored as |
|---------|----------------|-----------|
| address | `any` | `0.0.0.0/0` |
| | `host A.B.C.D` | `/32` |
| | `A.B.C.D W.W.W.W` (contiguous wildcard) | prefix, host bits cleared |
| | `A.B.C.D/len` | prefix, host bits cleared |
| | `A.B.C.D` alone (standard lists only) | `/32` |
| protocol | `ip`, `tcp`, `udp`, `icmp`, `0`–`255` | protocol number (`ip` = 0) |
| port | `eq N` | `N..N` |
| | `range LO HI` | `LO..HI` |
| | `gt N` | `N+1..65535` |
| | `lt N` | `1..N-1` |
| flag | `established` (tcp only, last token) | `MFW_RULE_F_ESTABLISHED` |

Validation rejects: list numbers outside 1–199; destination, ports or
protocol on standard lists; non-contiguous wildcards (`0.0.2.255`); prefixes
above 32; ports on non-TCP/UDP protocols; `established` without `tcp`; port
0; inverted ranges; `gt 65535` and `lt 1`; and, on extended lists, a bare
address without `host` or a wildcard.

The canonical form (`SHOW`, the saved policy) prints ACEs normalized
(`/16` becomes `10.1.0.0 0.0.255.255`, a range ending at 65535 becomes
`gt N`) and drops comments.

### 7.4 `mfw`

`mfw [-s socket] apply|check|show|status|stats|ping|version`. `check`
parses locally with `libmfw` and sends nothing. Exit status: 0 ok, 1
refused by mfwd, 2 usage, file or connection error. Set `MFW_DEBUG=1` in
mfwd's environment for libbpf debug output, including the verifier log.

---

## 8. Limitations and operating notes

### 8.1 Replies need rules

Without conntrack, replies to the host's own outbound connections are
ordinary inbound packets. If an extended list is bound, permit them
explicitly:

```text
acl 100 10 permit tcp any any established   # TCP replies (ACK or RST set)
acl 100 20 permit udp any eq 53 any         # DNS replies
acl 100 30 permit icmp any any              # ping replies, ICMP errors
```

`established` is the classic stateless approximation: it lets through any
TCP segment with ACK or RST set, including forged ones. It blocks only
unsolicited SYNs. Conntrack is the real fix (§9).

### 8.2 Fragments

Non-first fragments have no ports, so they match only extended ACEs without
port constraints or `established`. A large UDP datagram allowed by
`permit udp any any eq 4789` therefore has its later fragments dropped by
the implicit deny. Either permit by address (`permit udp host X any`) or set
`drop-ipv4-fragments 1` to drop all fragments consistently.

### 8.3 Per-interface policy

Each interface has its own standard and extended slot, at most 64
interfaces (`MFW_MAX_IFACES`). Policy follows the interface the packet
arrived on, so VLAN subinterfaces share their parent's lists: XDP runs on
the parent, and the tags are peeled before matching.

If an interface is deleted and re-created, it gets a new ifindex and loses
its XDP program. Its binding stays, but is not installed until the
interface is attached again.

### 8.4 Updates

Each interface switches atomically to its new ruleset (§6.3). An update
that touches several interfaces switches them one after another.

### 8.5 Performance

- XDP runs **before GRO**, so the extended list is scanned once per wire
  packet. In TC it would run once per GRO-merged packet. This trade-off buys
  the earliest possible drop.
- Matching is linear: worst case 64 + 128 ACE checks per packet. Put the
  most frequently hit ACEs first.
- Native XDP needs driver support. `auto` falls back to generic XDP (slower,
  but works everywhere, including veth without native support).

### 8.6 SYN floods

The kernel's own SYN cookies (`net.ipv4.tcp_syncookies = 1`, the default)
protect local listeners. An XDP SYN-cookie implementation was evaluated and
deferred: generating cookies is easy with `bpf_tcp_raw_gen_syncookie_ipv4`,
but handing the validated connection to a local socket needs either
netfilter SYNPROXY/conntrack or `bpf_sk_assign_tcp_reqsk` (kernel 6.9+).

### 8.7 Security

- Pins are root-only (directory mode 0700). Anyone who can write
  `/sys/fs/bpf/mfw` controls the policy.
- **The socket is the policy.** Whoever can connect to mfwd's socket can
  replace the policy. It is `0600` root by default; `-g` / `-m` widen it to
  one group (e.g. the one sw_configd runs as).
- mfwd parses only the line protocol and the policy grammar; it has no JSON
  or other complex input.
- **Fail-open by default.** With nothing bound, everything passes. A bound
  extended list fails closed.
- Non-IPv4 always passes. If IPv6 is enabled on the interface, it is not
  filtered at all.

---

## 9. Testing

| Suite | Command | Needs | Covers |
|-------|---------|-------|--------|
| ACE parser | `make test` | nothing | wildcard→prefix, field values, normalization, canonical round trips, every rejection rule |
| Policy | `make test` | nothing | parse and canonical form with comments and CRLF, every refusal with its line number, size limits (64/128 bound, 4096 total, 64 interfaces), compile |
| Dataplane | `make test-bpf` | root | crafted frames through `BPF_PROG_TEST_RUN`: unbound pass, standard blacklist, extended permit/deny/implicit, standard and extended combined, `established`, fragments and strict mode, VLAN/QinQ/ARP/IPv6, corrupt headers, full 64 + 128 tables, per-interface rulesets (separate lists, swap, removal, interface without a ruleset), stats |
| mfwd | `make test-mfwd` | root, `python3` | dummy interfaces in a private netns: apply/show/status/stats, socket mode, refusals leave the policy in place, missing interfaces, unbinding detaches, every `badreq` case (unknown, incomplete, too long, too slow), restart keeps policy and filtering, lost pins are re-applied, a re-created interface, purge, no daemon |
| End-to-end | `make smoke` | root, `nc`, `ping`, `python3` | real traffic through mfwd between two network namespaces over two veth pairs: standard deny and wildcard, extended permit and implicit deny, `established` for outbound TCP, bound empty list, different lists on two interfaces, filtering while mfwd is down and after a restart, no TC filters, refused policies, purge |

Notes:

- `test_bpf` loads the skeleton with pinning disabled and runs in its own
  network namespace with two dummy interfaces, whose ifindexes it passes
  as `ingress_ifindex`. It touches no host interface and no pins.
- `test_mfwd.sh` and `smoke-test.sh` start mfwd with `nsenter --net`
  rather than `ip netns exec`, because the latter remounts `/sys` and hides
  the host's bpffs. Both use their own pin root (`/sys/fs/bpf/mfw*-<pid>`),
  socket and state directory, so they run next to a live installation.
- To check the verifier budget after changes, load the skeleton with
  pinning disabled (as `test_bpf` does) and read `verified_insns` from
  `bpf_prog_get_info_by_fd()`. `bpftool prog loadall` also works, but it
  pins the `LIBBPF_PIN_BY_NAME` maps under `/sys/fs/bpf/`, which you then
  have to remove.

---

## 10. Differences from `design.md`

| Area | `design.md` (Rev 18) | Step 1 | Why |
|------|----------------------|--------|-----|
| Hooks | XDP + TC ingress + TC egress | XDP only | Local VM only; with no egress and no conntrack, TC had no remaining job |
| Extended list | TC ingress and egress | XDP, after the standard list | Earliest drop; a stateless match needs only headers |
| Egress | TC egress, local-out policy, `access-group out` | none; `out` rejected | Egress is out of scope |
| Conntrack | Cilium-style, TC | none | Deferred; `established` as a stopgap |
| Fragment tracking | Cilium-style port recovery, TC | none; port ACEs cannot match non-first fragments | Deferred |
| Control plane | CLI loader compiling ACEs into the maps per command | mfwd daemon, whole-policy `APPLY` over a socket; `mfw` is a client | One writer; whole-policy checks; front ends (sw_configd) link `libmfw` |
| ACL definitions | not specified (examples define lists before attach) | in the policy; mfwd saves the applied one in `/run/mfwd/policy` | The front end (or a policy file) is the source of truth |
| Maps (K14, K16) | `acl_std` / `acl_ext` shared by every interface | `rulesets` map-in-map: one `mfw_ruleset` per ifindex | Different lists per interface; atomic updates |
| Bound detection | sketch checked "index 0 enabled", per direction | `std_acl` / `ext_acl` in the ruleset | Explicit; no sentinel entries |
| Implicit deny | trailing synthetic `deny ip any any` | running off the end of a bound extended list | Counted separately from explicit denies; takes no ACE slot |
| `established` | not in design | added (Cisco-compatible) | Makes stateless reply handling practical |
| Stats ids | TC/CT/frag ids | XDP-only set (§4.5) | Nothing shipped; clean layout, append-only from now on |
| Kernel | 5.10+ | 5.12+ | Global BPF function with pointer arguments (§3.4) |
| `rule_id` delete | `no ip access-list N <rule_id\|seq>` | none: a policy is replaced as a whole | `rule_id` is still `(acl << 16) \| seq` |
| clsact management | meta markers, TC attach | none | No TC |

---

## 11. Future work

Roughly in order of value for the local-VM use case:

1. **Conntrack**, to replace `established` and source-port reply rules.
   Outbound flows must be observed, so this brings back a TC egress hook
   (observe-only, no filtering). The lookup can stay in XDP or move with the
   extended list; see design.md §Conntrack for the Cilium-based model.
2. **Fragment port recovery**, so port ACEs work for fragmented UDP.
3. **Per-ACE hit counters**, reported by `STATS` / `SHOW` (IOS-style
   `(N matches)`).
4. **Per-interface stats**, as a per-CPU map keyed by ifindex.
5. **XDP SYN cookies** once the target kernel is 6.9+ (§8.6).
6. **Interface hotplug.** mfwd could watch netlink link events and attach
   a bound interface as soon as it appears, instead of reporting it as
   missing until the next `APPLY`.
