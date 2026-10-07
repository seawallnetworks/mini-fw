# mini-fw: Step 1 Implementation (stateless XDP ACL)

| Field | Value |
|-------|-------|
| **Document** | Implementation description — what is actually built |
| **Scope** | Step 1: stateless, ingress-only, XDP-only ACL for a local VM |
| **Branch** | `feat/stateless-acl` |
| **Date** | 2026-10-06 |
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
- **One XDP program** per attached interface. Nothing is attached to TC.
- **Stateless.** Every packet is judged on its own headers. There is no connection table.
- **Cisco IOS-style numbered ACLs**, managed through the `mfw` CLI:
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
                       userspace                                   kernel
 ┌──────────────────────────────────────────┐
 │ mfw CLI (one-shot, no daemon)            │
 │  access-list / access-group / show       │──┐ writes ACEs and bindings
 │  attach / detach / stats / set           │  │
 └──────────────────────────────────────────┘  │
                                               ▼
 /sys/fs/bpf/mfw/  (bpffs, mode 0700)
   state/acl_db      HASH   every defined ACE         (userspace only)
   state/bindings    ARRAY  which list is bound        (userspace only)
   maps/acl_std      ARRAY  compiled standard list ─┐
   maps/acl_ext      ARRAY  compiled extended list ─┤ read by XDP
   maps/config       ARRAY  flags, generation      ─┤
   maps/stats        PERCPU counters               ─┘ written by XDP
   link/xdp_<if>     pinned bpf_link (keeps the program attached)

 NIC ──► XDP mfw_xdp ──► XDP_PASS ──► kernel stack ──► sockets
              │
              └──► XDP_DROP
```

Key properties:

- **No daemon.** Every `mfw` command opens the pins, does its work and exits.
  The pinned link keeps the XDP program attached after `mfw attach` exits.
- **One BPF object.** `bpf/mfw.bpf.o` is embedded in the `mfw` binary as a
  libbpf skeleton (`bpf/mfw.skel.h`), so there is no `.o` to install.
- **Maps are host-global.** Every attached interface runs the same program
  against the same maps (design K14).
- **Two layers of ACL state.** Userspace keeps the full list definitions in
  `state/`. Only bound lists are compiled ("materialized") into the
  dataplane maps in `maps/` (§6).

### 2.1 Source layout

```text
bpf/mfw.h            shared UAPI: mfw_rule, mfw_config, stat ids (single source of truth)
bpf/mfw.bpf.c        XDP program: parser, standard + extended matching
include/mfw_uapi.h   userspace wrapper that includes bpf/mfw.h
src/mfw_cli.h        CLI-internal declarations, exit codes, pin paths, binding slots
src/main.c           command dispatch, usage text
src/acl_parse.c      Cisco ACE parser and formatter (pure C, no libbpf)
src/acl.c            ACL store, bindings, materialization, show commands
src/loader.c         attach / detach, pinning, bpffs checks
src/stats.c          stats and set commands
tests/test_acl.c     parser unit tests (no kernel)
tests/test_bpf.c     dataplane tests via BPF_PROG_TEST_RUN (root)
scripts/smoke-test.sh  end-to-end test in two network namespaces (root)
```

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
- **Unbound means open.** A list with no `access-group` never drops anything.
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
CLI never writes one).

**Bound detection:** both maps are packed from index 0, and the scan stops at
the first entry with `enabled = 0`. If index 0 is empty, the list is unbound
(`MATCH_UNBOUND`). If the scan runs out without a match, the result is
`MATCH_MISS`.

**Implicit deny:** userspace appends a synthetic ACE with
`MFW_RULE_F_IMPLICIT` to every bound extended list. When the scan reaches it,
`match_ext` returns `MATCH_MISS`, which the program drops and counts as
`ext_implicit_deny`. This keeps implicit drops separate from explicit `deny`
ACEs in the stats. A bound list with no ACEs therefore contains only the
synthetic ACE and drops all IPv4.

### 3.4 Verifier strategy

A 128-iteration loop whose body contains every extended-match branch
exceeded the verifier's 1M-instruction limit. Two techniques fix it:

1. **Separate loop key.** The loop counter `i` stays in a register, and a
   copy `key = i` is passed to `bpf_map_lookup_elem`. Taking `&i` spills the
   counter to the stack, and the verifier then flags the loop as infinite.
2. **Global function for the per-ACE match.** `mfw_ext_ace_match` is
   non-static and `__noinline`, so the verifier checks it **once**,
   independently, instead of re-exploring its branches on every iteration.
   It must NULL-check its pointer arguments for that reason.

Result: the whole program (64-entry standard loop plus 128-entry extended
loop) verifies in about **16K instructions** (measured with
`bpftool -d prog loadall`). Global functions taking pointer arguments need
**kernel 5.12+**, which is why the minimum is above the design's 5.10.

---

## 4. Data structures and maps

All shared types are in `bpf/mfw.h`, fixed-width with explicit padding.

### 4.1 `struct mfw_rule` (44 bytes)

| Field | Type | Meaning |
|-------|------|---------|
| `acl_id` | `u16` | 1–99 standard, 100–199 extended (the synthetic implicit deny carries its list's id) |
| `seq` | `u16` | sequence number; `0xffff` for the synthetic implicit deny |
| `action` | `u8` | `MFW_ACTION_DENY` = 0, `MFW_ACTION_ALLOW` = 1 |
| `proto` | `u8` | 0 = any; otherwise the IPv4 protocol number |
| `direction` | `u8` | always `MFW_DIR_INGRESS` in step 1 (kept for ABI) |
| `enabled` | `u8` | 0 terminates the scan |
| `kind` | `u8` | `MFW_ACL_STANDARD` = 1, `MFW_ACL_EXTENDED` = 2 |
| `flags` | `u8` | `MFW_RULE_F_ESTABLISHED` (bit 0), `MFW_RULE_F_IMPLICIT` (bit 1) |
| `src`, `dst` | `mfw_cidr` | `addr` (network order) + `prefix` 0–32, normalized (host bits cleared) |
| `sport`, `dport` | `mfw_port_range` | inclusive `min..max`, host order; `(0,0)` = any |
| `rule_id` | `u32` | `(acl_id << 16) \| seq`, the same as the `acl_db` key |

Port 0 cannot be filtered, because `(0,0)` is the "any" sentinel. The CLI
rejects `eq 0`.

### 4.2 `struct mfw_config` (8 bytes)

| Field | Meaning |
|-------|---------|
| `default_action` | ABI only. Always DENY and ignored by BPF (design K10) |
| `drop_ipv4_fragments` | 1 drops every packet with MF set or offset ≠ 0 |
| `abi_version` | `MFW_ABI_VERSION` (1). `attach` refuses pinned maps with another version |
| `generation` | bumped after each successful materialization |

### 4.3 Maps

| Pin | Type | Key → value | Max | Writer | Reader |
|-----|------|-------------|-----|--------|--------|
| `maps/acl_std` | ARRAY | `u32` → `mfw_rule` | 64 | CLI | XDP |
| `maps/acl_ext` | ARRAY | `u32` → `mfw_rule` | 128 | CLI | XDP |
| `maps/config` | ARRAY | `0` → `mfw_config` | 1 | CLI | XDP |
| `maps/stats` | PERCPU_ARRAY | stat id → `u64` | `MFW_STAT_MAX` | XDP | CLI |
| `state/acl_db` | HASH | `(acl<<16)\|seq` → `mfw_rule` | 4096 | CLI | CLI |
| `state/bindings` | ARRAY | slot → `mfw_binding` | 2 | CLI | CLI |

`maps/*` are created by libbpf at the first `attach` (`LIBBPF_PIN_BY_NAME`
with pin root `/sys/fs/bpf/mfw/maps`) and reused on later attaches.
`state/*` are created by the CLI itself (`bpf_map_create` + `bpf_obj_pin`)
the first time a command needs them, so lists can be defined before any
`attach`. The kernel never reads `state/`.

`mfw_binding` is `{ u16 acl_id; u16 pad; char ifname[16]; }`. Slot 0 is the
standard list, slot 1 the extended list. `acl_id = 0` means unbound.

### 4.4 Stats

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

## 5. Pin layout and lifecycle

```text
/sys/fs/bpf/mfw/          0700, root only
  maps/{acl_std,acl_ext,config,stats}
  state/{acl_db,bindings}
  link/xdp_<ifname>
```

### 5.1 `mfw attach -i <if> [--xdp-mode native|generic|auto]`

1. Check that bpffs is mounted at `/sys/fs/bpf` (`statfs` magic). If not,
   print the mount command and exit 2.
2. Create `maps/` and `link/` with mode 0700.
3. Open the embedded skeleton with pin root `maps/` and load it. libbpf
   reuses existing map pins, or creates and pins new ones.
4. Initialize `config` if `abi_version` is 0. If it holds a different ABI
   version, refuse (detach with `--purge-maps` first).
5. Attach XDP:
   - If `link/xdp_<if>` exists, **replace in place** with `bpf_link_update`.
     This is atomic; there is no window without a program.
   - Otherwise `bpf_link_create(BPF_XDP)`, trying driver mode first and then
     generic mode (for `auto`), and pin the link.
6. Destroy the skeleton. The pinned link keeps the program and its maps alive.
7. Materialize the bound lists (§6), so a fresh attach enforces the current
   policy immediately.

On a re-attach, the XDP mode of an existing link is not changed.

### 5.2 `mfw detach -i <if> [--purge-maps]`

1. Unlink `link/xdp_<if>`. With the last reference gone, the kernel
   detaches the program. A missing pin or interface is tolerated.
2. With `--purge-maps`: refuse if other interfaces are still attached.
   Otherwise remove `maps/`, `state/`, `link/` and the pin root. **This also
   deletes all ACL definitions and bindings.**

### 5.3 Rollback and emergency removal

```bash
mfw detach -i eth0 --purge-maps
# if the CLI is unavailable:
rm /sys/fs/bpf/mfw/link/xdp_eth0       # releases the XDP link
ip link set dev eth0 xdp off           # only for non-link (legacy) attachments
```

---

## 6. Control plane: ACL store and materialization

### 6.1 Defining ACEs

`mfw ip access-list <list> [seq] permit|deny …`:

1. Parse with `mfw_parse_ace` (§7). Validation errors exit 4.
2. If no `seq` was given, use the highest `seq` in that list plus 10
   (Cisco behaviour). Refuse when that would exceed 65534.
3. Insert into `state/acl_db` with `BPF_NOEXIST`. A duplicate `(list, seq)`
   is an error (exit 4), as on IOS.
4. Materialize. If that fails (for example the bound list is now too long),
   the new ACE is deleted again.

`mfw no ip access-list <list> [seq]` deletes one ACE or the whole list. A
binding to a deleted list stays in place, as on IOS: a bound standard list
with no ACEs is open; a bound extended list with no ACEs denies all IPv4.

### 6.2 Binding lists

`mfw ip access-group <list> in <if>`:

- `<if>` must be attached, otherwise exit 3.
- The list number picks the slot: 1–99 → standard, 100–199 → extended.
  Binding a list number with no ACEs is allowed.
- Binding replaces whatever list was in that slot, with a note on stderr.
  **Bindings are host-global**: the interface name is recorded only for
  display, and the policy applies on every attached interface.
- `out` is rejected with exit 4 ("egress is not filtered").
- If materialization fails, the previous binding is restored.

`mfw no ip access-group [<list>] in <if>` clears both slots, or only the
slot holding `<list>`.

### 6.3 Materialization (`mfw_materialize`)

Called after every change to ACEs or bindings, and at the end of `attach`.

1. Load every ACE from `acl_db` and sort by `(acl_id, seq)`.
2. Standard: copy the ACEs of the bound standard list. Maximum 64.
3. Extended: copy the ACEs of the bound extended list, then append the
   synthetic implicit deny. Maximum 128 including that entry, so a bound
   extended list holds at most 127 user ACEs.
4. Set `direction = MFW_DIR_INGRESS` on every compiled entry.
5. If `maps/acl_std` or `maps/acl_ext` is not pinned (nothing attached yet),
   stop here successfully. `attach` will materialize later.
6. Write all 64 + 128 entries: new entries first, then zero the rest.
7. Increment `config.generation`.

**Not atomic.** Entries are written one at a time. While a write is in
progress, the XDP program can see a mix of old and new entries. This is
accepted for a single-admin tool (see §8.4 for options).

---

## 7. CLI reference

### 7.1 Commands

```text
mfw attach -i <ifname> [--xdp-mode native|generic|auto]
mfw detach -i <ifname> [--purge-maps]

mfw ip access-list <1-99>    [seq] permit|deny <src>
mfw ip access-list <100-199> [seq] permit|deny <proto> <src> [<port>] <dst> [<port>] [established]
mfw no ip access-list <list> [<seq>]
mfw ip access-group <list> in <ifname>
mfw no ip access-group [<list>] in <ifname>
mfw show ip access-lists [<list>]
mfw show ip access-group [<ifname>]

mfw stats [--json]
mfw set drop-ipv4-fragments 0|1
mfw set-default deny|allow        # deny: no-op; allow: rejected (design K10)
mfw version
mfw help
```

The leading `ip` is optional (`mfw access-list …`, `mfw show access-lists`).

### 7.2 Grammar

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

`show ip access-lists` prints ACEs in canonical form (`/16` becomes
`10.1.0.0 0.0.255.255`, a range ending at 65535 becomes `gt N`). Bound
lists are marked `[in <ifname>]`.

### 7.3 Exit codes

| Code | Meaning |
|------|---------|
| 0 | success |
| 1 | usage error |
| 2 | kernel or libbpf error (bpffs missing, load or attach failed) |
| 3 | not attached (`access-group` on an unattached interface, `stats`, `set`) |
| 4 | validation error |

Set `MFW_DEBUG=1` to see libbpf debug output, including the verifier log.

---

## 8. Limitations and operating notes

### 8.1 Replies need rules

Without conntrack, replies to the host's own outbound connections are
ordinary inbound packets. If an extended list is bound, permit them
explicitly:

```text
mfw ip access-list 100 permit tcp any any established   # TCP replies (ACK or RST set)
mfw ip access-list 100 permit udp any eq 53 any         # DNS replies
mfw ip access-list 100 permit icmp any any              # ping replies, ICMP errors
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

### 8.3 Host-global policy

All interfaces share one set of maps. You cannot bind different lists on
different interfaces in step 1.

### 8.4 Non-atomic updates

See §6.3. If this matters later, the usual fix is double buffering: two map
pairs plus an active-index entry in `config`, flipped after the new pair is
fully written.

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
- **Fail-open by default.** With nothing bound, everything passes. A bound
  extended list fails closed.
- Non-IPv4 always passes. If IPv6 is enabled on the interface, it is not
  filtered at all.

---

## 9. Testing

| Suite | Command | Needs | Covers |
|-------|---------|-------|--------|
| Parser | `make test` | nothing | wildcard→prefix, field values, normalization, canonical round trips, every rejection rule |
| Dataplane | `make test-bpf` | root | crafted frames through `BPF_PROG_TEST_RUN`: unbound pass, standard blacklist, extended permit/deny/implicit, standard and extended combined, `established`, fragments and strict mode, VLAN/QinQ/ARP/IPv6, corrupt headers, full 64 + 128 tables, stats |
| End-to-end | `make smoke` | root, `nc`, `ping`, `python3` | real traffic between two network namespaces: attach and re-attach, standard deny and wildcard, extended permit and implicit deny, `established` for outbound TCP, bound empty list, no TC filters, CLI validation, detach and purge |

Notes:

- `test_bpf` loads the skeleton with pinning disabled, so it touches no
  interface and no pins.
- `smoke-test.sh` uses `nsenter --net` rather than `ip netns exec`, because
  the latter remounts `/sys` and hides the host's bpffs. It refuses to run
  if `/sys/fs/bpf/mfw` already exists, so it cannot clobber a live
  installation.
- To verify the verifier budget after changes:
  `sudo bpftool -d prog loadall bpf/mfw.bpf.o /sys/fs/bpf/t 2>&1 | grep processed`.
  Then remove `/sys/fs/bpf/t` and any maps pinned under `/sys/fs/bpf/`.

---

## 10. Differences from `design.md`

| Area | `design.md` (Rev 18) | Step 1 | Why |
|------|----------------------|--------|-----|
| Hooks | XDP + TC ingress + TC egress | XDP only | Local VM only; with no egress and no conntrack, TC had no remaining job |
| Extended list | TC ingress and egress | XDP, after the standard list | Earliest drop; a stateless match needs only headers |
| Egress | TC egress, local-out policy, `access-group out` | none; `out` rejected | Egress is out of scope |
| Conntrack | Cilium-style, TC | none | Deferred; `established` as a stopgap |
| Fragment tracking | Cilium-style port recovery, TC | none; port ACEs cannot match non-first fragments | Deferred |
| ACL definitions | not specified (examples define lists before attach) | `state/acl_db` + `state/bindings` pinned maps | No config file, survives process exit, cleared on reboot like other pins |
| Bound detection | sketch checked "index 0 enabled", per direction | index 0 empty = unbound | Single direction; the design's sketch would also have been wrong for out-only bindings |
| Implicit deny | trailing synthetic `deny ip any any` | same, flagged `MFW_RULE_F_IMPLICIT` | Counted separately from explicit denies |
| `established` | not in design | added (Cisco-compatible) | Makes stateless reply handling practical |
| Stats ids | TC/CT/frag ids | XDP-only set (§4.4) | Nothing shipped; clean layout, append-only from now on |
| Kernel | 5.10+ | 5.12+ | Global BPF function with pointer arguments (§3.4) |
| `rule_id` delete | `no ip access-list N <rule_id\|seq>` | by `seq` only | `rule_id` equals `(acl << 16) \| seq` anyway |
| clsact management | meta markers, TC attach | none | No TC |

---

## 11. Future work

Roughly in order of value for the local-VM use case:

1. **Conntrack**, to replace `established` and source-port reply rules.
   Outbound flows must be observed, so this brings back a TC egress hook
   (observe-only, no filtering). The lookup can stay in XDP or move with the
   extended list; see design.md §Conntrack for the Cilium-based model.
2. **Fragment port recovery**, so port ACEs work for fragmented UDP.
3. **Atomic rule updates** via double-buffered maps (§8.4).
4. **Per-ACE hit counters** for `show ip access-lists` (IOS-style
   `(N matches)`).
5. **XDP SYN cookies** once the target kernel is 6.9+ (§8.6).
6. **Per-interface policy**, if more than one interface ever needs a
   different list.
