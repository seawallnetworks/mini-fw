# mini-fw

An IPv4 L4 host firewall built on eBPF, with Cisco IOS-style numbered access lists.
See [`docs/user-manual.md`](docs/user-manual.md) for the operator manual,
[`docs/implementation.md`](docs/implementation.md) for a detailed description of
what is built, and [`docs/design.md`](docs/design.md) for the full v1 design.

**Current state: stateless ACLs in a single XDP program, inbound only,
driven by a daemon.** The target is protecting a local VM, so there is no
router or forwarding mode, **egress is never filtered**, and nothing is
attached to TC. There is no conntrack or fragment tracking yet (design
PR5a–c).

| List | Numbers | Matches | End of list |
|------|---------|---------|-------------|
| Standard | 1–99 | source IP | **pass** (blacklist) |
| Extended | 100–199 | proto, src, dst, ports, `established` | **deny** (implicit) |

Each interface has its own lists: one standard and one extended list. Each
inbound IPv4 packet is checked against the lists of the interface it
arrived on, the **standard list first**. An explicit `deny` drops it. A
`permit` or no match moves on to the **extended list**, which then permits
or drops it. A standard `permit` does **not** bypass the extended list.

- First match wins, in sequence order.
- An interface with no list bound is fail-open.
- Non-IPv4 traffic (ARP, IPv6, …) is always passed to the kernel.
- VLAN / QinQ tags (up to 2) are peeled, so tagged IPv4 gets the same policy.

## Programs

| | |
|-|-|
| `mfwd` | The daemon, run as root. The only process that touches the BPF side: it attaches and detaches interfaces, swaps rulesets, reads counters. Listens on `/run/mfwd.sock`. |
| `mfw` | Command-line client: `apply`, `check`, `show`, `status`, `stats`. |
| `libmfw.a` | For front ends such as sw_configd: `mfw_policy.h` parses and checks policies with mfwd's own rules, `mfw_client.h` talks to mfwd. No libbpf, no privileges. |

A **policy** is the whole desired state, one item per line, sent at once:

```text
acl 10 10 deny host 203.0.113.66
acl 100 10 permit tcp any host 10.0.0.5 eq 22
acl 100 20 permit tcp any any established    # replies to our outbound TCP
acl 100 30 permit udp any eq 53 any          # DNS replies
bind eth0 in 10
bind eth0 in 100
set drop-ipv4-fragments 0
```

mfwd checks all of it first, so a bad line changes nothing. Then it
attaches every interface that gets a list, swaps in each one's ruleset
atomically, and detaches interfaces that lost theirs. The kernel side is
pinned, so filtering continues while mfwd is stopped or restarting.

## Build and install

Requirements: clang, libbpf ≥ 0.7 (`libbpf-dev`), bpftool, Linux ≥ 5.12 with BTF.

```bash
make                  # mfwd, mfw, libmfw.a (objects in build/)
make test             # ACE and policy parser tests
make test-bpf         # the BPF program on crafted packets (BPF_PROG_TEST_RUN, sudo)
make test-mfwd        # mfwd on dummy interfaces: protocol, attach/detach, restarts (sudo)
make smoke            # real traffic through mfwd in two network namespaces (sudo)
sudo make install     # PREFIX=/usr/local/seawall; also installs mfwd.service
```

`/usr/local/seawall` is the prefix shared by the Seawall stack
(libcli-plus, sw_authd, sw_configd). Its `bin` and `sbin` are not on
`PATH`; the examples below assume they are (see the
[user manual](docs/user-manual.md#2-installation)).

The root tests use their own pin root, socket and state directory, so they
run next to a live mini-fw without touching it.

## Usage

```bash
sudo systemctl enable --now mfwd
sudo mfw check policy.txt      # check locally, send nothing
sudo mfw apply policy.txt      # replace the running policy
sudo mfw show                  # the running policy, normalized
sudo mfw status                # generation, attached and missing interfaces
sudo mfw stats [--json]
sudo mfw apply /dev/null       # unbind everything, detach every interface
sudo mfwd -P                   # remove mini-fw completely (pins, saved policy)
```

Run `mfw help` for the grammar. Wildcards must be contiguous (`0.0.0.255`), and
CIDR (`10.0.0.0/8`) is also accepted. Ports: `eq N`, `range LO HI`, `gt N`, `lt N`.

`mfw` exit status: 0 ok, 1 refused by mfwd, 2 usage or connection error.

## mfwd protocol

One request per connection on the Unix socket; mfwd replies and closes.

| Request | Reply |
|---------|-------|
| `PING` | `OK` |
| `STATUS` | `OK generation=N drop-ipv4-fragments=0\|1 attached=a,b missing=c` |
| `STATS` | `OK xdp_pass=N xdp_drop=N …` (every counter) |
| `SHOW` | `OK <n>`, then the running policy in n lines |
| `APPLY`, policy lines, `END` | `OK <generation>[ missing=a,b]` |

Errors are `ERR <code> <message>`, with code `badreq` (malformed request),
`invalid` (the policy was refused; the message names the line), `kernel`
or `internal`. A request must arrive within 3 s and be at most 1 MiB.
The socket is root-only by default (`-m`, `-g` to change that).

## Stateless caveats (until conntrack lands)

- **Outbound traffic always leaves, but its replies are inbound and get
  filtered.** If you bind an extended list, also permit those replies. Use `established` for
  TCP (matches ACK or RST) and source-port ACEs for UDP. Example: `permit udp any eq 53 any`.
- **Non-first IPv4 fragments carry no ports.** They only match ACEs without
  port constraints or `established`. `set drop-ipv4-fragments 1` drops all
  fragments.

## Implementation notes (vs `design.md`)

- **A daemon owns the kernel side.** mfwd is the only writer of the BPF maps
  and links. It keeps the applied policy in `/run/mfwd/policy`, so a restarted
  mfwd knows it, and applies it again if the pins are gone. On start it also
  moves attached interfaces to the program it loaded, so upgrading mfwd
  upgrades the BPF code without a gap.
- **XDP only, ingress only.** Both lists run in XDP. The design's TC ingress
  and egress programs, `access-group … out`, and the egress list order are
  dropped. `mfw_rule.direction` stays in the ABI but is always `in`. If
  conntrack is added later, it will need a TC egress hook again to see
  outbound flows.
- **Per-packet cost.** XDP runs before GRO, so the extended list is scanned
  for every wire packet, not once per merged GRO packet as in TC. That is the
  trade-off for dropping disallowed traffic as early as possible.
- **Per-interface rulesets.** `maps/rulesets` is a map-in-map keyed by ifindex.
  Each attached interface gets an inner map holding one `struct mfw_ruleset`:
  its standard and extended ACEs, compiled. The design's shared
  `acl_std`/`acl_ext` maps (K14) are gone.
- **Atomic updates.** A change builds a new inner map and swaps it in with one
  map update, so a packet sees the whole old ruleset or the whole new one.
- **Implicit deny.** Running off the end of a bound extended list drops the
  packet and counts `ext_implicit_deny`, separately from explicit deny ACEs. It
  takes no ACE slot, so an extended list holds 128 ACEs.
- **`established` keyword.** Added (Cisco-compatible) as the stateless way to
  allow TCP replies. It uses the spare `mfw_rule.flags` byte.
- **Attach.** XDP uses a pinned `bpf_link` (native mode, falling back to
  generic). A link whose interface was deleted is noticed and replaced.
- **Verifier.** The per-ACE extended match is a global BPF function, so it is
  verified once. Both loops (64 standard + 128 extended ACEs) then verify in
  about 16K of the 1M instruction budget. Global functions with pointer args
  need **kernel 5.12+**, not the design's 5.10.
- **Stats.** There are two outcomes (`xdp_pass`, `xdp_drop`) and one reason
  per packet (`std_deny`, `ext_permit`, `ext_implicit_deny`, …). New ids are
  appended at the end.
