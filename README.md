# mini-fw

An IPv4 L4 host firewall built on eBPF, with Cisco IOS-style numbered access lists.
See [`docs/design.md`](docs/design.md) for the full v1 design.

**Current state: step 1, stateless ACLs in a single XDP program, inbound
only.** The target is protecting a local VM, so there is no router or
forwarding mode, **egress is never filtered**, and nothing is attached to TC.
There is no conntrack or fragment tracking yet (design PR5a–c). This step
covers PR1–PR4, cut down to ingress and XDP, plus a minimal `stats`/`set`.

| List | Numbers | Matches | End of list |
|------|---------|---------|-------------|
| Standard | 1–99 | source IP | **pass** (blacklist) |
| Extended | 100–199 | proto, src, dst, ports, `established` | **deny** (implicit) |

Each inbound IPv4 packet is checked against the **standard list first**. An
explicit `deny` drops it. A `permit` or no match moves on to the **extended
list**, which then permits or drops it. A standard `permit` does **not**
bypass the extended list.

- First match wins, in sequence order.
- A list with no `access-group` is fail-open.
- Non-IPv4 traffic (ARP, IPv6, …) is always passed to the kernel.
- VLAN / QinQ tags (up to 2) are peeled, so tagged IPv4 gets the same policy.

## Build

Requirements: clang, libbpf ≥ 0.7 (`libbpf-dev`), bpftool, Linux ≥ 5.12 with BTF.

```bash
make            # builds bpf/mfw.bpf.o and the ./mfw binary (BPF object embedded)
make test       # userspace parser tests
make test-bpf   # runs the BPF programs on crafted packets (BPF_PROG_TEST_RUN, sudo)
make smoke      # end-to-end in two network namespaces (sudo)
```

## Usage

```bash
# Define lists (works before or after attach)
mfw ip access-list 10 deny host 203.0.113.66
mfw ip access-list 100 permit tcp any host 10.0.0.5 eq 22
mfw ip access-list 100 permit icmp any any
mfw ip access-list 100 permit tcp any any established   # replies to our outbound TCP
mfw ip access-list 100 permit udp any eq 53 any         # DNS replies

mfw attach -i eth0
mfw ip access-group 10 in eth0      # standard list
mfw ip access-group 100 in eth0     # extended list ('out' is rejected)

mfw show ip access-lists
mfw show ip access-group
mfw stats [--json]

mfw no ip access-list 100 20        # delete one ACE by sequence
mfw no ip access-group in eth0      # unbind (back to fail-open)
mfw detach -i eth0 --purge-maps
```

Run `mfw help` for the full grammar. Wildcards must be contiguous (`0.0.0.255`), and
CIDR (`10.0.0.0/8`) is also accepted. Ports: `eq N`, `range LO HI`, `gt N`, `lt N`.

Exit codes: 0 ok, 1 usage, 2 kernel/libbpf, 3 not attached, 4 validation.

## Stateless caveats (until conntrack lands)

- **Outbound traffic always leaves, but its replies are inbound and get
  filtered.** If you bind an extended list, also permit those replies. Use `established` for
  TCP (matches ACK or RST) and source-port ACEs for UDP. Example: `permit udp any eq 53 any`.
- **Non-first IPv4 fragments carry no ports.** They only match ACEs without
  port constraints or `established`. `mfw set drop-ipv4-fragments 1` drops all
  fragments.
- **Bindings are host-global.** All attached interfaces share one set of maps
  (design K14). The interface name in `access-group` must be attached and is
  recorded for display only.
- **Rule updates are not atomic.** Maps are rewritten entry by entry (single
  writer, best effort).

## Implementation notes (step 1 vs `design.md`)

- **ACL store.** Lists live in two userspace-only pinned maps,
  `/sys/fs/bpf/mfw/state/{acl_db,bindings}`. That way they can be defined before
  `attach` without a config file. Like every other pin, they are cleared on reboot.
- **XDP only, ingress only.** Both lists run in XDP. The design's TC ingress
  and egress programs, `access-group … out`, and the egress list order are
  dropped. `mfw_rule.direction` stays in the ABI but is always `in`. If
  conntrack is added later, it will need a TC egress hook again to see
  outbound flows.
- **Per-packet cost.** XDP runs before GRO, so the extended list is scanned
  for every wire packet, not once per merged GRO packet as in TC. That is the
  trade-off for dropping disallowed traffic as early as possible.
- **Implicit deny.** It is materialized as a trailing ACE flagged
  `MFW_RULE_F_IMPLICIT`, so stats can tell it apart from explicit deny ACEs. A
  list is unbound exactly when its map is empty.
- **`established` keyword.** Added (Cisco-compatible) as the stateless way to
  allow TCP replies. It uses the spare `mfw_rule.flags` byte.
- **Attach.** XDP uses a pinned `bpf_link` (native mode, falling back to
  generic). Re-attaching swaps the program atomically.
- **Verifier.** The per-ACE extended match is a global BPF function, so it is
  verified once. Both loops (64 standard + 128 extended ACEs) then verify in
  about 16K of the 1M instruction budget. Global functions with pointer args
  need **kernel 5.12+**, not the design's 5.10.
- **Stats.** There are two outcomes (`xdp_pass`, `xdp_drop`) and one reason
  per packet (`std_deny`, `ext_permit`, `ext_implicit_deny`, …). New ids are
  appended at the end.
