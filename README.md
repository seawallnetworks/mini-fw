# mini-fw

An IPv4 L4 host firewall built on eBPF, with Cisco IOS-style numbered access lists.
See [`docs/user-manual.md`](docs/user-manual.md) for the operator manual,
[`docs/implementation.md`](docs/implementation.md) for a detailed description of
what is built, [`docs/design.md`](docs/design.md) for the full v1 design, and
[`docs/userspace-ebpf.md`](docs/userspace-ebpf.md) ([中文](docs/userspace-ebpf.zh-CN.md))
for how mfwd loads, pins and attaches the BPF side.

**Current state: stateless ACLs at XDP, in libxdp's dispatcher, or at TC
ingress when another program holds the XDP hook; inbound only, driven by
a daemon.** The target is protecting a local VM, so there is no router or
forwarding mode, and **egress is never filtered**. In the dispatcher a DDoS
gate such as [voidgate](https://github.com/seawallnetworks/voidgate) runs
first. There is no conntrack or fragment tracking yet (design PR5a–c):
replies to the host's own connections pass with no rule, found in
[sw_flowd](https://github.com/seawallnetworks/sw_flowd)'s table of the
flows the host opened (Seawall proposal 0015).

| List | Numbers | Matches | End of list |
|------|---------|---------|-------------|
| Standard | 1–99 | source IP | **pass** (blacklist) |
| Extended | 100–199 | proto, src, dst, ports, `established` | **deny** (implicit) |

Each interface has its own lists: one standard and one extended list. Each
inbound IPv4 packet is checked against the lists of the interface it
arrived on, the **standard list first**. An explicit `deny` drops it. A
`permit` or no match moves on. Where an extended list is bound, a **reply
to a flow the host opened** then passes, with no rule; anything else goes
to the **extended list**, which permits or drops it. So the extended list
says only who may connect in. A standard `permit` does **not** bypass the
extended list.

- First match wins, in sequence order.
- An interface with no list bound is fail-open.
- Non-IPv4 traffic (ARP, IPv6, …) is always passed to the kernel.
- VLAN / QinQ tags (up to 2) are peeled, so tagged IPv4 gets the same policy.

## Programs

| | |
|-|-|
| `mfwd` | The daemon, run as root. The only process that touches the BPF side: it attaches and detaches interfaces, swaps rulesets, reads counters. Listens on `/run/mfwd.sock`. |
| `mfw` | Command-line client: `apply`, `check`, `show`, `status`, `stats`. |
| `libmfw.a` | For front ends such as sw_configd: `mfw_policy.h` parses and checks policies with mfwd's own rules, `mfw_proto.h` talks to mfwd. No libbpf, no privileges. |

A **policy** is the whole desired state, one item per line, sent at once:

```text
acl 10 10 deny host 203.0.113.66
acl 100 10 permit tcp any host 10.0.0.5 eq 22  # who may connect in
bind eth0 in 10
bind eth0 in 100
set drop-ipv4-fragments 0
set reply-idle-tcp 86400                     # the defaults: how long a flow
set reply-idle-udp 180                       # the host opened may be idle
```

The host's own traffic needs no rule: replies to the flows it opened
pass before the extended list, ICMP errors about them too, and
"fragmentation needed" whatever connection it is about, so path MTU
discovery works for the services the host offers as well. Without
sw_flowd's table, only TCP with ACK or RST and "fragmentation needed"
pass so: then permit what else the host needs, such as DNS's replies.
"Fragmentation needed" passes in any case: without it, a connection
whose path has a smaller MTU, such as from a VPC's jumbo frames to the
internet, hangs on the first full-size packet the VM sends.

mfwd checks all of it first, so a bad line changes nothing. Then it
attaches every interface that gets a list, swaps in each one's ruleset
atomically, and detaches interfaces that lost theirs. The kernel side is
pinned, so filtering continues while mfwd is stopped. There is no live
update: a starting mfwd replaces the pins, so every interface passes
everything until it has applied the saved policy again.

## Build and install

Requirements: clang, libbpf ≥ 1.3 and libxdp (`libbpf-dev`, `libxdp-dev`;
mfwd links both in statically), bpftool, Linux ≥ 6.1 with BTF, bpffs at
`/sys/fs/bpf`, and sw_flowd's header (`<sw_flowd/sw_flowd.h>`, the
layout of its table: `make -C ../sw_flowd install-header`, or its `make
install`, puts it in `/usr/local/seawall/include`; `SW_FLOWD_PREFIX`
points elsewhere), and libpkt's headers (`<libpkt/parse.h>`, the
stack's packet parser: `make -C ../libpkt install` puts them in
`/usr/local/seawall/include`; `LIBPKT_PREFIX` points elsewhere), and
libsw (`libsw.a` and `libsw_bpf.a`, the stack's userspace library:
`make -C ../libsw install` puts them in `/usr/local/seawall/lib`;
`LIBSW_PREFIX` points elsewhere). `libmfw.a` needs only `libsw.a`, which
what links it links after it. Amazon Linux 2023 and Ubuntu 24.04 and 26.04 qualify. mfwd
attaches at XDP, in libxdp's dispatcher; on an interface where a program
that is not a dispatcher holds the XDP hook, at TC ingress: with tcx on 6.6
and later, and with classic TC (a cls_bpf filter on clsact) before. The
tests need xdp-tools (`xdp-loader`, `xdp-filter`), or run at TC only with
`MFW_NO_XDP=1`.

```bash
make                  # mfwd, mfw, libmfw.a (objects in build/)
make test             # ACE and policy parser tests
make test-bpf         # the BPF program on crafted packets (BPF_PROG_TEST_RUN, sudo)
make test-mfwd        # mfwd on dummy interfaces: protocol, attach/detach, restarts, sharing XDP (sudo)
make smoke            # real traffic through mfwd in two network namespaces (sudo); replies
                      # with sw_flowd (SW_FLOWD, or ../sw_flowd/sw_flowd), else skipped
sudo make install     # PREFIX=/usr/local/seawall; also installs mfwd.service
```

`make install` is `install-runtime` (`mfwd`, `mfw`, `mfwd.service`; it
needs the group `mfw` from the seawall repo, installed first) and
`install-static-lib` (`libmfw.a` and its headers, for linking a front
end such as sw_configd), which can also be run on their own.

`/usr/local/seawall` is the prefix shared by the Seawall stack
(libcli-plus, sw_authd, sw_configd). Its `bin` and `sbin` are not on
`PATH`; the examples below assume they are (see the
[user manual](docs/user-manual.md#2-installation)).

The root tests run on a bpffs of their own, with their own socket and
run directory, so they run next to a live mini-fw without touching it.

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

`mfw` exit status: 0 ok, 1 refused by mfwd, 2 usage, file or connection
error.

## mfwd protocol

One request per connection on the Unix socket; mfwd replies and closes.

| Request | Reply |
|---------|-------|
| `PING` | `OK` |
| `STATUS` | `OK generation=N drop-ipv4-fragments=0\|1 attached=a,b missing=c degraded=d flows=sw_flowd\|none` (`degraded`: at TC, another program holds XDP; `flows`: whether replies are read from sw_flowd's table, or fall back to `established`) |
| `STATS` | `OK xdp_pass=N xdp_drop=N …` (every counter) |
| `SHOW` | `OK <n>`, then the running policy in n lines |
| `APPLY`, policy lines, `END` | `OK <generation>[ missing=a,b]` |

Errors are `ERR <code> <message>`, with code `badreq` (malformed request),
`invalid` (the policy was refused; the message names the line), `kernel`
or `internal`. A request must arrive within 3 s and be at most 1 MiB.
mfwd's socket is root-only by default (`-m`, `-g` to change that).
The shipped unit gives it to the group `mfw`, mode `0660`.

## Stateless caveats (until conntrack lands)

- **Replies to the host's own traffic pass with no rule** where an
  extended list is bound, after the standard list and before the
  extended one (Seawall proposal 0015 §4), as sw_flowd's `sf_is_reply()`
  and ICMP error check define them: TCP with ACK or RST, or UDP to a port
  in the ephemeral range, of a flow that last left within
  `reply-idle-tcp` or `reply-idle-udp` seconds, and no more than 120 s
  after the host's FIN or 10 s after its RST, so an ACK flood doesn't
  pass; echo replies to its pings; ICMP errors about its packets, and
  path MTU errors (fragmentation needed) even without a flow, which may
  be about a connection the host accepted. Counter `reply`. There is no
  switch to turn it off.
- **Block an address in the standard list.** Its denies stop replies too.
  A `deny` in the extended list doesn't: replies pass before it, so
  `deny ip host 203.0.113.9 any` there still lets that host's replies in.
- **Without sw_flowd's table** (sw_flowd not running when mfwd started,
  or a table of another layout), replies fall back to `established`: TCP
  with ACK or RST passes (counter `reply_established`); "fragmentation
  needed" about the host's packets still passes, since it needs no table;
  UDP and other ICMP go to the lists, so DNS needs a source-port ACE
  (`permit udp any eq 53 any`).
  That is weaker than the table: an ACK flood passes. Connections opened
  before sw_flowd's first start, and flows its full table evicted, are
  dropped unless the extended list permits them.
- **Non-first IPv4 fragments skip the extended list** and go to the kernel;
  the standard list, which needs only the source, still applies. The first
  fragment carries the ports and is filtered as usual; if it is dropped,
  the kernel cannot reassemble the datagram. TCP fragments at
  offset 1 are always dropped (RFC 1858, counter `tcp_frag_off1`).
  `set drop-ipv4-fragments 1` drops all fragments.

## Implementation notes (vs `design.md`)

- **A daemon owns the kernel side.** mfwd is the only writer of the BPF maps
  and attachments. It keeps the applied policy in `/run/mfwd/policy`, so a restarted
  mfwd applies it again. A start detaches everything and removes the pins
  first, as `mfwd -P` does: no live update, so a restart or upgrade is
  fail-open for a moment.
- **Ingress only, at XDP or TC.** Both lists run in one program with two
  entries over one `mfw_judge()`: `mfw_xdp`, in libxdp's dispatcher at
  priority 20, after a DDoS gate's (voidgate's is 10), and `mfw_tc` at TC
  ingress. An interface's XDP hook holds one program; libxdp's dispatcher
  runs several in turn, and mini-fw never replaces a program that is not
  one: on that interface it filters at TC instead (degraded: a TC drop costs
  more). The design's TC egress program, `access-group … out`, and the
  egress list order are dropped. If conntrack is added later, it will need
  a TC egress hook again to see outbound flows. At TC a pass is
  `TCX_NEXT`, so a tc program attached after mini-fw still runs.
- **Per-packet cost.** At TC, after GRO, the extended list is scanned once
  per merged GRO packet, not per wire packet, and a packet whose headers
  are not all in the skb's linear part is pulled in first
  (`bpf_skb_pull_data`).
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
- **Replies by default, instead of the design's conntrack.** mini-fw reads
  sw_flowd's pinned table and its config (Seawall proposal 0015), which
  record the flows the host opens at TC egress and the ephemeral range;
  it never writes them. sw_flowd starts first (`mfwd.service` is `After=`
  and `Wants=sw_flowd.service`): mfwd opens both pins when it starts, and
  every program it loads binds them (`bpf_map__reuse_fd`); a table
  without its config isn't read. An mfwd started without them logs at
  crit, and sets `no_flow_table` in its config: replies fall back to `established`
  until mfwd restarts; a restart of sw_flowd changes nothing for mfwd.
  The idle limits travel in the ruleset, with the rules, so there is no
  map for them. The ICMP error check is a global function, walked once
  by the verifier (sw_flowd.h says why). A `reply` at the end of an ACE,
  the keyword of before, is a parse error saying replies pass without
  it. A table of another layout (a sw_flowd built from another
  `sw_flowd.h`) is refused.
- **Attach.** The XDP entry in the interface's libxdp dispatcher, made or
  joined, in its mode (native, else skb, for a new one), loaded by libxdp
  from an object of its own on the pinned maps; mini-fw pins it as
  `attach/xdp_<if>`, and the dispatcher's own pins keep it there. On an
  interface whose XDP hook is held by another program, a pinned tcx
  `bpf_link` (`attach/tcx_<if>`). A kernel without tcx (before 6.6) gets a
  classic TC filter instead, handle `0x4d46` at priority `0xc000` on the
  interface's clsact ingress, and the program pinned as `attach/tc_<if>` to
  say so. A pin whose interface was deleted is noticed and replaced. A
  start purges first and attaches afresh, so an interface moves from TC to
  XDP at the next start after its hook is free. `MFW_NO_XDP=1` attaches at TC only, and `SW_NO_TCX=1`, the
  stack's switch, with classic TC on a newer kernel, for the tests.
- **Verifier.** The per-ACE extended match is a global BPF function, so it is
  verified once. Both loops (64 standard + 128 extended ACEs) then verify in
  about 16K of the 1M instruction budget. Global functions with pointer args
  need kernel 5.12+, and tcx 6.6+ (classic TC before).
- **Stats.** There are two outcomes (`xdp_pass`, `xdp_drop`, whichever
  hook) and one reason
  per packet (`std_deny`, `ext_permit`, `ext_implicit_deny`, …), each
  named in `STATS`.
