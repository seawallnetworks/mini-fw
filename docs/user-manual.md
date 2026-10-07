# mini-fw User Manual

`mfw` is a small inbound firewall for a Linux VM. It filters IPv4 traffic
in XDP, the earliest point where the kernel sees a packet, using
Cisco IOS-style numbered access lists.

This manual is for people who run `mfw`. For how it works internally, see
[`implementation.md`](implementation.md).

**Contents**

1. [Before you start](#1-before-you-start)
2. [Installation](#2-installation)
3. [Concepts](#3-concepts)
4. [Quick start](#4-quick-start)
5. [Writing access lists](#5-writing-access-lists)
6. [Recipes](#6-recipes)
7. [Applying policy safely](#7-applying-policy-safely)
8. [Monitoring](#8-monitoring)
9. [Command reference](#9-command-reference)
10. [Persistence across reboots](#10-persistence-across-reboots)
11. [Removing mini-fw](#11-removing-mini-fw)
12. [Troubleshooting](#12-troubleshooting)
13. [FAQ](#13-faq)

---

## 1. Before you start

### 1.1 What mfw does

- Filters **inbound IPv4** packets on the interfaces you attach it to.
- **Never touches outbound traffic.** Everything the VM sends leaves normally.
- Is **stateless**: each packet is judged on its own, with no memory of
  connections. This matters for reply traffic (§3.4).
- **Passes all non-IPv4 traffic** untouched: ARP, IPv6, LLDP and so on.

### 1.2 Requirements

| Requirement | How to check |
|-------------|--------------|
| Linux kernel 5.12 or newer, with BTF | `uname -r`; `ls /sys/kernel/btf/vmlinux` |
| bpffs mounted at `/sys/fs/bpf` | `mount \| grep /sys/fs/bpf` |
| root (or `CAP_BPF` + `CAP_NET_ADMIN`) | all `mfw` commands need it |
| To build: clang, make, bpftool, libbpf-dev | `clang --version`, `bpftool version` |

If bpffs is not mounted:

```bash
sudo mount -t bpf bpf /sys/fs/bpf
```

---

## 2. Installation

```bash
git clone <repo-url> mini-fw && cd mini-fw
make                                   # builds ./mfw (the BPF program is embedded)
sudo install -m 0755 mfw /usr/local/sbin/mfw
mfw version
```

```text
mfw 0.1.0 (stateless ACL), ABI 1
```

On Debian/Ubuntu the build dependencies are:

```bash
sudo apt install clang llvm make libbpf-dev linux-tools-common linux-tools-$(uname -r)
```

Optional self-tests (the last two need root):

```bash
make test        # parser tests
make test-bpf    # runs the firewall program on crafted packets
make smoke       # real traffic between two network namespaces
```

---

## 3. Concepts

### 3.1 Two kinds of access list

| | Standard list | Extended list |
|--|---------------|---------------|
| Numbers | **1–99** | **100–199** |
| Matches on | source IP only | protocol, source, destination, ports, TCP `established` |
| Purpose | **blacklist**: block specific sources early | **allowlist**: say exactly what may come in |
| If no rule matches | packet **continues** | packet is **dropped** (implicit deny) |

### 3.2 How a packet is judged

```text
inbound IPv4 packet
   │
   ├─ standard list:   deny matches  → DROP
   │                   anything else → continue
   │
   └─ extended list:   permit matches   → ACCEPT
                       deny matches     → DROP
                       nothing matches  → DROP
```

- Inside each list, rules are checked **in sequence-number order**, and the
  **first match wins**.
- **A standard `permit` does not skip the extended list.** It only ends the
  standard check.
- **A list that is not bound does nothing.** With no lists bound, every
  packet is accepted.

### 3.3 Defining versus binding

Writing rules and enforcing them are separate steps, as on Cisco IOS:

1. `mfw ip access-list …` adds rules to a list. Nothing is enforced yet.
2. `mfw ip access-group <list> in <iface>` **binds** the list. From now on
   it is enforced, and later edits to the list take effect immediately.

You can bind at most **one standard and one extended list** at a time.
Bindings apply to **all attached interfaces** (the interface name is
recorded for display only).

### 3.4 Replies are inbound too

Because mfw is stateless, it doesn't know that a packet is a reply to a
connection your VM opened. When the VM browses the web, resolves DNS or
pings, the replies are ordinary inbound packets and must be permitted by the
extended list:

| Your VM does | The reply looks like | Rule that lets it in |
|--------------|---------------------|----------------------|
| opens TCP connections | TCP with ACK set | `permit tcp any any established` |
| DNS lookups | UDP from port 53 | `permit udp any eq 53 any` |
| NTP time sync | UDP from port 123 | `permit udp any eq 123 any` |
| DHCP lease renewal | UDP 67 → 68 | `permit udp any eq 67 any eq 68` |
| ping | ICMP echo reply | `permit icmp any any` |

**Forgetting these is the most common mistake.** Section 6.1 has a ready-made
baseline.

---

## 4. Quick start

Goal: a VM that accepts SSH from anywhere, blocks one abusive host, and can
still reach the internet.

```bash
# 1. Attach to the interface (does not block anything yet)
sudo mfw attach -i eth0

# 2. Write the lists
sudo mfw ip access-list 10 deny host 203.0.113.66            # blacklist

sudo mfw ip access-list 100 permit tcp any any eq 22         # SSH in
sudo mfw ip access-list 100 permit tcp any any established   # TCP replies
sudo mfw ip access-list 100 permit udp any eq 53 any         # DNS replies
sudo mfw ip access-list 100 permit udp any eq 123 any        # NTP replies
sudo mfw ip access-list 100 permit udp any eq 67 any eq 68   # DHCP
sudo mfw ip access-list 100 permit icmp any any              # ping

# 3. Bind them (now enforced). See §7 for doing this safely over SSH.
sudo mfw ip access-group 10 in eth0
sudo mfw ip access-group 100 in eth0

# 4. Check
sudo mfw show ip access-lists
sudo mfw stats
```

`show ip access-lists` prints:

```text
Standard IP access list 10  [in eth0]
    10 deny host 203.0.113.66
Extended IP access list 100  [in eth0]
    10 permit tcp any any eq 22
    20 permit tcp any any established
    30 permit udp any eq 53 any
    40 permit udp any eq 123 any
    50 permit udp any eq 67 any eq 68
    60 permit icmp any any
```

---

## 5. Writing access lists

### 5.1 Syntax

```text
mfw ip access-list <1-99>    [<seq>] permit|deny <source>
mfw ip access-list <100-199> [<seq>] permit|deny <protocol> <source> [<port>] <destination> [<port>] [established]
```

The `ip` keyword is optional: `mfw access-list 10 deny any` works too.

### 5.2 Addresses

| Write | Means |
|-------|-------|
| `any` | every address |
| `host 192.0.2.10` | exactly that address |
| `192.0.2.0 0.0.0.255` | network with a Cisco **wildcard** mask (inverse of a netmask) |
| `192.0.2.0/24` | the same network in CIDR form |
| `192.0.2.10` | standard lists only: same as `host 192.0.2.10` |

Wildcards must be contiguous: `0.0.0.255` is fine, `0.0.2.255` is rejected.
Host bits are cleared for you: `192.0.2.77 0.0.0.255` is stored as
`192.0.2.0 0.0.0.255`.

Common wildcards:

| CIDR | Wildcard |
|------|----------|
| /32 | `0.0.0.0` (use `host`) |
| /24 | `0.0.0.255` |
| /16 | `0.0.255.255` |
| /8 | `0.255.255.255` |

### 5.3 Protocols

`ip` (any protocol), `tcp`, `udp`, `icmp`, or a protocol number `0`–`255`
(for example `47` for GRE).

### 5.4 Ports (tcp and udp only)

A port operand can follow the source address, the destination address, or
both. Omitting it means any port.

| Write | Matches |
|-------|---------|
| `eq 443` | port 443 |
| `range 8000 8099` | 8000 to 8099 inclusive |
| `gt 1023` | 1024 to 65535 |
| `lt 1024` | 1 to 1023 |

Remember that a **source** port comes right after the source address:
`permit udp any eq 53 any` means "from port 53", while
`permit udp any any eq 53` means "to port 53".

Port 0 cannot be used.

### 5.5 `established` (tcp only)

`established` matches TCP packets with the ACK or RST flag set, which means
everything except the opening SYN of a new connection. Use it to let in
replies to connections your VM started, while still blocking new inbound
connections. It must be the last word on the line.

It is a stateless approximation: a forged packet with ACK set will also
pass. The receiving kernel rejects such packets for unknown connections,
but they do reach it.

### 5.6 Sequence numbers

Each rule has a sequence number that decides its position:

- Without one, the rule goes at the end, numbered 10 above the current last
  rule (10, 20, 30, …).
- To insert a rule in between, give a number explicitly:

```bash
sudo mfw ip access-list 100 5 deny tcp 198.51.100.0 0.0.0.255 any eq 22
```

```text
Extended IP access list 100  [in eth0]
    5 deny tcp 198.51.100.0 0.0.0.255 any eq 22
    10 permit tcp any any eq 22
    ...
```

- To change a rule, delete it and add it again with the same number.

### 5.7 Deleting

```bash
sudo mfw no ip access-list 100 30     # delete the rule with sequence 30
sudo mfw no ip access-list 100        # delete the whole list
```

Deleting a list does **not** unbind it. A bound extended list with no rules
**drops all IPv4**. A bound standard list with no rules does nothing.

### 5.8 Limits

| | Maximum |
|-|---------|
| Rules in the bound standard list | 64 |
| Rules in the bound extended list | 127 |
| Rules across all lists (bound or not) | 4096 |

Commands that would exceed a limit fail and change nothing.

---

## 6. Recipes

All recipes assume `mfw attach -i eth0` has been run and list 100 is bound
with `mfw ip access-group 100 in eth0`.

### 6.1 Baseline for a VM that needs the internet

Start every extended list with these, then add your services:

```bash
sudo mfw ip access-list 100 permit tcp any any established
sudo mfw ip access-list 100 permit udp any eq 53 any
sudo mfw ip access-list 100 permit udp any eq 123 any
sudo mfw ip access-list 100 permit udp any eq 67 any eq 68
sudo mfw ip access-list 100 permit icmp any any
```

Drop the DHCP line if the VM has a static address. Drop the NTP line if it
doesn't sync time over the network.

### 6.2 SSH only from an admin network

```bash
sudo mfw ip access-list 100 permit tcp 192.0.2.0 0.0.0.255 any eq 22
```

Anything else to port 22 hits the implicit deny.

### 6.3 Public web server

```bash
sudo mfw ip access-list 100 permit tcp any any eq 80
sudo mfw ip access-list 100 permit tcp any any eq 443
```

### 6.4 Block a host or network completely

Use the standard list. It drops the traffic before any other check:

```bash
sudo mfw ip access-list 10 deny host 203.0.113.66
sudo mfw ip access-list 10 deny 198.51.100.0/24
sudo mfw ip access-group 10 in eth0
```

A standard list alone (no extended list bound) is a pure blacklist:
everything not denied gets in.

### 6.5 Block one service from one network, allow it for others

Put the deny before the permit:

```bash
sudo mfw ip access-list 100 5 deny tcp 198.51.100.0 0.0.0.255 any eq 22
sudo mfw ip access-list 100 10 permit tcp any any eq 22
```

### 6.6 Allow a port range (passive FTP, game servers)

```bash
sudo mfw ip access-list 100 permit tcp any any range 50000 50100
```

### 6.7 Large UDP messages (fragments)

Only the first fragment of a large UDP datagram carries ports, so a rule
like `permit udp any any eq 4789` lets the first fragment in and drops the
rest. Either permit the sender by address:

```bash
sudo mfw ip access-list 100 permit udp host 192.0.2.50 any
```

or decide not to accept fragmented traffic at all:

```bash
sudo mfw set drop-ipv4-fragments 1
```

---

## 7. Applying policy safely

**Binding an extended list can lock you out of a remote VM.** If the list
doesn't permit your SSH session, your connection freezes the moment you
bind it.

Before binding, check that the list contains:

1. a rule permitting your SSH traffic, for example `permit tcp any any eq 22`, and
2. `permit tcp any any established` if you want outbound connections to work.

An already-open SSH session survives if the list has the `established`
rule, because every packet after the first carries ACK. **New** logins still
need the port-22 rule. Test with a second login, not your current session.

When working remotely, use a dead-man switch: bind the list, then
automatically unbind it after a few minutes unless you cancel. Run this in a
root shell (`sudo -i`), so the background job can be cancelled:

```bash
# 1. Arm: unbind automatically in 3 minutes
(sleep 180; mfw no ip access-group in eth0) &
DEADMAN=$!

# 2. Apply
mfw ip access-group 100 in eth0

# 3. Open a NEW SSH session from your workstation. If it works, return to
#    this shell and disarm:
kill $DEADMAN
```

If the new session fails, wait three minutes for the policy to be unbound,
then fix the list.

If you are locked out, use the VM console (hypervisor or cloud serial
console) and run `mfw no ip access-group in eth0` or `mfw detach -i eth0`.
A reboot also clears all mfw state (§10).

---

## 8. Monitoring

### 8.1 Counters

```bash
sudo mfw stats
sudo mfw stats --json
```

Example output (the numbers are illustrative):

```text
xdp_pass           18342
xdp_drop           271
std_deny           12
std_permit         0
ext_permit         18119
ext_deny           3
ext_implicit_deny  256
parse_err          0
frag_drop          0
non_ipv4           223
```

| Counter | Meaning |
|---------|---------|
| `xdp_pass` | packets accepted |
| `xdp_drop` | packets dropped |
| `std_deny` | dropped by a standard `deny` rule |
| `std_permit` | accepted by a standard `permit` rule (only counted when no extended list is bound) |
| `ext_permit` | accepted by an extended `permit` rule |
| `ext_deny` | dropped by an extended `deny` rule |
| `ext_implicit_deny` | dropped because no extended rule matched |
| `parse_err` | dropped because the IPv4 or VLAN header was malformed |
| `frag_drop` | dropped fragments (`drop-ipv4-fragments` is 1) |
| `non_ipv4` | non-IPv4 packets passed through unchecked |

`xdp_pass + xdp_drop` is the total packet count. Counters are cumulative and
are only reset by `mfw detach --purge-maps`. To measure a period, take two
readings and subtract.

**Rising `ext_implicit_deny` right after a change** usually means a missing
reply rule (§3.4).

### 8.2 Seeing the current policy

```bash
sudo mfw show ip access-lists          # all lists; bound ones are marked [in <iface>]
sudo mfw show ip access-lists 100      # one list
sudo mfw show ip access-group          # what is bound
```

```text
standard in  list 10  (via eth0)
extended in  list 100 (via eth0)
```

An unbound slot shows `not set (fail-open)`.

---

## 9. Command reference

| Command | What it does |
|---------|--------------|
| `mfw attach -i <iface> [--xdp-mode native\|generic\|auto]` | Load mini-fw on an interface. Default mode `auto` tries native XDP, then falls back to generic. Running it again on the same interface replaces the program without a gap. |
| `mfw detach -i <iface>` | Remove mini-fw from an interface. Lists and bindings are kept. |
| `mfw detach -i <iface> --purge-maps` | Also delete all lists, bindings and counters. Refused while other interfaces are still attached. |
| `mfw ip access-list <list> [<seq>] …` | Add a rule (§5). |
| `mfw no ip access-list <list> [<seq>]` | Delete a rule or a whole list. |
| `mfw ip access-group <list> in <iface>` | Bind a list. Replaces any list of the same kind that was bound. The interface must be attached. |
| `mfw no ip access-group [<list>] in <iface>` | Unbind both lists, or just `<list>`. |
| `mfw show ip access-lists [<list>]` | Print lists. |
| `mfw show ip access-group [<iface>]` | Print bindings. |
| `mfw stats [--json]` | Print counters. |
| `mfw set drop-ipv4-fragments 0\|1` | 1 drops every IPv4 fragment. Default 0. |
| `mfw set-default deny` | Accepted for Cisco compatibility; does nothing. `allow` is rejected. |
| `mfw version` | Print version. |
| `mfw help` | Print usage. |

Only `in` exists. `out` is rejected:

```text
$ sudo mfw ip access-group 100 out eth0
mfw: 'out' is not supported: egress is not filtered
```

### 9.1 Exit codes

| Code | Meaning |
|------|---------|
| 0 | success |
| 1 | wrong command usage |
| 2 | kernel or libbpf error |
| 3 | interface not attached (or nothing attached yet) |
| 4 | invalid rule or argument |

---

## 10. Persistence across reboots

mini-fw keeps everything in the kernel (under `/sys/fs/bpf/mfw`). A reboot
clears all of it: the VM boots **unprotected** until you apply the policy
again. Keep your policy as a script and run it at boot.

Example `/usr/local/sbin/mfw-apply`:

```bash
#!/bin/sh
set -e
IF=eth0
mfw detach -i $IF --purge-maps 2>/dev/null || true
mfw attach -i $IF

mfw ip access-list 10 deny host 203.0.113.66

mfw ip access-list 100 permit tcp any any established
mfw ip access-list 100 permit udp any eq 53 any
mfw ip access-list 100 permit udp any eq 123 any
mfw ip access-list 100 permit udp any eq 67 any eq 68
mfw ip access-list 100 permit icmp any any
mfw ip access-list 100 permit tcp any any eq 22

mfw ip access-group 10 in $IF
mfw ip access-group 100 in $IF
```

Example systemd unit `/etc/systemd/system/mfw.service`:

```ini
[Unit]
Description=mini-fw inbound firewall
After=network-pre.target sys-fs-bpf.mount
Before=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/sbin/mfw-apply
ExecStop=/usr/local/sbin/mfw detach -i eth0 --purge-maps

[Install]
WantedBy=multi-user.target
```

```bash
sudo chmod +x /usr/local/sbin/mfw-apply
sudo systemctl daemon-reload
sudo systemctl enable --now mfw.service
```

The interface must exist when the script runs. Adjust `After=` if your
interface appears late.

These are examples, not files shipped with mini-fw. Test them on the console
before relying on them remotely.

---

## 11. Removing mini-fw

```bash
sudo mfw detach -i eth0 --purge-maps     # repeat -i for each attached interface; purge on the last
sudo rm /usr/local/sbin/mfw
```

If the `mfw` binary is gone but the firewall is still active:

```bash
sudo rm /sys/fs/bpf/mfw/link/xdp_eth0    # detaches the program
sudo rm -r /sys/fs/bpf/mfw               # removes all state
```

---

## 12. Troubleshooting

| Symptom | Likely cause | Fix |
|---------|--------------|-----|
| `bpffs is not mounted at /sys/fs/bpf` | bpffs missing | `sudo mount -t bpf bpf /sys/fs/bpf` |
| `cannot open ACL store … are you root?` | not root | use `sudo` |
| `load BPF object: …` | kernel too old (< 5.12), no BTF, or not root | check §1.2; rerun with `MFW_DEBUG=1` to see the verifier log |
| `XDP attach on eth0 (auto): …` (or `native` / `generic`) | another XDP program is already attached, or the driver rejects XDP | check `ip link show eth0` for an existing `xdp` program and remove it; try `--xdp-mode generic` |
| `eth0 is not attached` when binding | `access-group` needs an attached interface | `mfw attach -i eth0` first |
| `pinned maps have ABI N, expected 1` | state left by a different mfw version | `mfw detach -i <iface> --purge-maps`, then attach again |
| DNS, updates or web browsing stopped working | extended list lacks reply rules | add the §6.1 baseline |
| VM lost its IP address after some hours | DHCP renewal replies blocked | `permit udp any eq 67 any eq 68` |
| A service is unreachable | no permit rule, or a deny rule above it | `mfw show ip access-lists`; watch `ext_implicit_deny` / `ext_deny` while testing |
| Everything blocked after deleting rules | bound extended list is now empty | add rules or `mfw no ip access-group in <iface>` |
| Large UDP transfers fail | non-first fragments dropped | §6.7 |
| IPv6 traffic not filtered | by design: only IPv4 is filtered | disable IPv6 or use ip6tables/nftables for it |
| `--purge-maps refused` | other interfaces still attached | detach the others first |
| `list 100 already has sequence N` | duplicate sequence number | pick another, or delete the old rule first |
| `non-contiguous wildcard` | wildcard like `0.0.2.255` | use a contiguous wildcard or CIDR |
| `'10.0.0.1' needs a wildcard` | extended lists need `host` or a wildcard | write `host 10.0.0.1` |

Useful low-level checks:

```bash
ip link show eth0                                   # shows "xdp" or "xdpgeneric" when attached
sudo bpftool prog show name mfw_xdp
sudo bpftool map dump pinned /sys/fs/bpf/mfw/maps/acl_ext
```

---

## 13. FAQ

**Does mfw replace iptables or nftables?**
No. They can run side by side. mfw decides first (in XDP); packets it
accepts then go through netfilter as usual.

**Can I filter outgoing traffic?**
No. mini-fw only filters inbound traffic.

**Can I use different lists on different interfaces?**
Not currently. Bindings apply to every attached interface.

**What happens if I attach but bind nothing?**
Nothing is blocked. mfw only counts packets.

**Is there a default-deny without writing rules?**
Bind an extended list. If it has no rules, it drops all inbound IPv4.
Only do this from the console.

**Does a standard `permit` override the extended list?**
No. A standard `permit` only stops the standard check; the extended list
still decides.

**Are rule changes applied instantly?**
Yes, changes to a bound list take effect immediately. During the
millisecond-scale update, a packet can briefly see a mix of old and new
rules.

**Does mfw protect against SYN floods?**
mfw drops SYNs to ports you haven't permitted. For permitted ports, the
kernel's own SYN cookies (`net.ipv4.tcp_syncookies = 1`, the default)
protect the listening service.

**Do I need to restart anything after changing rules?**
No.
