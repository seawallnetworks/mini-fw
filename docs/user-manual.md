# mini-fw User Manual

mini-fw is a small inbound firewall for a Linux VM. It filters IPv4 traffic
at TC ingress, before the kernel's IP stack and netfilter, using
Cisco IOS-style numbered access lists. XDP, which comes earlier, is left
to a DDoS gate such as voidGate.

It has two programs:

- **`mfwd`**, a daemon that runs as root and is the only thing that touches
  the kernel side.
- **`mfw`**, the command-line client. You write the whole policy in a file
  and `mfw apply` sends it to mfwd. Front ends such as sw_configd do the
  same through `libmfw.a`.

This manual is for people who run mini-fw. For how it works internally,
see [`implementation.md`](implementation.md).

**Contents**

1. [Before you start](#1-before-you-start)
2. [Installation](#2-installation)
3. [Concepts](#3-concepts)
4. [Quick start](#4-quick-start)
5. [Writing a policy](#5-writing-a-policy)
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

### 1.1 What mini-fw does

- Filters **inbound IPv4** packets on the interfaces your policy binds
  lists to.
- **Never touches outbound traffic.** Everything the VM sends leaves normally.
- Is **stateless**: each packet is judged on its own, with no memory of
  connections. This matters for reply traffic (§3.4).
- **Passes all non-IPv4 traffic** untouched: ARP, IPv6, LLDP and so on.
- **Keeps filtering when mfwd stops.** The kernel side is pinned; mfwd is
  only needed to change or inspect the policy.

### 1.2 Requirements

| Requirement | How to check |
|-------------|--------------|
| Linux kernel 6.1 or newer, with BTF | `uname -r`; `ls /sys/kernel/btf/vmlinux` |
| bpffs mounted at `/sys/fs/bpf` | `mount \| grep /sys/fs/bpf` |
| mfwd runs as root (`CAP_BPF`, `CAP_NET_ADMIN`, `CAP_SYS_ADMIN`) | `mfwd.service` does this |
| `mfw` needs access to mfwd's socket | root by default; see `mfwd -m` / `-g` |
| To build: clang, make, bpftool, libbpf-dev | `clang --version`, `bpftool version` |

If bpffs is not mounted:

```bash
sudo mount -t bpf bpf /sys/fs/bpf
```

---

## 2. Installation

```bash
git clone git@github.com:seawallnetworks/mini-fw.git && cd mini-fw
make                     # mfwd, mfw and libmfw.a
sudo make install        # /usr/local/seawall/{sbin/mfwd,bin/mfw,lib/libmfw.a,include/*},
                         # /etc/systemd/system/mfwd.service
sudo systemctl daemon-reload
sudo systemctl enable --now mfwd
mfw version
sudo mfw ping
```

```text
mfw 0.4.0, ABI 2
mfwd is running
```

`/usr/local/seawall` is the prefix shared by the Seawall stack
(libcli-plus, sw_authd, sw_configd). `PREFIX` and `DESTDIR` work as usual
(`make install PREFIX=/opt/mfw`), but the unit runs
`/usr/local/seawall/sbin/mfwd` whatever `PREFIX` is.

The prefix's `bin` and `sbin` are not on `PATH`, and this manual runs
`mfw` and `mfwd` by name. Add them for login shells and for `sudo`, whose
`secure_path` replaces `PATH`:

```bash
echo 'PATH=$PATH:/usr/local/seawall/sbin:/usr/local/seawall/bin' |
    sudo tee /etc/profile.d/seawall.sh
sudo visudo -f /etc/sudoers.d/seawall   # append the two directories to
                                        # the secure_path in /etc/sudoers
```

On Debian/Ubuntu the build dependencies are:

```bash
sudo apt install clang llvm make libbpf-dev linux-tools-common linux-tools-$(uname -r)
```

On Amazon Linux 2023 (or RHEL 9 and its rebuilds):

```bash
sudo dnf install clang llvm make gcc libbpf-devel libbpf-static bpftool
```

mfwd attaches with tcx on Linux 6.6 and later, and with classic TC (a
cls_bpf filter on the interface's clsact qdisc) on 6.1 to 6.5, such as
Amazon Linux 2023's default kernel; its log says which when it starts.
Both filter the same way. With classic TC, `mfwd -P` removes the filters
from the interfaces of the network namespace it runs in.

Self-tests (all but the first need root, and none touch a running mini-fw):

```bash
make test        # ACE and policy parsing
make test-bpf    # runs the firewall program on crafted packets
make test-mfwd   # mfwd on dummy interfaces: protocol, attach/detach, restarts
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
inbound IPv4 packet on eth0
   │
   ├─ eth0's standard list:   deny matches  → DROP
   │                          anything else → continue
   │
   └─ eth0's extended list:   permit matches   → ACCEPT
                              deny matches     → DROP
                              nothing matches  → DROP
```

- Inside each list, rules are checked **in sequence-number order**, and the
  **first match wins**.
- **A standard `permit` does not skip the extended list.** It only ends the
  standard check.
- **A list that is not bound does nothing.** An interface with no lists
  bound accepts everything.

### 3.3 The policy is the whole state

A policy file says everything at once: the lists, which interface each is
bound to, and the global settings.

```text
acl 10 10 deny host 203.0.113.66
acl 100 10 permit tcp any any eq 22
bind eth0 in 10
bind eth0 in 100
```

`mfw apply` replaces the running policy with the file:

- Interfaces that get a list are **attached** automatically; interfaces
  that no longer have one are **detached**.
- Lists left out of the file are gone.
- The file is checked completely first. If anything is wrong, **nothing
  changes** and the error names the line.
- Each interface switches to its new rules in one step: no packet ever sees
  half of an update.

Each interface can have **one standard and one extended list** bound, and
different interfaces can have different lists.

### 3.4 Replies are inbound too

Because mini-fw is stateless, it doesn't know that a packet is a reply to a
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

Write `/usr/local/seawall/etc/mfw/policy`:

```text
# blacklist
acl 10 10 deny host 203.0.113.66

# what may come in
acl 100 10 permit tcp any any eq 22            # SSH
acl 100 20 permit tcp any any established      # TCP replies
acl 100 30 permit udp any eq 53 any            # DNS replies
acl 100 40 permit udp any eq 123 any           # NTP replies
acl 100 50 permit udp any eq 67 any eq 68      # DHCP
acl 100 60 permit icmp any any                 # ping

bind eth0 in 10
bind eth0 in 100
```

Then:

```bash
# check only reads the file and sends nothing; see §7 for applying it
# safely over SSH
sudo mfw check /usr/local/seawall/etc/mfw/policy
sudo mfw apply /usr/local/seawall/etc/mfw/policy
sudo mfw status
sudo mfw stats
```

```text
ok: 7 ACEs, 1 interfaces
applied, generation 1
generation           1
attached             eth0
missing              -
drop-ipv4-fragments  0
```

---

## 5. Writing a policy

### 5.1 Lines

One item per line. `#` starts a comment, to the end of the line; blank
lines are ignored.

```text
acl <list> <seq> permit|deny ...        one rule (§5.2)
bind <interface> in <list>              enforce a list on an interface (§5.7)
set drop-ipv4-fragments 0|1             1 drops every IPv4 fragment; default 0
```

`acl` rules:

```text
acl <1-99>    <seq> permit|deny <source>
acl <100-199> <seq> permit|deny <protocol> <source> [<port>] <destination> [<port>] [established]
```

The order of lines in the file doesn't matter: rules are sorted by list and
sequence number. `mfw show` prints the running policy in that sorted,
normalized form, without comments.

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
connections. It must be the last word of the rule.

It is a stateless approximation: a forged packet with ACK set will also
pass. The receiving kernel rejects such packets for unknown connections,
but they do reach it.

### 5.6 Sequence numbers

Every rule has a sequence number, 1–65535, unique within its list. It
decides the rule's position. Leave gaps (10, 20, 30, …) so a rule can be
inserted later:

```text
acl 100 5 deny tcp 198.51.100.0 0.0.0.255 any eq 22
acl 100 10 permit tcp any any eq 22
```

### 5.7 Binding

```text
bind eth0 in 10       # eth0's standard list
bind eth0 in 100      # eth0's extended list
bind eth1 in 110      # eth1 gets its own
```

- The list number decides which slot: 1–99 standard, 100–199 extended.
  A second list of the same kind on one interface is an error.
- Binding a list with no rules is allowed. A bound **extended** list with
  no rules **drops all IPv4** on that interface; a bound standard list with
  no rules does nothing.
- Only `in` exists: `bind eth0 out 100` is rejected, because outbound
  traffic is never filtered.
- An interface that doesn't exist is accepted and reported as missing
  (§8.2). It is attached the next time a policy is applied while it exists.
- Traffic for a VLAN subinterface arrives on its parent first, so the
  parent's lists apply to it.

### 5.8 Limits

| | Maximum |
|-|---------|
| Rules in a bound standard list | 64 |
| Rules in a bound extended list | 128 |
| Rules across all lists (bound or not) | 4096 |
| Interfaces with lists bound | 64 |
| Size of a policy | 1 MiB |

A policy that exceeds a limit is refused and changes nothing.

---

## 6. Recipes

Each recipe shows lines to add to the policy file. They assume
`bind eth0 in 100` (and `bind eth0 in 10` for standard lists).

### 6.1 Baseline for a VM that needs the internet

Start every extended list with these, then add your services:

```text
acl 100 10 permit tcp any any established
acl 100 20 permit udp any eq 53 any
acl 100 30 permit udp any eq 123 any
acl 100 40 permit udp any eq 67 any eq 68
acl 100 50 permit icmp any any
```

Drop the DHCP line if the VM has a static address. Drop the NTP line if it
doesn't sync time over the network.

### 6.2 SSH only from an admin network

```text
acl 100 100 permit tcp 192.0.2.0 0.0.0.255 any eq 22
```

Anything else to port 22 hits the implicit deny.

### 6.3 Public web server

```text
acl 100 110 permit tcp any any eq 80
acl 100 120 permit tcp any any eq 443
```

### 6.4 Block a host or network completely

Use the standard list. It drops the traffic before any other check:

```text
acl 10 10 deny host 203.0.113.66
acl 10 20 deny 198.51.100.0/24
bind eth0 in 10
```

A standard list alone (no extended list bound) is a pure blacklist:
everything not denied gets in.

### 6.5 Block one service from one network, allow it for others

Put the deny before the permit:

```text
acl 100 5 deny tcp 198.51.100.0 0.0.0.255 any eq 22
acl 100 10 permit tcp any any eq 22
```

### 6.6 Allow a port range (passive FTP, game servers)

```text
acl 100 130 permit tcp any any range 50000 50100
```

### 6.7 Large UDP messages (fragments)

Only the first fragment of a large UDP datagram carries ports, so only
the first fragment is checked against your extended rules. The later
fragments are checked against the standard list (source address) only,
then go to the kernel, which can reassemble the datagram only if the
first fragment got in. So a rule like
`permit udp any any eq 4789` accepts the whole datagram.

TCP fragments at offset 1 are always dropped and counted as
`tcp_frag_off1`. Real TCP stacks never send them; they are an attack
(RFC 1858).

To refuse fragmented traffic altogether:

```text
set drop-ipv4-fragments 1
```

### 6.8 Different lists on two interfaces

```text
acl 100 10 permit tcp any any eq 22            # management side: SSH only
acl 110 10 permit tcp any any eq 443           # public side: HTTPS only
acl 110 20 permit tcp any any established
bind eth0 in 100
bind eth1 in 110
```

---

## 7. Applying policy safely

**Applying an extended list can lock you out of a remote VM.** If the list
doesn't permit your SSH session, your connection freezes the moment the
policy is applied.

Before applying, check that the policy contains:

1. a rule permitting your SSH traffic, for example `permit tcp any any eq 22`, and
2. `permit tcp any any established` if you want outbound connections to work.

An already-open SSH session survives if the list has the `established`
rule, because every packet after the first carries ACK. **New** logins still
need the port-22 rule. Test with a second login, not your current session.

When working remotely, use a dead-man switch: apply the new policy, then
automatically go back to the old one after a few minutes unless you cancel.
Run this in a root shell (`sudo -i`), so the background job can be
cancelled:

```bash
# 0. Keep the running policy
mfw show > /root/mfw.good

# 1. Arm: go back to it in 3 minutes
(sleep 180; mfw apply /root/mfw.good) &
DEADMAN=$!

# 2. Apply
mfw apply /usr/local/seawall/etc/mfw/policy

# 3. Open a NEW SSH session from your workstation. If it works, return to
#    this shell and disarm:
kill $DEADMAN
```

If the new session fails, wait three minutes for the old policy to come
back, then fix the file.

If you are locked out, use the VM console (hypervisor or cloud serial
console) and run `mfw apply /dev/null`, which unbinds everything and
detaches every interface, or `mfwd -P` (§11). A reboot also clears the
policy (§10).

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
tcp_frag_off1      0
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
| `tcp_frag_off1` | dropped TCP fragments at offset 1 (an attack, RFC 1858) |

The counters cover all interfaces together. `xdp_pass + xdp_drop` is the
total packet count. Counters are cumulative and are only reset by
`mfwd -P`, or by an upgrade to a version with new counters. To measure a period, take two readings and subtract.

**Rising `ext_implicit_deny` right after a change** usually means a missing
reply rule (§3.4).

### 8.2 Seeing the current policy

```bash
sudo mfw show      # the running policy, sorted and normalized
sudo mfw status
```

```text
generation           4
attached             eth0,eth1
missing              eth2
drop-ipv4-fragments  0
```

- **generation** counts applied policies ("none" before the first since
  boot).
- **attached**: the interfaces mini-fw runs on.
- **missing**: interfaces the policy binds lists to that don't exist. Apply
  the policy again once they do.

---

## 9. Command reference

### 9.1 `mfw`

```text
mfw [-s socket] <command>
```

| Command | What it does |
|---------|--------------|
| `mfw apply [file]` | Replace the whole policy with the file (stdin if no file or `-`). Attaches and detaches interfaces to match. |
| `mfw check [file]` | Check a policy without sending it. Uses the same rules as mfwd and needs no access to mfwd. |
| `mfw show` | Print the running policy. |
| `mfw status` | Generation, attached and missing interfaces, fragment setting. |
| `mfw stats [--json]` | Print counters. |
| `mfw ping` | Check that mfwd answers. |
| `mfw version` | Print version. |
| `mfw help` | Print usage. |

The socket is `-s`, else `$MFW_SOCKET`, else `/run/mfwd.sock`.

Exit status: **0** success, **1** refused by mfwd (an invalid policy, a
kernel error), **2** usage, file or connection error.

### 9.2 `mfwd`

```text
mfwd [-s socket] [-m mode] [-g group] [-p pinroot] [-d statedir] [-x auto|native|generic]
mfwd -P [-p pinroot] [-d statedir]
```

| Option | Default | Meaning |
|--------|---------|---------|
| `-s socket` | `/run/mfwd.sock` | where to listen |
| `-m mode` | `0600` | socket permissions |
| `-g group` | | socket group; with `-m 0660`, that group may use `mfw` without root |
| `-p pinroot` | `/sys/fs/bpf/mfw` | bpffs directory for maps and links |
| `-d statedir` | `/run/mfwd` | where the running policy is saved |
| `-P` | | detach every interface, remove all pins and the saved policy, then exit |
| `-V` | | print the version |

mfwd logs to stderr, which systemd sends to the journal
(`journalctl -u mfwd`). Every applied or refused policy is logged with the
caller's uid.

---

## 10. Persistence across reboots

The kernel side and the saved policy live in memory (`/sys/fs/bpf`,
`/run`), so a reboot clears them: **the VM boots unprotected until a
policy is applied.** Restarting mfwd, on the other hand, keeps the policy.

On a system with sw_configd, sw_configd applies its configuration when it
starts. Standalone, apply your policy file whenever mfwd starts, with a
drop-in:

```bash
sudo systemctl edit mfwd
```

```ini
[Service]
ExecStartPost=/usr/local/seawall/bin/mfw apply /usr/local/seawall/etc/mfw/policy
```

The interfaces must exist when this runs. An interface that appears later
is reported as missing until the policy is applied again.

---

## 11. Removing mini-fw

```bash
sudo systemctl disable --now mfwd
sudo mfwd -P                         # detaches every interface, removes all state
sudo make uninstall                  # in the source tree, with the same PREFIX
```

Stopping mfwd alone does **not** stop the filtering.

If the `mfwd` binary is gone but the firewall is still active:

```bash
sudo rm -r /sys/fs/bpf/mfw               # detaches the program and removes all state
```

---

## 12. Troubleshooting

| Symptom | Likely cause | Fix |
|---------|--------------|-----|
| `mfw: cannot reach mfwd: No such file or directory` | mfwd not running | `sudo systemctl start mfwd`; `journalctl -u mfwd` |
| `mfw: cannot reach mfwd: Permission denied` | no access to the socket | use `sudo`, or start mfwd with `-g <group> -m 0660` |
| `… is not on bpffs` (mfwd log) | bpffs missing | `sudo mount -t bpf bpf /sys/fs/bpf` |
| `load BPF object: …` (mfwd log) | kernel too old (< 6.1), no BTF, or missing capabilities | check §1.2; run mfwd with `MFW_DEBUG=1` to see the verifier log |
| `eth0: attach TC ingress: …` | missing capabilities | check §1.2 |
| `pinned maps under … have ABI N, expected 2` | state left by a different mini-fw version | `sudo mfwd -P`, then start mfwd again |
| `line N: …` | the policy has an error on that line | fix it; `mfw check` finds it without sending |
| an interface listed as `missing` | it doesn't exist (yet) | apply the policy again once it does |
| DNS, updates or web browsing stopped working | extended list lacks reply rules | add the §6.1 baseline |
| VM lost its IP address after some hours | DHCP renewal replies blocked | `permit udp any eq 67 any eq 68` |
| A service is unreachable | no permit rule, or a deny rule above it | `mfw show`; watch `ext_implicit_deny` / `ext_deny` while testing |
| Everything blocked | a bound extended list is empty or lacks your rules | fix the file, or `mfw apply /dev/null` |
| Large UDP transfers fail | `drop-ipv4-fragments 1`, or the first fragment is not permitted | §6.7 |
| IPv6 traffic not filtered | by design: only IPv4 is filtered | disable IPv6 or use ip6tables/nftables for it |
| `list 100 already has sequence N` | duplicate sequence number | renumber one of the rules |
| `non-contiguous wildcard` | wildcard like `0.0.2.255` | use a contiguous wildcard or CIDR |
| `'10.0.0.1' needs a wildcard` | extended lists need `host` or a wildcard | write `host 10.0.0.1` |

Useful low-level checks:

```bash
sudo bpftool net show dev eth0                      # "tcx/ingress mfw_tc" when attached ("clsact/ingress" before 6.6)
sudo bpftool prog show name mfw_tc
sudo bpftool map dump pinned /sys/fs/bpf/mfw/maps/rulesets   # ifindex → inner map id
sudo bpftool map dump id <inner map id>                       # that interface's ruleset
```

---

## 13. FAQ

**Does mini-fw replace iptables or nftables?**
No. They can run side by side. mini-fw decides first (at TC ingress);
packets it accepts then go through netfilter as usual. An XDP program,
such as voidGate's, runs before mini-fw.

**Can I filter outgoing traffic?**
No. mini-fw only filters inbound traffic.

**Can I use different lists on different interfaces?**
Yes. Give each interface its own `bind` lines (§6.8). A packet is checked
against the lists of the interface it arrived on.

**Why a whole policy file instead of one command per rule?**
So that every change is checked as a whole before anything happens, and
each interface switches to its new rules in one step. It also lets front
ends such as sw_configd keep the configuration and simply send all of it.

**Is there a default-deny without writing rules?**
Bind an extended list with no rules: `bind eth0 in 100` and no `acl 100`
lines. It drops all inbound IPv4. Only do this from the console.

**Does a standard `permit` override the extended list?**
No. A standard `permit` only stops the standard check; the extended list
still decides.

**Are policy changes applied instantly?**
Yes. Each interface switches atomically: every packet is judged either by
the old rules or by the new ones.

**What happens when mfwd stops or crashes?**
Filtering goes on with the last policy. A restarted mfwd picks up the
saved policy and serves `show` and `status` as before.

**Does mini-fw protect against SYN floods?**
It drops SYNs to ports you haven't permitted. For permitted ports, the
kernel's own SYN cookies (`net.ipv4.tcp_syncookies = 1`, the default)
protect the listening service.
