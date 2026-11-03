# mini-fw: Userspace eBPF/XDP Explained

English | [中文](userspace-ebpf.zh-CN.md)

mini-fw's userspace does one thing: it puts the BPF programs and maps into the kernel, and pins them so they keep working after mfwd exits. This document walks through that mechanism by the lifetime of each kernel object.

Scope: commit `6112f9b`. The files involved are `src/dataplane.c`, `src/dp_xdp.c`, `src/dp_tc.c`, `src/mfwd.c` and `src/bpf/mfw.bpf.c`; the libxdp parts were checked against xdp-tools `7873be4`. The internals of sw_flowd, libpkt and libsw were not checked, and are marked where they come up. The overall design and implementation are in [implementation.md](implementation.md).

## 1. The big picture: the pin tree, and what keeps what alive

A kernel object lives as long as something references it: an fd, a pin, a link, a qdisc or a dispatcher. The mfwd process itself holds nothing, so filtering goes on after it exits.

```
/sys/fs/bpf/seawall/mfw/
├── maps/                       ← pinned automatically (LIBBPF_PIN_BY_NAME)
│   ├── rulesets   HASH_OF_MAPS: ifindex → inner ARRAY[1]{mfw_ruleset}
│   ├── config     ARRAY[1]{mfw_config}
│   └── stats      PERCPU_ARRAY[MFW_STAT_MAX]
└── attach/                     ← mini-fw's own record of what it owns
    ├── xdp_eth0   prog pin (marks which dispatcher component is ours)
    ├── tcx_eth1   link pin (holds the attachment: unlink detaches)
    └── tc_eth2    prog pin (a marker only; the cls_bpf filter lives in the qdisc)

/sys/fs/bpf/xdp/dispatch-<ifindex>-<id>/   ← libxdp's own pins, which hold the XDP components
/sys/fs/bpf/seawall/flows/outbound         ← sw_flowd's table (read-only to mini-fw)
```

In each of the three ways of attaching, something different keeps the program attached:

| Attached with | What holds the program | What the `attach/` pin does | How it is removed |
| --- | --- | --- | --- |
| XDP (libxdp) | The dispatcher and its pins | Records the component's prog id | `xdp_program__detach()`; libxdp rebuilds the dispatcher |
| tcx | A bpf_link, held by the pin | It is the holder | `unlink(pin)`; the link detaches when its last reference goes |
| Classic TC | The cls_bpf filter in the clsact qdisc | A marker only | `bpf_tc_detach()`, then unlink the marker |

That is why `detach_pinned()` (`dataplane.c:587`) skips tcx: deleting the pin is enough. The other two must be removed explicitly; unlinking alone would leave the program running as an orphan that mfwd no longer tracks.

**Why `attach/xdp_<if>` is a pin.** It lets userspace find "which component on this interface is ours" again, and the answer is that prog id (`mfw_xdp_pinned_id()`, `dp_xdp.c:147`). A pin, rather than an ordinary file, also:

- outlives an mfwd restart, since mfwd keeps no state of its own;
- holds a reference to the program, so while the pin exists its id can't be given to another program;
- carries the interface name in the file name, so listing `attach/` tells which interfaces are attached and how (`mfw_dp_list_attached()`, purge);
- keeps all state under `/sys/fs/bpf/seawall/mfw/`, so `mfwd -P` cleans up by directory.

The cost: if someone else takes the component out of the dispatcher, the pin keeps the program object in memory until `mfw_xdp_attached()` notices the pin is stale and unlinks it.

## 2. Build time: the skeleton

The BPF object is embedded whole in the mfwd binary, so nothing has to find a `.o` file on disk at run time.

```
mfw.bpf.c --clang -target bpf--> build/mfw.bpf.o --bpftool gen skeleton--> src/mfw.skel.h
```

`mfw.skel.h` holds the whole ELF as a byte array and generates typed accessors: `skel->maps.rulesets`, `skel->progs.mfw_tc`, and `mfw_bpf__open_opts()`, `__load()`, `__destroy()`. libxdp and libbpf are linked into mfwd statically, so the machine needs neither; libelf and zlib, which they need, stay shared.

A skeleton can be opened many times, each time as an independent `bpf_object`. mini-fw relies on that to load one copy of the program per XDP interface (section 5).

## 3. `mfw_dp_open()`: open → bind → load

`mfw_dp_open()` (`dataplane.c:207`) loads only the TC entry, and creates and pins all the shared maps. It attaches nothing.

```c
LIBBPF_OPTS(bpf_object_open_opts, opts, .pin_root_path = maps);
skel = mfw_bpf__open_opts(&opts);                       // parse ELF/BTF; nothing in the kernel yet
bpf_map__reuse_fd(skel->maps.flows, flows_fd);          // use sw_flowd's map instead
bpf_program__set_autoload(skel->progs.mfw_xdp, false);  // load the TC entry only
mfw_bpf__load(skel);                                    // create/reuse maps → relocate → verifier
```

**`pin_root_path` and `LIBBPF_PIN_BY_NAME`.** At load, libbpf checks for each map with a pinning attribute whether `<root>/<name>` exists. If it does, libbpf opens it with `bpf_obj_get()`, checks it is compatible (type, key/value size, max_entries, flags) and reuses it; if not, it creates the map and pins it. mfwd purges at start, so the first load always creates; every per-interface XDP copy loaded after that reuses these pins, so all program instances share one state.

**`flows` is deliberately not pinned.** It binds someone else's map. `bpf_map__reuse_fd()` must be called before load (`dataplane.c:247`): it dups the fd and replaces the ELF's definition with that map's info. The `max_entries 1` in the source is only a placeholder: with sw_flowd it is replaced; without it, each program instance gets an empty LRU map of its own, and `reply` never matches, failing closed.

**`set_autoload(false)`.** One ELF has two entries. mfwd loads the TC entry itself; the XDP entry must go through libxdp, which loads it as freplace (section 5). So each side turns off the other's entry.

**The two entries are two separate kernel objects.** `mfw.bpf.c` has `SEC("xdp.frags") mfw_xdp` (:496) and `SEC("tcx/ingress") mfw_tc` (:519). Opening the ELF, libbpf makes one `bpf_program` per entry; at load each entry is its own `BPF_PROG_LOAD`, giving its own `struct bpf_prog` in the kernel, with its own prog id and program type.

| Entry | Loaded where | Program type in the kernel | Copies |
| --- | --- | --- | --- |
| `mfw_tc` | `mfw_dp_open()`: `dataplane.c:259` turns off the XDP entry, :262 loads, :269 takes the fd | `BPF_PROG_TYPE_SCHED_CLS` | One, shared by every interface at TC |
| `mfw_xdp` | `xdp_load()`: `dp_xdp.c:254` turns off the TC entry, :264 hands it to libxdp | XDP in the source; libxdp changes it to `BPF_PROG_TYPE_EXT` before loading (`xdp_multiprog__link_prog()`) | One per XDP interface |

**Maps are shared, code is not.** Before each load, libbpf opens the same pinned maps through `pin_root_path`, and `flows` is bound to the same sw_flowd table (`dataplane.c:247`, `dp_xdp.c:256`). The kernel records the map pointers in each program's `used_maps`, each holding a reference, so every entry reads and writes the same maps. Code, on the other hand, is per program, each with its own instructions and JIT image: `mfw_judge()` is `__always_inline` (:390) and is expanded into both entries; `mfw_ext_ace_match()` is a global function (:264), but libbpf still appends it to each program that calls it.

Measured with `bpftool prog show`:

```
74249: ext  name mfw_xdp  tag 1984d724104a1ac0  gpl
	xlated 3752B  jited 2279B  memlock 4096B  map_ids 47163,47162,47161,14572
	btf_id 50740
```

`mfw_tc` shows the same `map_ids`. 14572 is sw_flowd's table, the same across mfwd restarts; the other three are rulesets, config and stats, made anew at every mfwd start.

**The verifier and the global function.** `mfw_ext_ace_match()` is a non-static `__noinline` function. The verifier checks a global function once within a program, by its BTF signature; at a call site it only checks the argument types and treats the return value as an unknown integer. Inlined into the 128-iteration loop, it would be explored again on every iteration, since the verifier walks a bounded loop iteration by iteration, and the states it leaves would compound across iterations; mini-fw's early version exceeded the 1M-instruction limit that way ([implementation.md](implementation.md) §3.4). Now the whole program verifies in about 16K instructions. The costs: global functions with pointer arguments need kernel 5.12+, the function must NULL-check its arguments (`mfw.bpf.c:266`), and every ACE checked is a real function call. The verifier runs only at load; the data path pays nothing for it.

Finally, `mfw_dp_open()` takes the fds, probes for tcx with `sw_bpf_have_tcx()`, and writes config's initial value with `init_config()`.

## 4. Map-in-map: swapping a ruleset atomically

Each interface's ruleset is in an inner map of its own. Changing the rules swaps one pointer, so every packet sees either the whole old ruleset or the whole new one.

An `mfw_ruleset` is about 6.8KB (8 + 192×36 bytes). Overwritten in place with `bpf_map_update_elem`, the kernel's copy isn't atomic, and a packet in flight could read half old and half new rules.

Userspace splits the work in two: `mfw_dp_ruleset_new()` (`dataplane.c:389`) creates and fills an inner map, and `mfw_dp_ruleset_swap()` (:414) swaps it into the outer map. `install()` in `mfwd.c` (:262) first makes an inner map for every interface, and only when all succeed writes config, swaps them in one by one, and finally closes them all:

```c
// mfw_dp_ruleset_new(): create, fill, return the fd; install() calls it for every interface first
fd = bpf_map_create(BPF_MAP_TYPE_ARRAY, "mfw_ruleset", 4, sizeof(*rs), 1, NULL);
bpf_map_update_elem(fd, &zero, rs, BPF_ANY);                      // 1. fill the new inner map

// once all are made
mfw_dp_set_config(dp, drop_ipv4_fragments, gen);                  // 2. then write config
bpf_map_update_elem(dp->rulesets_fd, &ifindex, &fd[i], BPF_ANY);  // 3. mfw_dp_ruleset_swap(): one pointer swap
mfw_dp_ruleset_prune(dp, keep, n_keep);                           // 4. remove entries no longer needed
close(fd[i]);                                                     // 5. the outer map holds the reference
```

If making an inner map fails (on memlock or ENOMEM, say), config and every interface's rules are still untouched, the old policy runs on, and `apply()` detaches the interfaces `attach_bound()` just attached. Only a failed swap leaves a mix of old and new, and an update with a map already made hardly ever fails.

**`bpf_map_create()` always creates a new map.** It never looks one up; the fd it returns is the new map's only handle. The name `"mfw_ruleset"` is just a label for `bpftool map show`: every inner map has it, the kernel doesn't require it to be unique, and there is no way to look a map up by name. Which inner map belongs to which interface is decided in step 3, by the outer map's key, the ifindex. An array's elements are allocated and zeroed at creation, so the order fill-then-swap matters: swapped in first, the program would read an all-zero ruleset, both lists unbound, and the interface would pass everything meanwhile.

On the BPF side, `ruleset_of()` (`mfw.bpf.c:368`):

```c
inner = bpf_map_lookup_elem(&rulesets, &ifindex);   // the inner map's pointer
return bpf_map_lookup_elem(inner, &zero);           // then the value
```

**The inner map template.** `struct ruleset_map` (`mfw.bpf.c:99-104`) is the inner map's template. Creating the outer map, libbpf first makes a temporary inner map from it as a sample, and the kernel copies the sample's metadata into the outer map. Every inner map put in later is compared with it on type, key_size, value_size and flags, and for an array on max_entries too (`BPF_F_INNER_MAP` isn't set); a mismatch is EINVAL. Both sides use `struct mfw_ruleset` from `include/mfw.h`, so the sizes agree. The template is written when the outer map is created; mfwd recreates every map at start, so changing `mfw_ruleset`'s size can't clash with an old outer map. Names aren't compared.

**Why it is atomic.** Updating the outer map replaces one pointer. A program running holds the old inner map's pointer inside an RCU read-side section and can finish reading safely; the old map is freed only after a grace period. New packets see the new pointer. The kernel keeps the old pointer in the old hash element, already unlinked; after the grace period it frees the element and puts the old inner map (`bpf_map_put()`). The outer map is its only reference, so the old inner map is freed with it.

**The cost.** Every update or delete on a `HASH_OF_MAPS` calls `synchronize_rcu()` in the syscall, so that on return no program is still using the old inner map. Only mfwd's syscall pays: the calling thread sleeps in the kernel until the grace period ends, using no CPU and causing no extra grace period. The data path is unaffected, since BPF programs are RCU readers and never wait. A grace period is usually a few to a few tens of milliseconds, so an apply takes about (swaps + deletes) grace periods. mfwd is single-threaded and serves no other request meanwhile. Today every APPLY still reinstalls every bound interface, including those whose rules didn't change.

**`mfw_dp_ruleset_prune()`** (`dataplane.c:428`) deletes outer-map entries (ifindex → inner map pointer) not in the keep list, and their inner maps are freed with them. Reinstalling the bound interfaces isn't enough: an interface no longer bound has no new ruleset to swap in, so its entry would keep the old rules; and an interface deleted, re-created or renamed is invisible to `detach_unbound()`, which works by name. Prune reconciles by ifindex, so the outer map matches the new policy. While walking, a successful delete leaves the cursor at the last key kept, and only a kept key moves it on, so each key is visited once, and a delete that fails can't loop forever. Deleting while walking is safe because mfwd is the outer map's only writer.

## 5. XDP: libxdp's dispatcher

libxdp's dispatcher lets mini-fw share an interface's XDP hook with voidgate, after it. mini-fw loads a copy of its program for each interface.

**The problem.** An interface's XDP hook holds one program. mini-fw has to coexist with voidgate (the DDoS gate), and voidgate must run first (Seawall proposal 0004).

**libxdp's answer.** A dispatcher XDP program with a number of empty `__noinline` stub slots:

```
dispatcher(ctx):
    ret = slot0(ctx)   ← voidgate (priority 10)   freplace
    if !(chain_call_actions[0] & (1<<ret)) return ret
    ret = slot1(ctx)   ← mfw_xdp  (priority 20)   freplace
    if !(chain_call_actions[1] & (1<<ret)) return ret
    ...
    return XDP_PASS
```

Each component is loaded as `BPF_PROG_TYPE_EXT` (freplace) and replaces one slot function. Its order, and which return values go on, it declares itself in a special ELF section:

```c
struct { __uint(priority, 20); __uint(XDP_PASS, 1); } XDP_RUN_CONFIG(mfw_xdp);
// priority 20 (after voidgate's 10); only XDP_PASS goes on to the next component
```

**Priority only orders: it is not a slot, and equal priorities don't conflict.** On every rebuild libxdp sorts the components with `cmp_xdp_programs()` (xdp-tools `lib/libxdp/libxdp.c:1535-1575`) and fills the slots in that order: lowest priority first; then by program name; then by load state, size, tag and load time. A program without `XDP_RUN_CONFIG` gets priority 50 (`headers/xdp/xdp_helpers.h:9`). What does need care is what the order implies, and the dispatcher's limits:

- **The order decides who sees a packet.** The chain stops when a component returns an action not in its `chain_call_actions`; by default only `XDP_PASS` goes on (`xdp_helpers.h:10`). A program with a priority below 20 runs ahead of mini-fw and could bypass the firewall;
- **A dispatcher holds at most 10 components** (`MAX_DISPATCHER_ACTIONS`, `headers/xdp/prog_dispatcher.h:21`);
- **Frags support is set by the weakest component.** If any component lacks it, the whole dispatcher is loaded without it (`libxdp.c:3175-3188`), and an interface with a jumbo MTU refuses it.

Seawall proposal 0013 allocates the components' priorities.

**How freplace binds its target.** In two steps. Loading needs a target (`bpf_program__set_attach_target(prog, dispatcher_fd, "prog0")`): the verifier checks the program against that function's BTF signature, so a dispatcher must exist before the first load. Attaching creates a link with `bpf_link_create(prog_fd, target_fd, 0, {.target_btf_id})`; since kernel 5.10, `target_fd` may be another dispatcher whose function has a compatible signature. libxdp itself relies on that (`xdp_multiprog__link_prog()`): whenever a component joins or leaves, it makes a new dispatcher and links the existing components to it again. So the kernel doesn't prevent one `mfw_xdp` from being linked into several interfaces' dispatchers at once.

**Why mini-fw still loads one copy per interface (`xdp_load()`, `dp_xdp.c:237`).** It is mini-fw's own choice, so that each interface's attachment is independent in identity and lifetime:

- one prog id per interface: the id in `attach/xdp_eth0` belongs to eth0 alone, and `mfw_xdp_attached()`, `mfw_xdp_unload()` and purge all work by "interface → id";
- no dependence on the first interface: shared, the program's load target would be the first interface's dispatcher, which gets complicated once that interface is deleted;
- mfwd holds no shared XDP program object for long: each attach opens, loads, attaches, pins and destroys in one go.

The cost is small: the maps are shared through `pin_root_path`, so only the program itself is extra; each copy goes through the verifier once, only at attach. For each interface:

```c
skel = mfw_bpf__open_opts(&oopts);                   // a new bpf_object, pin_root_path at maps/
bpf_program__set_autoload(skel->progs.mfw_tc, false);
bpf_map__reuse_fd(skel->maps.flows, flows_fd);
xopts.obj = skel->obj;
xp = xdp_program__create(&xopts);                    // libxdp takes over the load (as EXT)
xdp_program__set_xdp_frags_support(xp, true);
xdp_program__attach(xp, ifindex, mode, 0);           // join the dispatcher, or make one
bpf_obj_pin(xdp_program__fd(xp), "attach/xdp_<if>"); // our own marker
xdp_program__close(xp); mfw_bpf__destroy(skel);      // close the fds; the kernel's references stay
```

Inside the attach: libxdp reads the current dispatcher's components, adds the new one, sorts by priority, makes a new dispatcher, and replaces the whole hook atomically, so existing components never drop out for a moment. The new dispatcher references the component, and libxdp pins them under `/sys/fs/bpf/xdp/`, so the program lives on after mfwd closes every fd.

**Programs attach per interface, not per RX queue.** Each RX queue calls the same program on its own CPU, so one `mfw_xdp` can run on several CPUs at once. That is why `stats` is a per-CPU map (section 8); `rulesets` and `config` are read-only on the data path, so concurrent reads are fine.

**Reading the hook's state (`mfw_xdp_state()`, `dp_xdp.c:53`).** ENOENT from `xdp_multiprog__get_from_ifindex()` means the hook is free. `is_legacy` with a main program means someone else holds the hook alone: mini-fw never replaces it and falls back to TC, degraded. Otherwise there is a dispatcher, which mini-fw joins in its mode.

**Native and skb mode.** A new dispatcher is tried in native mode (in the driver, fastest) first; if the driver refuses, mfwd logs a warning with the native-mode errno (`dp_xdp.c:362`) and falls back to skb mode, generic XDP, which runs in `netif_receive_skb` after the skb is allocated and costs about as much as TC. ENA, common on AWS, refuses native mode with an MTU over 3498.

**Frags.** `SEC("xdp.frags")` gives the program `BPF_F_XDP_HAS_FRAGS`, but the dispatcher itself must support frags too, or an interface with a jumbo MTU refuses it, so `dp_xdp.c:277` tells libxdp as well. mini-fw reads headers only from the first buffer, so multi-buffer packets are unaffected.

**Recognizing our component.** `mfw_xdp_pinned_id()` reads the prog id from the pin, and `mfw_xdp_attached()` (`dp_xdp.c:177`) compares it with each component in the dispatcher; it is the component's (EXT program's) id, not the dispatcher's. When the interface was deleted and re-created, or the component was removed by someone else, the pin is stale and is deleted. `mfw_xdp_unload(ifindex, 0)` (`dp_xdp.c:348`) removes, by the name `mfw_xdp`, copies left by a crash that no pin points to.

**Removal.** `xdp_program__detach()` takes the component out: libxdp makes a new dispatcher without it and swaps it in atomically.

## 6. Falling back to TC: tcx and classic cls_bpf

When another program holds the XDP hook alone, mini-fw falls back to TC ingress: a tcx link on 6.6 and later, a cls_bpf filter on the clsact qdisc before (6.1 is the floor kept for Amazon Linux 2023).

**tcx (6.6+)** attaches at TC with a bpf_link (`mfw_tcx_attach()`, `dp_tc.c:199`):

```c
fd = bpf_link_create(prog_fd, ifindex, BPF_TCX_INGRESS, NULL);  // appended at the end by default
bpf_obj_pin(fd, "attach/tcx_<if>");  close(fd);                 // the pin is the only reference
```

A link's semantics are clean: it detaches when its last reference goes, so even a crash leaves no orphan. On return values, `TC_ACT_UNSPEC` (-1) equals `TCX_NEXT`, handing the packet to the next program, and `TC_ACT_SHOT` equals `TCX_DROP` (`mfw.bpf.c:558-561`). The tcx constants needed to build with 6.1's UAPI headers, and reading the ifindex from a link (`sw_bpf_tcx_ifindex()`), now come from libsw's `<sw/bpf.h>` (commit `ff3d37e`). Whether mfwd uses tcx is decided at run time, by `sw_bpf_have_tcx()` probing the kernel, so an mfwd built with 6.1's headers still uses tcx on a 6.6+ kernel.

**Classic TC (before 6.6):**

```c
bpf_tc_hook_create(&hook);     // make the clsact qdisc (EEXIST if there is one)
bpf_tc_attach(&hook, &opts);   // cls_bpf filter, direct-action, handle 0x4d46, prio 0xc000, REPLACE
```

The filter is an object in the qdisc, tied to no fd, so the pin only marks that mfwd put it there. `BPF_TC_F_REPLACE` makes a repeated attach replace the filter in one netlink request, with no gap. Detaching removes only the filter and leaves clsact, which others may use.

**`bpf_skb_pull_data` at the TC entry (`mfw.bpf.c:549`).** A TC program can read only the skb's linear part directly, and after GRO the headers may be in frags. The code parses what is there first, and pulls only on `PKT_SHORT` when the linear part really is shorter than `PKT_HDR_MAX`: a pull makes the skb writable, which copies the head of a cloned skb. After a pull, the `data`/`data_end` pointers are invalid and must be read again, as the verifier enforces.

Every interface at TC shares the one program instance `mfw_dp_open()` loaded; one program can be referenced by several tcx links or filters at once.

## 7. Lifetime

Every mfwd start purges and rebuilds, and an exit removes nothing; only `mfwd -P` removes mini-fw.

```
mfwd starts
  sw_sock_listen()            ← take the socket first: a second mfwd can't touch the pins
  mfw_dp_purge()              ← detach by the attach/ pins, then unpin attach/ and maps/
                                (an interface that can't be looked up → stop, keep the pins)
  mfw_dp_open()               ← load the TC entry; the maps are made anew and pinned
  restore()                   ← apply /run/mfwd/policy again
                                  └ attach (one XDP copy per interface, or tcx/tc)
                                  └ install (make inner maps → swap)
  sw_notify_ready()
  accept loop...
mfwd exits
  mfw_bpf__destroy()          ← closes fds only; pins, links, dispatchers, qdiscs stay → filtering goes on
mfwd -P
  purge + remove the saved policy   ← removed completely
```

Between purge and the end of restore every interface passes everything (fail-open), by design: there is no live update. If restore fails (`restore()`, `mfwd.c:730`), mfwd logs an error saying every interface passes everything, but still serves and tells systemd it is ready, so a front end such as sw_configd can apply a policy again.

**Privileges.** `mfwd.service` runs as root with `CapabilityBoundingSet` CAP_BPF, CAP_NET_ADMIN, CAP_SYS_ADMIN, CAP_PERFMON and CAP_CHOWN. CAP_SYS_ADMIN has to stay: commands such as `BPF_PROG_GET_FD_BY_ID` still require it, and libxdp opens the dispatcher and its components by id. With CAP_SYS_ADMIN the perfmon check passes too, so dropping CAP_PERFMON would gain nothing. Two of the unit's other sandboxing settings concern BPF: `SystemCallFilter=@system-service` additionally allows `bpf`; and `ProtectKernelTunables=` is left out on purpose, since it mounts all of `/sys` read-only, `ReadWritePaths=` can't make `/sys/fs/bpf` writable again, and mfwd and libxdp both pin there.

## 8. Counters: reading a per-CPU map

The counters are a `PERCPU_ARRAY` (`mfw.bpf.c:125`): the BPF side increments them without locks, and userspace reads each CPU's value and adds them up.

On the BPF side each CPU writes only its own slot (`v->count++` in `stat_inc()`, `mfw.bpf.c:166`). XDP and TC programs running on one CPU aren't interrupted by another writer of the same map, so no atomic operation is needed, and no cache line bounces between CPUs. A userspace lookup in a per-CPU map returns an array of `libbpf_num_possible_cpus()` values, which it sums itself (`mfw_dp_stats()`, `dataplane.c:523`). It must be the possible CPU count, not the online one, or the buffer is too small.

## 9. Commands for the field

These commands show the actual state of each layer above.

```bash
xdp-loader status eth0                                   # dispatcher components, priorities, mode
bpftool net show dev eth0                                # XDP / tcx / tc at a glance
bpftool link show                                        # tcx links, and the components' freplace links
tc filter show dev eth0 ingress                          # classic cls_bpf (handle 0x4d46)
bpftool map dump pinned /sys/fs/bpf/seawall/mfw/maps/rulesets   # ifindex → inner map id
bpftool map dump id <inner_id>                           # an interface's current ruleset
bpftool -f prog show name mfw_xdp                        # each interface's copy; -f lists pin paths
sysctl -w kernel.bpf_stats_enabled=1                     # prog show then adds run_time_ns / run_cnt
SW_BPF_DEBUG=1 mfwd -v                                   # the verifier log
```

A few fields of `bpftool prog show`: `tag` is a hash of the instructions with map references blanked, the same for the same code; `xlated` is the size in bytes of the instructions after the verifier rewrote them (8 bytes each), `jited` the size of the JIT's machine code; `memlock` is the program header plus the xlated instructions rounded up to pages, without the JIT code or the maps; `btf_id` is the program's own BTF object, different for each copy. With `bpf_stats_enabled` on, `run_time_ns / run_cnt` is the average time per packet; the statistics cost something themselves, so turn them off after measuring.
