# mini-fw：用户态 eBPF/XDP 详解

[English](userspace-ebpf.md) | 中文

mini-fw 的用户态只做一件事：把 BPF 程序和 maps 放进内核，并用 pin 让它们在 mfwd 退出后继续工作。本文按内核对象的生命周期讲清楚这套机制。

范围：commit `6112f9b`。涉及的文件是 `src/dataplane.c`、`src/dp_xdp.c`、`src/dp_tc.c`、`src/mfwd.c` 和 `src/bpf/mfw.bpf.c`；libxdp 的部分对照的是 xdp-tools `7873be4`。sw_flowd、libpkt、libsw 的内部实现本文没有核对，涉及时会标明。设计和实现的总体说明见 [implementation.md](implementation.md)。

## 1. 全局图：pin 树与谁让谁活着

内核对象的生命周期由引用计数决定，引用者可以是 fd、pin、link、qdisc 或 dispatcher。mfwd 进程本身什么都不持有，所以它退出后过滤照常继续。

```
/sys/fs/bpf/seawall/mfw/
├── maps/                       ← LIBBPF_PIN_BY_NAME 自动 pin
│   ├── rulesets   HASH_OF_MAPS: ifindex → inner ARRAY[1]{mfw_ruleset}
│   ├── config     ARRAY[1]{mfw_config}
│   └── stats      PERCPU_ARRAY[MFW_STAT_MAX]
└── attach/                     ← mini-fw 自己的“所有权标记”
    ├── xdp_eth0   prog pin（标记：dispatcher 里哪个组件是我们的）
    ├── tcx_eth1   link pin（真正持有挂载：unlink 即 detach）
    └── tc_eth2    prog pin（仅标记；cls_bpf filter 活在 qdisc 里）

/sys/fs/bpf/xdp/dispatch-<ifindex>-<id>/   ← libxdp 自己的 pin，真正持有 XDP 组件
/sys/fs/bpf/seawall/flows/outbound         ← sw_flowd 的表（mini-fw 只读）
```

三种挂载方式里，真正让程序挂着的东西各不相同：

| 挂载方式 | 谁持有程序 | `attach/` 下 pin 的作用 | 如何拆除 |
| --- | --- | --- | --- |
| XDP（libxdp） | dispatcher 及其 pins | 记下组件的 prog id | `xdp_program__detach()`，libxdp 重建 dispatcher |
| tcx | bpf_link，由 pin 持有 | 就是持有者 | `unlink(pin)`，link 引用归零后自动 detach |
| classic TC | clsact qdisc 里的 cls_bpf filter | 仅作标记 | `bpf_tc_detach()`，再 unlink 标记 |

所以 `detach_pinned()`（`dataplane.c:587`）跳过 tcx：删 pin 就够了。另外两种必须显式拆除，否则 unlink 之后程序会作为孤儿继续运行，mfwd 也失去了对它的追踪。

**`attach/xdp_<if>` 为什么用 pin 来记。** 它的作用是让用户态找回"这块网卡上哪个组件是我们的"，答案就是那个 prog id（`mfw_xdp_pinned_id()`，`dp_xdp.c:147`）。用 pin 而不是普通文件来记，还有几个好处：

- mfwd 进程不保存状态，pin 能跨过 mfwd 重启；
- pin 持有 prog 的引用，只要 pin 在，这个 id 就不会被分配给别的程序；
- 文件名里编码了接口名，遍历 `attach/` 就知道挂在哪些网卡上、用的哪种方式（`mfw_dp_list_attached()`、purge）；
- 全部状态都在 `/sys/fs/bpf/seawall/mfw/` 下，`mfwd -P` 按目录清理即可。

代价是：组件被别人从 dispatcher 里取下后，pin 仍让这个程序对象留在内存里，直到 `mfw_xdp_attached()` 发现它已过时并 unlink。

## 2. 编译期：skeleton

BPF 对象被整个嵌进 mfwd 二进制，运行时不需要在磁盘上找 `.o` 文件。

```
mfw.bpf.c --clang -target bpf--> build/mfw.bpf.o --bpftool gen skeleton--> src/mfw.skel.h
```

`mfw.skel.h` 把整个 ELF 存成字节数组，并生成带类型的访问器：`skel->maps.rulesets`、`skel->progs.mfw_tc`，以及 `mfw_bpf__open_opts()`、`__load()`、`__destroy()`。libxdp 和 libbpf 静态链进 mfwd，目标机器上不需要装这两个库；它们依赖的 libelf 和 zlib 仍是动态链接。

一个 skeleton 可以 open 多次，每次得到一个独立的 `bpf_object`。mini-fw 正是靠这一点给每个 XDP 接口加载一份独立副本（见第 5 节）。

## 3. `mfw_dp_open()`：open → 绑定 → load

`mfw_dp_open()`（`dataplane.c:207`）只加载 TC 入口，并创建、pin 所有共享 maps；它不挂载任何接口。

```c
LIBBPF_OPTS(bpf_object_open_opts, opts, .pin_root_path = maps);
skel = mfw_bpf__open_opts(&opts);                       // 解析 ELF/BTF，还没进内核
bpf_map__reuse_fd(skel->maps.flows, flows_fd);          // 换成 sw_flowd 的 map
bpf_program__set_autoload(skel->progs.mfw_xdp, false);  // 只加载 TC 入口
mfw_bpf__load(skel);                                    // 创建/复用 map → 重定位 → 验证器
```

**`pin_root_path` 与 `LIBBPF_PIN_BY_NAME`。** load 时，libbpf 对每个带 pinning 属性的 map 检查 `<root>/<name>` 是否存在。存在就 `bpf_obj_get()`，做兼容性检查（type、key/value size、max_entries、flags）后复用；不存在就创建并 pin。mfwd 启动时先 purge，所以第一次 load 总是创建；之后每个接口的 XDP 副本 load 时都复用这几个 pin，多个程序实例因此共享同一份状态。

**`flows` 故意不 pin。** 它要绑定的是别人的 map。`bpf_map__reuse_fd()` 必须在 load 之前调用（`dataplane.c:247`），它会 dup 这个 fd，并用该 fd 的 map info 覆盖 ELF 里的定义。所以源码里的 `max_entries 1` 只是占位：有 sw_flowd 时被替换；没有时每个程序实例各有一个空的 LRU map，`reply` 永远匹配不到，即 fail closed。

**`set_autoload(false)`。** 一个 ELF 里有两个入口。TC 入口由 mfwd 直接 load；XDP 入口必须交给 libxdp，以 freplace 方式加载（见第 5 节）。所以两边各自关掉对方的入口。

**两个入口是两个独立的内核对象。** `mfw.bpf.c` 里有 `SEC("xdp.frags") mfw_xdp`（:496）和 `SEC("tcx/ingress") mfw_tc`（:519）。libbpf 打开 ELF 时为每个入口建一个 `bpf_program`；load 时每个入口各发一次 `BPF_PROG_LOAD`，在内核里生成各自的 `struct bpf_prog`，有各自的 prog id 和程序类型。

| 入口 | 在哪里 load | 内核里的程序类型 | 份数 |
| --- | --- | --- | --- |
| `mfw_tc` | `mfw_dp_open()`：`dataplane.c:259` 关掉 XDP 入口，:262 load，:269 取 fd | `BPF_PROG_TYPE_SCHED_CLS` | 1 份，所有走 TC 的接口共用 |
| `mfw_xdp` | `xdp_load()`：`dp_xdp.c:254` 关掉 TC 入口，:264 交给 libxdp | 源码里是 XDP，libxdp 在 load 前改成 `BPF_PROG_TYPE_EXT`（`xdp_multiprog__link_prog()`） | 每个 XDP 接口 1 份 |

**maps 共享，代码不共享。** 每次 load 前，libbpf 通过 `pin_root_path` 打开同一组 pinned maps，`flows` 则绑定同一个 sw_flowd 表（`dataplane.c:247`、`dp_xdp.c:256`）。内核把 map 指针记进每个程序的 `used_maps` 并各持一个引用，所以所有入口读写的是同一组 maps。代码则每个程序各有一份指令和 JIT 镜像：`mfw_judge()` 是 `__always_inline`（:390），直接展开进两个入口；`mfw_ext_ace_match()` 虽是 global 函数（:264），libbpf 也会把它追加到每个调用它的程序后面。

实测（`bpftool prog show`）：

```
74249: ext  name mfw_xdp  tag 1984d724104a1ac0  gpl
	xlated 3752B  jited 2279B  memlock 4096B  map_ids 47163,47162,47161,14572
	btf_id 50740
```

`mfw_tc` 的 `map_ids` 与之相同；其中 14572 是 sw_flowd 的表，跨越 mfwd 重启也不变，其余三个是 rulesets、config、stats，每次 mfwd 启动都会重建。

**验证器与 global function。** `mfw_ext_ace_match()` 是非 static 的 `__noinline` 函数。验证器对 global 函数只按 BTF 签名在一个程序内单独验证一次，调用点只检查参数类型、把返回值当作未知整数。若把它展开在 128 次的循环里，验证器会逐圈展开循环，每圈都要重新走一遍函数里的所有分支，状态还会跨圈叠加；mini-fw 早期的写法就因此超过了 100 万条指令的上限（[implementation.md](implementation.md) §3.4）。现在整个程序约 16K 条指令。代价是：带指针参数的 global 函数要求内核 5.12+，函数内部必须判 NULL（`mfw.bpf.c:266`），而且每检查一条 ACE 都是一次真正的函数调用。验证器只在 load 时运行，数据路径上没有验证开销。

最后，`mfw_dp_open()` 取出各 fd，用 `sw_bpf_have_tcx()` 探测 tcx，并调用 `init_config()` 写入 config 的初始值。

## 4. Map-in-map：规则集的原子替换

每个接口的规则集放在一个独立的 inner map 里，换规则就是换一个指针，所以每个包看到的要么是完整的旧规则，要么是完整的新规则。

一个 `mfw_ruleset` 约 6.8KB（8 + 192×36 字节）。如果用 `bpf_map_update_elem` 原地覆盖，内核的拷贝不是原子的，正在执行的包可能读到一半旧、一半新的规则。

用户态分成两个函数：`mfw_dp_ruleset_new()`（`dataplane.c:389`）新建并填好 inner map，`mfw_dp_ruleset_swap()`（:414）把它换进 outer map。`mfwd.c` 的 `install()`（:262）先为所有接口建好 inner map，全部成功后才写 config、逐个替换，最后统一 close：

```c
// mfw_dp_ruleset_new()：建好、填好，返回 fd；install() 对每个接口先调一遍
fd = bpf_map_create(BPF_MAP_TYPE_ARRAY, "mfw_ruleset", 4, sizeof(*rs), 1, NULL);
bpf_map_update_elem(fd, &zero, rs, BPF_ANY);                      // 1. 填好新的 inner map

// 全部建好之后
mfw_dp_set_config(dp, drop_ipv4_fragments, gen);                  // 2. 再写 config
bpf_map_update_elem(dp->rulesets_fd, &ifindex, &fd[i], BPF_ANY);  // 3. mfw_dp_ruleset_swap()：一次指针替换
mfw_dp_ruleset_prune(dp, keep, n_keep);                           // 4. 删掉不再需要的条目
close(fd[i]);                                                     // 5. outer map 持有引用
```

建 inner map 失败（比如 memlock 或 ENOMEM）时，config 和所有接口的规则都还没动，旧策略照常运行，`apply()` 还会拆下 `attach_bound()` 刚挂上的接口。只有替换本身失败才会留下新旧混合，而对一个已经建好的 map 做 update 几乎不会失败。

**`bpf_map_create()` 每次都新建一个 map。** 它不会去找已有的 map；返回的 fd 就是新 map 唯一的句柄。名字 `"mfw_ruleset"` 只是给 `bpftool map show` 看的标签，所有 inner map 都叫这个名字，内核不要求唯一，也没有按名字查 map 的接口。哪个 inner map 属于哪个接口，是第 3 步按 outer map 的 key（ifindex）决定的。ARRAY 的元素在创建时就分配好并清零，所以先填后挂这个顺序很重要：如果先挂上去，程序会读到全 0 的 ruleset，即两个列表都未绑定，这个接口在这段时间里全部放行。

BPF 侧 `ruleset_of()`（`mfw.bpf.c:368`）：

```c
inner = bpf_map_lookup_elem(&rulesets, &ifindex);   // 取到 inner map 指针
return bpf_map_lookup_elem(inner, &zero);           // 再取 value
```

**inner map 模板。** `struct ruleset_map`（`mfw.bpf.c:99-104`）是 inner map 的模板。libbpf 创建 outer map 时，先按它临时建一个 inner map 作为样板，内核从样板抄下元数据存在 outer map 里。之后每次放入 inner map，内核都会比较 type、key_size、value_size、flags，对 ARRAY 还有 max_entries（因为没设 `BPF_F_INNER_MAP`），不一致就返回 EINVAL。两边都用 `include/mfw.h` 的 `struct mfw_ruleset`，大小自然一致。模板是在创建 outer map 时写进去的；mfwd 每次启动都重建所有 maps，改了 `mfw_ruleset` 的大小也不会和旧的 outer map 冲突。名字不在比较之列。

**为什么是原子的。** outer map 的 update 本质是替换一个指针。正在执行的程序处于 RCU 读临界区，已拿到旧 inner map 的指针，可以安全读完；旧 map 在宽限期过后才释放。新包看到新指针。旧指针由内核保存在已从链表摘下的旧 hash 元素里，宽限期过后，内核释放这个元素并对旧 inner map 做 `bpf_map_put()`；outer map 是它唯一的引用者，所以旧 inner map 随之释放。

**代价。** 对 `HASH_OF_MAPS` 的每次 update 或 delete，系统调用路径都会 `synchronize_rcu()`，保证返回时已没有程序在用旧 inner map。这个代价只落在 mfwd 的那次系统调用上：调用线程在内核里睡眠等待宽限期结束，不占 CPU，也不额外制造宽限期。数据路径不受影响，因为 BPF 程序是 RCU 读者，从不等待。宽限期通常是几毫秒到几十毫秒，一次 apply 的耗时约为（替换次数 + 删除次数）乘以一个宽限期。mfwd 是单线程的，这段时间里不处理其他请求。目前每次 APPLY 仍会重装所有绑定接口，规则没变的也不例外。

**`mfw_dp_ruleset_prune()`**（`dataplane.c:428`）删的是 outer map 里不在 keep 列表中的条目（ifindex → inner map 指针），inner map 随之释放。只重装仍绑定的接口是不够的：不再绑定的接口没有新规则可换，它的条目会一直保留旧规则；被删除、重建或改名的接口，按名字工作的 `detach_unbound()` 也找不到。prune 按 ifindex 对账，保证 outer map 和新策略一致。遍历时，删除成功不移动游标，下一轮仍从上一个保留的 key 往后找；保留才前移游标。这样每个 key 只访问一次，删除失败也不会死循环。边遍历边删除之所以安全，是因为 mfwd 是 outer map 唯一的写者。

## 5. XDP：libxdp dispatcher

libxdp 的 dispatcher 让 mini-fw 排在 voidgate 之后、与它共用一块网卡的 XDP hook；mini-fw 为每个接口加载一份独立的程序副本。

**问题背景。** 一块网卡的 XDP hook 只能挂一个程序。mini-fw 要和 voidgate（DDoS 闸门）共存，且 voidgate 必须先运行（Seawall proposal 0004）。

**libxdp 的解法。** 生成一个 dispatcher XDP 程序，里面有若干个 `__noinline` 的空 stub 槽位：

```
dispatcher(ctx):
    ret = slot0(ctx)   ← voidgate (priority 10)   freplace
    if !(chain_call_actions[0] & (1<<ret)) return ret
    ret = slot1(ctx)   ← mfw_xdp  (priority 20)   freplace
    if !(chain_call_actions[1] & (1<<ret)) return ret
    ...
    return XDP_PASS
```

每个组件以 `BPF_PROG_TYPE_EXT`（freplace）加载，替换 dispatcher 里的某个槽位函数。顺序和哪些返回值继续往下走，由组件在一个特殊的 ELF section 里自己声明：

```c
struct { __uint(priority, 20); __uint(XDP_PASS, 1); } XDP_RUN_CONFIG(mfw_xdp);
// 优先级 20（在 voidgate 的 10 之后）；只有返回 XDP_PASS 才交给下一个组件
```

**priority 只是排序依据，不对应槽位，相等也不冲突。** libxdp 每次重建 dispatcher 时用 `cmp_xdp_programs()`（xdp-tools `lib/libxdp/libxdp.c:1535-1575`）把所有组件排一遍序，再按顺序填进槽位：priority 小的先运行；相同时按程序名的字典序；名字也相同时，依次比较是否已加载、指令数、tag、加载时间。没有声明 `XDP_RUN_CONFIG` 的程序默认 priority 是 50（`headers/xdp/xdp_helpers.h:9`）。需要注意的是顺序带来的后果和 dispatcher 的限制：

- **顺序决定谁看得到包。** 组件返回的动作不在它的 `chain_call_actions` 里时，调用链就此结束；默认只有 `XDP_PASS` 会继续（`xdp_helpers.h:10`）。别的程序若把 priority 设得比 20 小，就会抢在 mini-fw 之前，可能绕过防火墙；
- **一个 dispatcher 最多 10 个组件**（`MAX_DISPATCHER_ACTIONS`，`headers/xdp/prog_dispatcher.h:21`）；
- **frags 支持取决于最弱的组件。** 只要有一个组件不支持 frags，整个 dispatcher 就按不支持加载（`libxdp.c:3175-3188`），jumbo MTU 的网卡上 attach 会失败。

各组件的 priority 分配见 Seawall proposal 0013。

**freplace 怎么绑定目标。** 分两步。load 时必须指定一个目标（`bpf_program__set_attach_target(prog, dispatcher_fd, "prog0")`），验证器对照这个目标函数的 BTF 签名验证程序，所以第一次 load 时必须已有一个 dispatcher。attach 时用 `bpf_link_create(prog_fd, target_fd, 0, {.target_btf_id})` 建立链接；从内核 5.10 起，`target_fd` 可以是另一个签名兼容的 dispatcher。libxdp 自己就依赖这一点（`xdp_multiprog__link_prog()`）：每次有组件加入或离开，它都生成新的 dispatcher，把原有的组件重新链接过去。所以内核并不禁止一份 `mfw_xdp` 同时链接到多块网卡的 dispatcher。

**为什么 mini-fw 仍然每个接口一份副本（`xdp_load()`，`dp_xdp.c:237`）。** 这是 mini-fw 自己的设计选择，为的是让每个接口的挂载在身份和生命周期上都独立：

- 每个接口一个 prog id，一一对应：`attach/xdp_eth0` 里的 id 只属于 eth0，`mfw_xdp_attached()`、`mfw_xdp_unload()` 和 purge 都按“接口 → id”工作；
- 不依赖第一个接口：共用时，程序的 load 目标是第一个接口的 dispatcher，那块网卡被删后关系会变复杂；
- mfwd 进程内不长期持有共享的 XDP 程序对象，每次 open、load、attach、pin、destroy 一气呵成。

代价很小：maps 通过 `pin_root_path` 共享，多出来的只是程序本身；每份副本过一次验证器，只在 attach 时发生。每个接口都要：

```c
skel = mfw_bpf__open_opts(&oopts);                   // 新 bpf_object，pin_root_path 指向 maps/
bpf_program__set_autoload(skel->progs.mfw_tc, false);
bpf_map__reuse_fd(skel->maps.flows, flows_fd);
xopts.obj = skel->obj;
xp = xdp_program__create(&xopts);                    // libxdp 接管 load（作为 EXT）
xdp_program__set_xdp_frags_support(xp, true);
xdp_program__attach(xp, ifindex, mode, 0);           // 加入或新建 dispatcher
bpf_obj_pin(xdp_program__fd(xp), "attach/xdp_<if>"); // 自己的标记
xdp_program__close(xp); mfw_bpf__destroy(skel);      // 关 fd；内核里的引用还在
```

attach 的内部过程：libxdp 读出当前 dispatcher 的组件列表，加入新组件，按 priority 排序，生成一个新的 dispatcher，再原子替换整个 hook，已有组件不会出现被短暂卸下的窗口。组件被新 dispatcher 引用，libxdp 还在 `/sys/fs/bpf/xdp/` 下 pin 住它们，所以 mfwd 关掉所有 fd 后程序依然存活。

**挂载粒度是网卡，不是收包队列。** 网卡的每个 RX 队列在各自的 CPU 上调用同一份程序，所以一份 `mfw_xdp` 可能同时在多个 CPU 上执行。`stats` 因此用 per-CPU map（第 8 节）；`rulesets` 和 `config` 在数据路径上只读，并发读取没有问题。

**判断 hook 状态（`mfw_xdp_state()`，`dp_xdp.c:53`）。** `xdp_multiprog__get_from_ifindex()` 返回 ENOENT 表示 hook 空闲；`is_legacy` 为真且有 main prog，表示别人独占了 hook：mini-fw 绝不替换，转去 TC，即降级；否则说明已有 dispatcher，加入它并沿用它的模式。

**native 与 skb 模式。** 新建 dispatcher 时先试 native（驱动层，性能最好）；驱动拒绝时先打一条 warn（带上原生模式的 errno，`dp_xdp.c:362`），再退到 skb，即 generic XDP，运行在 `netif_receive_skb` 路径上，skb 已分配，性能接近 TC。AWS 上常见的 ENA 在 MTU > 3498 时会拒绝 native 模式。

**frags。** `SEC("xdp.frags")` 让程序带上 `BPF_F_XDP_HAS_FRAGS`，但 dispatcher 本身也必须支持 frags，否则 jumbo MTU 的网卡拒绝挂载，所以 `dp_xdp.c:277` 要额外告诉 libxdp。mini-fw 只读第一个 buffer 里的头部，多 buffer 的包不受影响。

**识别我们的组件。** `mfw_xdp_pinned_id()` 从 pin 拿到 prog id，`mfw_xdp_attached()`（`dp_xdp.c:177`）遍历 dispatcher 的组件逐个比对；这里的 id 是组件（EXT）程序的 id，不是 dispatcher 的。网卡被删除重建，或组件被别人移除时，判定 pin 已过时并删掉它。`mfw_xdp_unload(ifindex, 0)`（`dp_xdp.c:348`）按名字 `mfw_xdp` 清理崩溃后残留、没有 pin 指向的副本。

**拆除。** `xdp_program__detach()` 取下指定组件，libxdp 生成一个不含它的新 dispatcher 并原子替换。

## 6. TC 降级：tcx 与 classic cls_bpf

当别的程序独占 XDP hook 时，mini-fw 退到 TC ingress：6.6 及以后用 tcx link，之前用 clsact qdisc 上的 cls_bpf filter（6.1 是为 Amazon Linux 2023 保留的下限）。

**tcx（6.6+）** 是基于 bpf_link 的 TC 挂载（`mfw_tcx_attach()`，`dp_tc.c:199`）：

```c
fd = bpf_link_create(prog_fd, ifindex, BPF_TCX_INGRESS, NULL);  // 默认追加到末尾
bpf_obj_pin(fd, "attach/tcx_<if>");  close(fd);                 // pin 是唯一的引用
```

link 的语义很干净：所有引用消失时自动 detach，进程崩溃也不留孤儿。返回值方面，`TC_ACT_UNSPEC`（-1）等于 `TCX_NEXT`，表示交给下一个程序；`TC_ACT_SHOT` 等于 `TCX_DROP`（`mfw.bpf.c:558-561`）。在 6.1 的 UAPI 头文件下编译所需的 tcx 常量，以及从 link 读出 ifindex（`sw_bpf_tcx_ifindex()`），现在由 libsw 的 `<sw/bpf.h>` 提供（commit `ff3d37e`）。mfwd 用不用 tcx 是运行时由 `sw_bpf_have_tcx()` 探测内核决定的，在 6.1 头文件下编译出的 mfwd 放到 6.6+ 的内核上照样用 tcx。

**classic TC（6.6 之前）：**

```c
bpf_tc_hook_create(&hook);     // 建 clsact qdisc（已存在就是 EEXIST）
bpf_tc_attach(&hook, &opts);   // cls_bpf filter，direct-action，handle 0x4d46，prio 0xc000，REPLACE
```

filter 是 qdisc 里的对象，与任何 fd 无关，所以 pin 只用来标记这是 mfwd 放的。`BPF_TC_F_REPLACE` 让重复 attach 在一次 netlink 请求里完成替换，没有空档。detach 时只删 filter、保留 clsact，因为别人可能也在用它。

**TC 入口特有的 `bpf_skb_pull_data`（`mfw.bpf.c:549`）。** TC 程序只能直接访问 skb 的线性区，而 GRO 之后头部可能落在 frags 里。代码先按现有数据解析，只有返回 `PKT_SHORT`、且线性区确实不够 `PKT_HDR_MAX` 时才 pull。原因是 pull 会让 skb 变成可写，对 clone 出来的 skb 要拷贝头部。pull 之后 `data`/`data_end` 指针失效，必须重新读取，验证器也强制这一点。

所有 TC 接口共用 `mfw_dp_open()` 加载的同一个程序实例；一个 prog 可以同时被多个 tcx link 或 filter 引用。

## 7. 生命周期

mfwd 每次启动都清空重建，退出时什么都不拆；只有 `mfwd -P` 会真正移除 mini-fw。

```
mfwd 启动
  sw_sock_listen()            ← 先占住 socket：防止第二个 mfwd 碰 pins
  mfw_dp_purge()              ← 按 attach/ pins 拆除挂载，再 unpin attach/ 和 maps/
                                （任一接口无法 lookup → 中止，保留 pins，宁可不动）
  mfw_dp_open()               ← load TC 入口，maps 被新建并 pin
  restore()                   ← 重放 /run/mfwd/policy
                                  └ attach（每个接口一份 XDP 副本，或 tcx/tc）
                                  └ install（创建 inner map → swap）
  sw_notify_ready()
  accept 循环...
mfwd 退出
  mfw_bpf__destroy()          ← 只关 fd；pins、link、dispatcher、qdisc 都还在 → 继续过滤
mfwd -P
  purge + 删除保存的策略       ← 彻底移除
```

从 purge 到 restore 完成之间，所有接口都是放行状态（fail-open），这是有意的取舍：没有 live update。restore 失败时（`restore()`，`mfwd.c:730`），mfwd 记一条 error，说明所有接口都在放行，但仍然继续服务并通知 systemd 就绪，好让 sw_configd 这样的前端重新下发策略。

**运行权限。** `mfwd.service` 以 root 运行，`CapabilityBoundingSet` 是 CAP_BPF、CAP_NET_ADMIN、CAP_SYS_ADMIN、CAP_PERFMON、CAP_CHOWN。CAP_SYS_ADMIN 必须保留：`BPF_PROG_GET_FD_BY_ID` 这类命令仍要求它，而 libxdp 要按 id 打开 dispatcher 及其组件。有了 CAP_SYS_ADMIN，perfmon 检查也已满足，所以去掉 CAP_PERFMON 并无意义。unit 里的其他沙箱指令和 BPF 相关的有两点：`SystemCallFilter=@system-service` 之外单独放行了 `bpf`；并且刻意没有开 `ProtectKernelTunables=`，因为它会把整个 `/sys` 挂成只读，`ReadWritePaths=` 也救不回 `/sys/fs/bpf`，而 mfwd 和 libxdp 都要在那里 pin。

## 8. 统计：per-CPU map 的读取

计数器是 `PERCPU_ARRAY`（`mfw.bpf.c:125`），BPF 侧无锁自增，用户态读出每个 CPU 的值再求和。

BPF 侧每个 CPU 只写自己的槽（`stat_inc()` 里的 `v->count++`，`mfw.bpf.c:166`）。XDP 和 TC 在单个 CPU 上执行时不会被同一 map 的其他写者打断，所以不需要原子操作，也不会互相抢 cache line。用户态 lookup 一个 per-CPU map，得到的是长度为 `libbpf_num_possible_cpus()` 的数组，需要自己求和（`mfw_dp_stats()`，`dataplane.c:523`）。注意要用 possible CPU 数，而不是 online 数，否则 buffer 会不够大。

## 9. 现场排查命令

这些命令能看到上面每一层对象的实际状态。

```bash
xdp-loader status eth0                                   # dispatcher 组件、优先级、模式
bpftool net show dev eth0                                # XDP / tcx / tc 全貌
bpftool link show                                        # tcx link，以及组件的 freplace link
tc filter show dev eth0 ingress                          # classic cls_bpf（handle 0x4d46）
bpftool map dump pinned /sys/fs/bpf/seawall/mfw/maps/rulesets   # ifindex → inner map id
bpftool map dump id <inner_id>                           # 某接口当前的 ruleset
bpftool -f prog show name mfw_xdp                        # 各接口的副本，加 -f 列出 pin 路径
sysctl -w kernel.bpf_stats_enabled=1                     # 之后 prog show 多出 run_time_ns / run_cnt
SW_BPF_DEBUG=1 mfwd -v                                   # 验证器日志
```

`bpftool prog show` 的几个字段：`tag` 是指令内容（抹掉 map 引用后）的哈希，代码相同则相同；`xlated` 是验证器改写后的 BPF 指令字节数（每条 8 字节），`jited` 是 JIT 后的机器码字节数；`memlock` 是程序头加 xlated 指令按页取整后的大小，不含 JIT 代码和 maps；`btf_id` 是程序自带的 BTF 对象，每份副本各不相同。开启 `bpf_stats_enabled` 后，`run_time_ns / run_cnt` 就是每个包的平均耗时；统计本身有开销，测完记得关掉。
