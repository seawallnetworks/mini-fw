
/* SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause */

/*
 * Dataplane tests via BPF_PROG_TEST_RUN: feed crafted frames to the TC
 * ingress program and check verdicts (TC_ACT_UNSPEC: passed on,
 * TC_ACT_SHOT). Each frame goes through the XDP entry too, whose verdict
 * must be the same (XDP_PASS, XDP_DROP). Needs root. Runs in a private
 * network namespace with two dummy interfaces, so the per-interface
 * rulesets have real ifindexes; touches no host interface or pins.
 */


#define _GNU_SOURCE

#include "mfw_policy.h"
#include "mfw.skel.h"

#include <sw_flowd/sw_flowd.h>

#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/pkt_cls.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <net/if.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>


#define mfw_check(cond, ...)                                                 \
    do {                                                                     \
        if (!(cond)) {                                                       \
            mfw_failures++;                                                  \
            printf("FAIL %s:%d: ", __FILE__, __LINE__);                      \
            printf(__VA_ARGS__);                                             \
            printf("\n");                                                    \
        }                                                                    \
    } while (0)

/* TC's verdict on a frame, on if0 unless said otherwise */
#define mfw_tc(...)         run(mfw_if0, &(mfw_pkt_spec_t) { __VA_ARGS__ })
#define mfw_tc_on(i, ...)   run((i), &(mfw_pkt_spec_t) { __VA_ARGS__ })

#define MFW_TCP   .proto = IPPROTO_TCP
#define MFW_UDP   .proto = IPPROTO_UDP
#define MFW_ICMP  .proto = IPPROTO_ICMP

/* run_prog(): the program couldn't run (-1 is TC_ACT_UNSPEC) */
#define MFW_RUN_ERR  (-100)


/* ---- packet builder ---- */

typedef struct {
    const char  *src;
    const char  *dst;
    __u8         proto;
    __u16        sport;
    __u16        dport;
    __u8         tcp_flags;    /* default SYN */
    int          vlans;        /* 0..3 tags */
    __u16        frag_off;     /* host order: IP_MF | offset */
    __u8         ihl;          /* default 5 */
    __u16        ethertype;    /* default IPv4 */
    __u8         icmp_type;    /* default 8, echo request */
    int          echo_reply;   /* type 0, which icmp_type can't say */
    __u8         icmp_code;
    __u16        icmp_id;
    /*
     * an ICMP error's embedded packet, if in_proto is set: from in_src to
     * in_dst, its ports or an echo request's identifier (in_sport)
     */
    const char  *in_src;
    const char  *in_dst;
    __u8         in_proto;
    __u16        in_sport;
    __u16        in_dport;
} mfw_pkt_spec_t;


static int build(const mfw_pkt_spec_t *s, __u8 *buf);
static void build_inner(const mfw_pkt_spec_t *s, __u8 *p);
static int run_prog(struct bpf_program *prog, void *ctx, __u32 ctx_size,
    __u8 *buf, int len);
static void stats_copy(struct mfw_stat_value *save, int restore);
static int run(__u32 ifindex, const mfw_pkt_spec_t *s);
static void reset(void);
static void add(const char *line);
static void commit_on(__u32 ifindex);
static void commit(void);
static __u64 stat(__u32 id);
static __u64 now_ns(void);
static void flow_add_state(int table, __u8 proto, const char *raddr,
    __u16 rport, __u16 lport, __u64 ago_s, __u64 state);
static void flow_add(int table, __u8 proto, const char *raddr, __u16 rport,
    __u16 lport, __u64 ago_s);
static void flows_clear(int table);
static void set_no_flow_table(int on);
static void test_unbound(void);
static void test_standard(void);
static void test_extended(void);
static void test_combined(void);
static void test_established(void);
static void test_reply(void);
static void test_reply_miss(void);
static void test_fragments(void);
static void test_full_tables(void);
static void test_per_interface(void);
static void test_corrupt(void);
static int setup_netns(void);


static struct mfw_bpf      *mfw_skel;
static int                  mfw_flows_table;  /* sw_flowd's, bound at load */
static int                  mfw_failures;
static __u32                mfw_if0, mfw_if1; /* the dummy mfwt0, mfwt1 */
static struct mfw_ruleset   mfw_rs;           /* being built */


static int
build(const mfw_pkt_spec_t *s, __u8 *buf)
{
    int              i;
    __u8            *p, *proto;
    __be16           v;
    struct iphdr    *ip;
    struct tcphdr   *th;
    struct udphdr   *uh;
    struct ethhdr   *eth;

    memset(buf, 0, 256);

    p = buf;
    eth = (void *) p;
    memset(eth->h_dest, 0x02, ETH_ALEN);
    memset(eth->h_source, 0x04, ETH_ALEN);
    p += sizeof(*eth);

    proto = p - 2;               /* ethertype slot to fill next */

    for (i = 0; i < s->vlans; i++) {
        v = htons(i == 0 && s->vlans > 1 ? 0x88a8 : 0x8100);
        memcpy(proto, &v, 2);
        p[1] = 10 + i;           /* VID */
        proto = p + 2;
        p += 4;
    }

    v = htons(s->ethertype != 0 ? s->ethertype : ETH_P_IP);
    memcpy(proto, &v, 2);

    if (s->ethertype != 0 && s->ethertype != ETH_P_IP) {
        /*
         * e.g. ARP: payload is irrelevant, but an skb test run of IPv6
         * needs 40
         */
        return p - buf + 40;
    }

    ip = (void *) p;
    ip->version = 4;
    ip->ihl = s->ihl != 0 ? s->ihl : 5;
    ip->ttl = 64;
    ip->protocol = s->proto;
    ip->saddr = inet_addr(s->src);
    ip->daddr = inet_addr(s->dst);
    ip->frag_off = htons(s->frag_off);
    ip->id = htons(0x1234);
    p += 20;

    if (!(s->frag_off & 0x1fff)) {
        if (s->proto == IPPROTO_TCP) {
            th = (void *) p;
            th->source = htons(s->sport);
            th->dest = htons(s->dport);
            th->doff = 5;
            p[13] = s->tcp_flags != 0 ? s->tcp_flags : 0x02;
            p += sizeof(*th);

        } else if (s->proto == IPPROTO_UDP) {
            uh = (void *) p;
            uh->source = htons(s->sport);
            uh->dest = htons(s->dport);
            uh->len = htons(8);
            p += sizeof(*uh);

        } else if (s->proto == IPPROTO_ICMP) {
            p[0] = s->echo_reply ? 0 : s->icmp_type != 0 ? s->icmp_type : 8;
            p[1] = s->icmp_code;
            v = htons(s->icmp_id);
            memcpy(p + 4, &v, 2);
            p += 8;

            if (s->in_proto != 0) {
                build_inner(s, p);
                p += 28;
            }
        }
    }

    p += 16;                     /* a little payload */
    ip->tot_len = htons(p - (__u8 *) ip);

    return p - buf;
}


/*
 * An ICMP error's embedded packet at p: the IPv4 header, and the 8 bytes
 * of L4 an error carries, 28 bytes in all
 */
static void
build_inner(const mfw_pkt_spec_t *s, __u8 *p)
{
    __be16         v;
    struct iphdr  *ip = (void *) p;

    ip->version = 4;
    ip->ihl = 5;
    ip->ttl = 1;
    ip->protocol = s->in_proto;
    ip->saddr = inet_addr(s->in_src);
    ip->daddr = inet_addr(s->in_dst);
    ip->tot_len = htons(60);
    p += 20;

    if (s->in_proto == IPPROTO_ICMP) {
        p[0] = 8;                /* the host's echo request */
        v = htons(s->in_sport);
        memcpy(p + 4, &v, 2);

    } else {
        v = htons(s->in_sport);
        memcpy(p, &v, 2);
        v = htons(s->in_dport);
        memcpy(p + 2, &v, 2);
    }
}


/* prog's return value on the frame, with ctx; MFW_RUN_ERR if it can't run */
static int
run_prog(struct bpf_program *prog, void *ctx, __u32 ctx_size, __u8 *buf,
    int len)
{
    LIBBPF_OPTS(bpf_test_run_opts, opts, .data_in = buf,
                .data_size_in = len, .ctx_in = ctx,
                .ctx_size_in = ctx_size, .repeat = 1);

    if (bpf_prog_test_run_opts(bpf_program__fd(prog), &opts) != 0) {
        perror("bpf_prog_test_run_opts");
        mfw_failures++;
        return MFW_RUN_ERR;
    }

    return (int) opts.retval;
}


/*
 * The counters, all CPUs': put back after the XDP run, so they count
 * the TC run alone.
 */
static void
stats_copy(struct mfw_stat_value *save, int restore)
{
    int    fd, ncpu;
    __u32  id;

    ncpu = libbpf_num_possible_cpus();
    fd = bpf_map__fd(mfw_skel->maps.stats);

    for (id = 0; id < MFW_STAT_MAX; id++) {
        if (restore) {
            bpf_map_update_elem(fd, &id, save + id * ncpu, BPF_ANY);

        } else {
            bpf_map_lookup_elem(fd, &id, save + id * ncpu);
        }
    }
}


/* TC's verdict on the frame, which XDP's must match. */
static int
run(__u32 ifindex, const mfw_pkt_spec_t *s)
{
    int                     len, tc, xdp;
    struct xdp_md           xctx = {};
    struct __sk_buff        ctx = {};
    __u8                    buf[256];
    struct mfw_stat_value   save[MFW_STAT_MAX * libbpf_num_possible_cpus()];

    len = build(s, buf);

    ctx.ingress_ifindex = ifindex;

    /* the frame's bounds, as the kernel checks them */
    xctx.data_end = len;
    xctx.ingress_ifindex = ifindex;

    stats_copy(save, 0);
    xdp = run_prog(mfw_skel->progs.mfw_xdp, &xctx, sizeof(xctx), buf, len);
    stats_copy(save, 1);

    tc = run_prog(mfw_skel->progs.mfw_tc, &ctx, sizeof(ctx), buf, len);

    mfw_check(xdp == (tc == TC_ACT_SHOT ? XDP_DROP : XDP_PASS),
              "XDP verdict %d, TC verdict %d", xdp, tc);

    return tc;
}


/* ---- rule loading (mirrors mfw_policy_compile() and dataplane.c) ---- */


/* Clears the ruleset being built and every installed one. */
static void
reset(void)
{
    __u32              k;
    struct mfw_config  cfg = {};

    cfg.abi_version = MFW_ABI_VERSION;
    k = 0;

    memset(&mfw_rs, 0, sizeof(mfw_rs));

    /* as mfw_policy_compile() sets them; the test's: an hour, a minute */
    mfw_rs.reply_idle_tcp = 3600;
    mfw_rs.reply_idle_udp = 60;

    bpf_map_update_elem(bpf_map__fd(mfw_skel->maps.config), &k, &cfg,
                        BPF_ANY);
    bpf_map_delete_elem(bpf_map__fd(mfw_skel->maps.rulesets), &mfw_if0);
    bpf_map_delete_elem(bpf_map__fd(mfw_skel->maps.rulesets), &mfw_if1);
}


static void
add(const char *line)
{
    int              argc;
    char            *t;
    struct mfw_rule  r;
    char            *argv[32], buf[256], err[160];

    snprintf(buf, sizeof(buf), "%s", line);

    argc = 0;

    for (t = strtok(buf, " "); t != NULL; t = strtok(NULL, " ")) {
        argv[argc++] = t;
    }

    if (mfw_parse_ace(argc, argv, &r, err, sizeof(err)) != 0) {
        printf("bad test rule '%s': %s\n", line, err);
        mfw_failures++;
        return;
    }

    if (r.kind == MFW_ACL_STANDARD) {
        mfw_rs.std_acl = r.acl_id;
        mfw_rs.std[mfw_rs.n_std++] = r;

    } else {
        mfw_rs.ext_acl = r.acl_id;
        mfw_rs.ext[mfw_rs.n_ext++] = r;
    }
}


/* Swaps the ruleset built so far in on ifindex, as dataplane.c does. */
static void
commit_on(__u32 ifindex)
{
    int    fd, outer;
    __u32  zero;

    zero = 0;
    outer = bpf_map__fd(mfw_skel->maps.rulesets);

    fd = bpf_map_create(BPF_MAP_TYPE_ARRAY, "mfw_ruleset", sizeof(__u32),
                        sizeof(struct mfw_ruleset), 1, NULL);

    if (fd < 0
        || bpf_map_update_elem(fd, &zero, &mfw_rs, BPF_ANY) != 0
        || bpf_map_update_elem(outer, &ifindex, &fd, BPF_ANY) != 0)
    {
        perror("install ruleset");
        mfw_failures++;
    }

    if (fd >= 0) {
        close(fd);   /* the outer map holds the inner one now */
    }
}


static void
commit(void)
{
    commit_on(mfw_if0);
}


static __u64
stat(__u32 id)
{
    int                     i, ncpu;
    __u64                   sum;
    struct mfw_stat_value   vals[libbpf_num_possible_cpus()];

    ncpu = libbpf_num_possible_cpus();
    sum = 0;

    if (bpf_map_lookup_elem(bpf_map__fd(mfw_skel->maps.stats), &id, vals)
        != 0)
    {
        return 0;
    }

    for (i = 0; i < ncpu; i++) {
        sum += vals[i].count;
    }

    return sum;
}


static void
test_unbound(void)
{
    reset();
    mfw_check(mfw_tc(.src = "10.0.0.1", .dst = "10.0.0.5", MFW_TCP,
                     .dport = 22) == TC_ACT_UNSPEC,
              "no ruleset: open");

    commit();
    mfw_check(mfw_tc(.src = "10.0.0.1", .dst = "10.0.0.5", MFW_TCP,
                     .dport = 22) == TC_ACT_UNSPEC,
              "ruleset with nothing bound: open");
}


static void
test_standard(void)
{
    reset();
    add("10 deny host 10.0.0.1");
    add("10 permit 10.0.0.0 0.0.0.255");
    add("10 deny 10.0.0.0/8");
    commit();

    mfw_check(mfw_tc(.src = "10.0.0.1", .dst = "1.1.1.1", MFW_UDP)
              == TC_ACT_SHOT, "explicit deny");
    mfw_check(mfw_tc(.src = "10.0.0.2", .dst = "1.1.1.1", MFW_UDP)
              == TC_ACT_UNSPEC, "earlier permit wins");
    mfw_check(mfw_tc(.src = "10.9.0.2", .dst = "1.1.1.1", MFW_UDP)
              == TC_ACT_SHOT, "later deny");
    mfw_check(mfw_tc(.src = "192.168.1.1", .dst = "1.1.1.1", MFW_UDP)
              == TC_ACT_UNSPEC, "miss → pass (blacklist)");
    mfw_check(mfw_tc(.src = "10.0.0.1", .dst = "1.1.1.1", .proto = 47)
              == TC_ACT_SHOT, "std matches any proto");
    mfw_check(mfw_tc(.src = "10.0.0.1", .dst = "1.1.1.1", MFW_UDP,
                     .vlans = 1) == TC_ACT_SHOT, "802.1Q peel");
    mfw_check(mfw_tc(.src = "10.0.0.1", .dst = "1.1.1.1", MFW_UDP,
                     .vlans = 2) == TC_ACT_SHOT, "QinQ peel");
    mfw_check(mfw_tc(.src = "10.0.0.1", .dst = "1.1.1.1", MFW_UDP,
                     .vlans = 3) == TC_ACT_UNSPEC,
              ">2 tags → non-IPv4 pass");
    mfw_check(mfw_tc(.ethertype = ETH_P_ARP) == TC_ACT_UNSPEC, "ARP pass");
    mfw_check(mfw_tc(.ethertype = ETH_P_ARP, .vlans = 1) == TC_ACT_UNSPEC,
              "tagged ARP pass");
    mfw_check(mfw_tc(.ethertype = ETH_P_IPV6) == TC_ACT_UNSPEC,
              "IPv6 pass");
    mfw_check(mfw_tc(.src = "10.0.0.1", .dst = "1.1.1.1", MFW_UDP,
                     .frag_off = 100) == TC_ACT_SHOT,
              "non-first frag still matches saddr");
}


static void
test_extended(void)
{
    reset();
    add("100 deny tcp host 10.0.0.66 any eq 22");
    add("100 permit tcp any host 10.0.0.5 eq 22");
    add("100 permit udp any eq 53 any");
    add("100 permit icmp any any");
    commit();

    mfw_check(mfw_tc(.src = "1.2.3.4", .dst = "10.0.0.5", MFW_TCP,
                     .sport = 40000, .dport = 22) == TC_ACT_UNSPEC,
              "ssh ok");
    mfw_check(mfw_tc(.src = "10.0.0.66", .dst = "10.0.0.5", MFW_TCP,
                     .sport = 40000, .dport = 22) == TC_ACT_SHOT,
              "deny before permit");
    mfw_check(mfw_tc(.src = "1.2.3.4", .dst = "10.0.0.5", MFW_TCP,
                     .sport = 40000, .dport = 23) == TC_ACT_SHOT,
              "implicit deny");
    mfw_check(mfw_tc(.src = "1.2.3.4", .dst = "10.0.0.6", MFW_TCP,
                     .sport = 40000, .dport = 22) == TC_ACT_SHOT,
              "wrong dst");
    mfw_check(mfw_tc(.src = "8.8.8.8", .dst = "10.0.0.5", MFW_UDP,
                     .sport = 53, .dport = 5555) == TC_ACT_UNSPEC,
              "dns reply by sport");
    mfw_check(mfw_tc(.src = "8.8.8.8", .dst = "10.0.0.5",
                     .proto = IPPROTO_ICMP) == TC_ACT_UNSPEC, "icmp");
    mfw_check(mfw_tc(.src = "8.8.8.8", .dst = "10.0.0.5", .proto = 47)
              == TC_ACT_SHOT, "gre implicit deny");
    mfw_check(mfw_tc(.src = "1.2.3.4", .dst = "10.0.0.5", MFW_TCP,
                     .dport = 22, .vlans = 2) == TC_ACT_UNSPEC,
              "QinQ + extended");

    /* empty bound list = implicit deny only */
    reset();
    mfw_rs.ext_acl = 101;
    commit();

    mfw_check(mfw_tc(.src = "1.2.3.4", .dst = "10.0.0.5",
                     .proto = IPPROTO_ICMP) == TC_ACT_SHOT,
              "empty bound ext list denies");
}


/* Both lists bound: standard deny is final; otherwise extended decides. */
static void
test_combined(void)
{
    reset();
    add("10 deny host 203.0.113.66");
    add("10 permit 203.0.113.0 0.0.0.255");
    add("100 permit tcp any any eq 22");
    commit();

    mfw_check(mfw_tc(.src = "203.0.113.66", .dst = "10.0.0.5", MFW_TCP,
                     .dport = 22) == TC_ACT_SHOT,
              "std deny beats ext permit");
    mfw_check(mfw_tc(.src = "203.0.113.7", .dst = "10.0.0.5", MFW_TCP,
                     .dport = 80) == TC_ACT_SHOT,
              "std permit does not bypass ext implicit deny");
    mfw_check(mfw_tc(.src = "203.0.113.7", .dst = "10.0.0.5", MFW_TCP,
                     .dport = 22) == TC_ACT_UNSPEC,
              "std permit then ext permit");
    mfw_check(mfw_tc(.src = "198.51.100.1", .dst = "10.0.0.5", MFW_TCP,
                     .dport = 22) == TC_ACT_UNSPEC,
              "std miss then ext permit");
}


static void
test_established(void)
{
    reset();
    add("100 permit tcp any any established");
    commit();

    mfw_check(mfw_tc(.src = "1.1.1.1", .dst = "2.2.2.2", MFW_TCP,
                     .tcp_flags = 0x02) == TC_ACT_SHOT, "SYN blocked");
    mfw_check(mfw_tc(.src = "1.1.1.1", .dst = "2.2.2.2", MFW_TCP,
                     .tcp_flags = 0x12) == TC_ACT_UNSPEC, "SYN-ACK ok");
    mfw_check(mfw_tc(.src = "1.1.1.1", .dst = "2.2.2.2", MFW_TCP,
                     .tcp_flags = 0x10) == TC_ACT_UNSPEC, "ACK ok");
    mfw_check(mfw_tc(.src = "1.1.1.1", .dst = "2.2.2.2", MFW_TCP,
                     .tcp_flags = 0x04) == TC_ACT_UNSPEC, "RST ok");
}


/*
 * bpf_ktime_get_coarse_ns()'s clock, which sw_flowd and mfw_tc read: a
 * last_seen from the fine one could be ahead of mfw_tc's now.
 */
static __u64
now_ns(void)
{
    struct timespec  ts;

    clock_gettime(CLOCK_MONOTONIC_COARSE, &ts);

    return ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}


/*
 * A flow the host opened, as sw_flowd records it: to raddr:rport from
 * lport, last out ago_s seconds ago, in the close state state.
 */
static void
flow_add_state(int table, __u8 proto, const char *raddr, __u16 rport,
    __u16 lport, __u64 ago_s, __u64 state)
{
    __be32               a;
    struct sf_flow       f = {};
    struct sf_flow_key   k = {};

    k.family = SF_FAMILY_V4;
    k.protocol = proto;
    k.rport = htons(rport);
    k.lport = htons(lport);

    a = inet_addr(raddr);
    memcpy(k.raddr, &a, 4);

    f.last_seen = ((now_ns() - ago_s * 1000000000ULL) & ~SF_STATE_MASK)
                  | state;

    if (bpf_map_update_elem(table, &k, &f, BPF_ANY) != 0) {
        perror("flow_add");
        mfw_failures++;
    }
}


/* an open flow: flow_add_state()'s */
static void
flow_add(int table, __u8 proto, const char *raddr, __u16 rport,
    __u16 lport, __u64 ago_s)
{
    flow_add_state(table, proto, raddr, rport, lport, ago_s, SF_STATE_OPEN);
}


/* Empties sw_flowd's table: the flows one test added. */
static void
flows_clear(int table)
{
    struct sf_flow_key  k, next;

    while (bpf_map_get_next_key(table, NULL, &next) == 0) {
        k = next;
        bpf_map_delete_elem(table, &k);
    }
}


/* mini-fw's config with no_flow_table, as mfwd sets it without the table */
static void
set_no_flow_table(int on)
{
    __u32              k = 0;
    struct mfw_config  cfg;

    bpf_map_lookup_elem(bpf_map__fd(mfw_skel->maps.config), &k, &cfg);
    cfg.no_flow_table = on;
    bpf_map_update_elem(bpf_map__fd(mfw_skel->maps.config), &k, &cfg,
                        BPF_ANY);
}


/*
 * Replies to flows in sw_flowd's table pass before the extended list,
 * with no rule (Seawall proposal 0015 §4): within the idle limits, after
 * the standard list, not stopped by the extended list's denies. Echo
 * replies, and ICMP errors about the host's packets; path MTU errors
 * without a flow too. Without the table, TCP with ACK or RST passes.
 */
static void
test_reply(void)
{
    int    table;
    __u64  before;

    table = mfw_flows_table;

    /* who may connect in, and nothing else: the host's SSH */
    reset();
    add("100 permit tcp any host 10.0.0.5 eq 22");
    commit();

    mfw_check(mfw_tc(.src = "1.1.1.1", .dst = "10.0.0.5", MFW_TCP,
                     .sport = 443, .dport = 40000, .tcp_flags = 0x10)
              == TC_ACT_SHOT, "empty table: no reply");
    mfw_check(mfw_tc(.src = "1.1.1.9", .dst = "10.0.0.5", MFW_TCP,
                     .sport = 50000, .dport = 22, .tcp_flags = 0x02)
              == TC_ACT_UNSPEC, "the extended list still lets SSH in");

    flow_add(table, IPPROTO_TCP, "1.1.1.1", 443, 40000, 0);
    flow_add(table, IPPROTO_TCP, "1.1.1.2", 443, 40001, 7200);  /* idle 2 h */
    flow_add(table, IPPROTO_UDP, "8.8.8.8", 53, 50000, 10);
    flow_add(table, IPPROTO_UDP, "8.8.4.4", 53, 50001, 120);    /* 2 min */

    before = stat(MFW_STAT_REPLY);

    mfw_check(mfw_tc(.src = "1.1.1.1", .dst = "10.0.0.5", MFW_TCP,
                     .sport = 443, .dport = 40000, .tcp_flags = 0x12)
              == TC_ACT_UNSPEC, "SYN-ACK of a flow the host opened");
    mfw_check(stat(MFW_STAT_REPLY) > before, "counted as a reply");
    mfw_check(mfw_tc(.src = "1.1.1.1", .dst = "10.0.0.5", MFW_TCP,
                     .sport = 443, .dport = 40000, .tcp_flags = 0x10)
              == TC_ACT_UNSPEC, "ACK of it");
    mfw_check(mfw_tc(.src = "1.1.1.1", .dst = "10.0.0.5", MFW_TCP,
                     .sport = 443, .dport = 40000, .tcp_flags = 0x04)
              == TC_ACT_UNSPEC, "RST of it");
    mfw_check(mfw_tc(.src = "1.1.1.1", .dst = "10.0.0.5", MFW_TCP,
                     .sport = 443, .dport = 40000, .tcp_flags = 0x02)
              == TC_ACT_SHOT, "a SYN is no reply");
    mfw_check(mfw_tc(.src = "1.1.1.1", .dst = "10.0.0.5", MFW_TCP,
                     .sport = 443, .dport = 40002, .tcp_flags = 0x10)
              == TC_ACT_SHOT, "an ACK flood: ACK to another local port");
    mfw_check(mfw_tc(.src = "1.1.1.1", .dst = "10.0.0.5", MFW_TCP,
                     .sport = 444, .dport = 40000, .tcp_flags = 0x10)
              == TC_ACT_SHOT, "ACK from another remote port");
    mfw_check(mfw_tc(.src = "1.1.1.3", .dst = "10.0.0.5", MFW_TCP,
                     .sport = 443, .dport = 40000, .tcp_flags = 0x10)
              == TC_ACT_SHOT, "ACK from another address");
    mfw_check(mfw_tc(.src = "1.1.1.2", .dst = "10.0.0.5", MFW_TCP,
                     .sport = 443, .dport = 40001, .tcp_flags = 0x10)
              == TC_ACT_SHOT, "a flow idle past reply-idle-tcp");
    mfw_check(mfw_tc(.src = "8.8.8.8", .dst = "10.0.0.5", MFW_UDP,
                     .sport = 53, .dport = 50000)
              == TC_ACT_UNSPEC, "UDP reply");
    mfw_check(mfw_tc(.src = "8.8.8.8", .dst = "10.0.0.5", MFW_UDP,
                     .sport = 53, .dport = 50001)
              == TC_ACT_SHOT, "UDP to another local port");
    mfw_check(mfw_tc(.src = "8.8.4.4", .dst = "10.0.0.5", MFW_UDP,
                     .sport = 53, .dport = 50001)
              == TC_ACT_SHOT, "a UDP flow idle past reply-idle-udp");
    mfw_check(mfw_tc(.src = "1.1.1.1", .dst = "10.0.0.5", MFW_UDP,
                     .sport = 443, .dport = 40000)
              == TC_ACT_SHOT, "UDP doesn't match a TCP flow");

    /* UDP is a reply only to a port in the ephemeral range */
    flow_add(table, IPPROTO_UDP, "8.8.8.8", 53, 1000, 0);
    mfw_check(mfw_tc(.src = "8.8.8.8", .dst = "10.0.0.5", MFW_UDP,
                     .sport = 53, .dport = 1000)
              == TC_ACT_SHOT, "UDP to a port outside the range");

    /* a flow the host closed: SF_FIN_NS after a FIN, SF_RST_NS after RST */
    flow_add_state(table, IPPROTO_TCP, "1.1.1.4", 443, 40010, 60,
                   SF_STATE_FIN);
    flow_add_state(table, IPPROTO_TCP, "1.1.1.4", 443, 40011, 130,
                   SF_STATE_FIN);
    flow_add_state(table, IPPROTO_TCP, "1.1.1.4", 443, 40012, 5,
                   SF_STATE_RST);
    flow_add_state(table, IPPROTO_TCP, "1.1.1.4", 443, 40013, 15,
                   SF_STATE_RST);
    mfw_check(mfw_tc(.src = "1.1.1.4", .dst = "10.0.0.5", MFW_TCP,
                     .sport = 443, .dport = 40010, .tcp_flags = 0x11)
              == TC_ACT_UNSPEC, "60 s after the host's FIN");
    mfw_check(mfw_tc(.src = "1.1.1.4", .dst = "10.0.0.5", MFW_TCP,
                     .sport = 443, .dport = 40011, .tcp_flags = 0x10)
              == TC_ACT_SHOT, "130 s after it");
    mfw_check(mfw_tc(.src = "1.1.1.4", .dst = "10.0.0.5", MFW_TCP,
                     .sport = 443, .dport = 40012, .tcp_flags = 0x10)
              == TC_ACT_UNSPEC, "5 s after the host's RST");
    mfw_check(mfw_tc(.src = "1.1.1.4", .dst = "10.0.0.5", MFW_TCP,
                     .sport = 443, .dport = 40013, .tcp_flags = 0x10)
              == TC_ACT_SHOT, "15 s after it");

    /* echo replies to the host's identifier; a ping in is the lists' */
    flow_add(table, IPPROTO_ICMP, "1.1.1.5", 0, 0x77, 0);
    mfw_check(mfw_tc(.src = "1.1.1.5", .dst = "10.0.0.5", MFW_ICMP,
                     .echo_reply = 1, .icmp_id = 0x77)
              == TC_ACT_UNSPEC, "echo reply to the host's ping");
    mfw_check(mfw_tc(.src = "1.1.1.5", .dst = "10.0.0.5", MFW_ICMP,
                     .echo_reply = 1, .icmp_id = 0x78)
              == TC_ACT_SHOT, "echo reply with another identifier");
    mfw_check(mfw_tc(.src = "1.1.1.5", .dst = "10.0.0.5", MFW_ICMP,
                     .icmp_type = 8, .icmp_id = 0x77)
              == TC_ACT_SHOT, "a ping in: no ICMP permit");

    /* ICMP errors about the host's packets, from a router */
    mfw_check(mfw_tc(.src = "9.9.9.9", .dst = "10.0.0.5", MFW_ICMP,
                     .icmp_type = 3, .icmp_code = 4,
                     .in_src = "10.0.0.5", .in_dst = "1.1.1.1",
                     .in_proto = IPPROTO_TCP, .in_sport = 40000,
                     .in_dport = 443)
              == TC_ACT_UNSPEC, "frag needed about a flow");
    mfw_check(mfw_tc(.src = "9.9.9.9", .dst = "10.0.0.5", MFW_ICMP,
                     .icmp_type = 3, .icmp_code = 4,
                     .in_src = "10.0.0.5", .in_dst = "1.1.1.9",
                     .in_proto = IPPROTO_TCP, .in_sport = 22,
                     .in_dport = 50000)
              == TC_ACT_UNSPEC,
              "frag needed with no flow: an accepted connection's");
    mfw_check(mfw_tc(.src = "9.9.9.9", .dst = "10.0.0.5", MFW_ICMP,
                     .icmp_type = 3, .icmp_code = 4,
                     .in_src = "10.0.0.6", .in_dst = "1.1.1.1",
                     .in_proto = IPPROTO_TCP, .in_sport = 40000,
                     .in_dport = 443)
              == TC_ACT_SHOT, "frag needed about another host's packet");
    mfw_check(mfw_tc(.src = "9.9.9.9", .dst = "10.0.0.5", MFW_ICMP,
                     .icmp_type = 3, .icmp_code = 3,
                     .in_src = "10.0.0.5", .in_dst = "8.8.8.8",
                     .in_proto = IPPROTO_UDP, .in_sport = 50000,
                     .in_dport = 53)
              == TC_ACT_UNSPEC, "port unreachable about a UDP flow");
    mfw_check(mfw_tc(.src = "9.9.9.9", .dst = "10.0.0.5", MFW_ICMP,
                     .icmp_type = 3, .icmp_code = 3,
                     .in_src = "10.0.0.5", .in_dst = "8.8.8.8",
                     .in_proto = IPPROTO_UDP, .in_sport = 50099,
                     .in_dport = 53)
              == TC_ACT_SHOT, "port unreachable with no flow");
    mfw_check(mfw_tc(.src = "9.9.9.9", .dst = "10.0.0.5", MFW_ICMP,
                     .icmp_type = 11, .icmp_code = 0,
                     .in_src = "10.0.0.5", .in_dst = "1.1.1.5",
                     .in_proto = IPPROTO_ICMP, .in_sport = 0x77)
              == TC_ACT_UNSPEC, "time exceeded about the host's ping");
    mfw_check(mfw_tc(.src = "9.9.9.9", .dst = "10.0.0.5", MFW_ICMP,
                     .icmp_type = 3, .icmp_code = 1,
                     .in_src = "10.0.0.5", .in_dst = "1.1.1.2",
                     .in_proto = IPPROTO_TCP, .in_sport = 40001,
                     .in_dport = 443)
              == TC_ACT_SHOT, "host unreachable about a flow past its limit");

    /* a reply counts one reason: reply, not the extended list's */
    {
        __u64  permit = stat(MFW_STAT_EXT_PERMIT);
        __u64  deny = stat(MFW_STAT_EXT_IMPLICIT_DENY);
        __u64  reply = stat(MFW_STAT_REPLY);

        mfw_check(mfw_tc(.src = "1.1.1.1", .dst = "10.0.0.5", MFW_TCP,
                         .sport = 443, .dport = 40000, .tcp_flags = 0x10)
                  == TC_ACT_UNSPEC, "a reply");
        /* run() counts the TC run only: it restores XDP's */
        mfw_check(stat(MFW_STAT_REPLY) == reply + 1
                  && stat(MFW_STAT_EXT_PERMIT) == permit
                  && stat(MFW_STAT_EXT_IMPLICIT_DENY) == deny,
                  "counted as a reply only: %llu %llu %llu",
                  (unsigned long long) (stat(MFW_STAT_REPLY) - reply),
                  (unsigned long long) (stat(MFW_STAT_EXT_PERMIT) - permit),
                  (unsigned long long) (stat(MFW_STAT_EXT_IMPLICIT_DENY)
                                        - deny));
    }

    /* the standard list's denies stop replies; the extended list's don't */
    reset();
    add("10 deny host 1.1.1.1");
    add("100 permit tcp any host 10.0.0.5 eq 22");
    commit();

    mfw_check(mfw_tc(.src = "1.1.1.1", .dst = "10.0.0.5", MFW_TCP,
                     .sport = 443, .dport = 40000, .tcp_flags = 0x10)
              == TC_ACT_SHOT, "a blacklisted address's replies");

    reset();
    add("10 deny host 9.9.9.9");
    add("100 permit tcp any host 10.0.0.5 eq 22");
    commit();

    mfw_check(mfw_tc(.src = "9.9.9.9", .dst = "10.0.0.5", MFW_ICMP,
                     .icmp_type = 3, .icmp_code = 4,
                     .in_src = "10.0.0.5", .in_dst = "1.1.1.1",
                     .in_proto = IPPROTO_TCP, .in_sport = 40000,
                     .in_dport = 443)
              == TC_ACT_SHOT, "an error from a blacklisted router");

    reset();
    add("100 deny ip host 1.1.1.1 any");
    add("100 permit tcp any host 10.0.0.5 eq 22");
    commit();

    mfw_check(mfw_tc(.src = "1.1.1.1", .dst = "10.0.0.5", MFW_TCP,
                     .sport = 443, .dport = 40000, .tcp_flags = 0x10)
              == TC_ACT_UNSPEC, "an extended deny doesn't stop replies");

    /* a DHCP server's answers pass with no flow, unicast or broadcast */
    reset();
    add("10 deny host 9.9.9.8");
    add("100 permit tcp any host 10.0.0.5 eq 22");
    commit();

    {
        __u64  dhcp = stat(MFW_STAT_REPLY_DHCP);
        __u64  reply = stat(MFW_STAT_REPLY);

        mfw_check(mfw_tc(.src = "10.0.0.1", .dst = "10.0.0.5", MFW_UDP,
                         .sport = 67, .dport = 68)
                  == TC_ACT_UNSPEC, "dhcp: a server's unicast answer");
        mfw_check(mfw_tc(.src = "10.0.0.1", .dst = "255.255.255.255",
                         MFW_UDP, .sport = 67, .dport = 68)
                  == TC_ACT_UNSPEC, "dhcp: a broadcast answer");
        mfw_check(stat(MFW_STAT_REPLY_DHCP) == dhcp + 2
                  && stat(MFW_STAT_REPLY) == reply,
                  "dhcp: counted as reply_dhcp only");
    }

    mfw_check(mfw_tc(.src = "10.0.0.1", .dst = "10.0.0.5", MFW_UDP,
                     .sport = 66, .dport = 68)
              == TC_ACT_SHOT, "dhcp: not from 67");
    mfw_check(mfw_tc(.src = "10.0.0.1", .dst = "10.0.0.5", MFW_UDP,
                     .sport = 67, .dport = 69)
              == TC_ACT_SHOT, "dhcp: not to 68");
    mfw_check(mfw_tc(.src = "10.0.0.1", .dst = "10.0.0.5", MFW_UDP,
                     .sport = 68, .dport = 67)
              == TC_ACT_SHOT, "dhcp: a client's request in");
    mfw_check(mfw_tc(.src = "10.0.0.1", .dst = "10.0.0.5", MFW_TCP,
                     .sport = 67, .dport = 68, .tcp_flags = 0x02)
              == TC_ACT_SHOT, "dhcp: TCP from 67 to 68");
    mfw_check(mfw_tc(.src = "9.9.9.8", .dst = "10.0.0.5", MFW_UDP,
                     .sport = 67, .dport = 68)
              == TC_ACT_SHOT, "dhcp: a blacklisted server's");

    /* no extended list: everything passes, and nothing is looked up */
    reset();
    commit();
    before = stat(MFW_STAT_REPLY);

    mfw_check(mfw_tc(.src = "1.1.1.1", .dst = "10.0.0.5", MFW_TCP,
                     .sport = 443, .dport = 40000, .tcp_flags = 0x10)
              == TC_ACT_UNSPEC, "no extended list: passes");
    mfw_check(stat(MFW_STAT_REPLY) == before, "and isn't looked up");

    /* an extended list bound with no entry yet: replies only */
    reset();
    mfw_rs.ext_acl = 100;
    commit();

    mfw_check(mfw_tc(.src = "1.1.1.1", .dst = "10.0.0.5", MFW_TCP,
                     .sport = 443, .dport = 40000, .tcp_flags = 0x10)
              == TC_ACT_UNSPEC, "an empty extended list: a reply passes");
    mfw_check(mfw_tc(.src = "1.1.1.1", .dst = "10.0.0.5", MFW_TCP,
                     .sport = 443, .dport = 22, .tcp_flags = 0x02)
              == TC_ACT_SHOT, "and nothing else");

    /* without sw_flowd's table: "established", TCP only */
    reset();
    add("100 permit tcp any host 10.0.0.5 eq 22");
    commit();
    set_no_flow_table(1);
    before = stat(MFW_STAT_REPLY_ESTABLISHED);

    {
        __u64  permit = stat(MFW_STAT_EXT_PERMIT);
        __u64  deny = stat(MFW_STAT_EXT_IMPLICIT_DENY);

        mfw_check(mfw_tc(.src = "1.1.1.7", .dst = "10.0.0.5", MFW_TCP,
                         .sport = 443, .dport = 40020, .tcp_flags = 0x10)
                  == TC_ACT_UNSPEC, "no table: an ACK passes");
        mfw_check(stat(MFW_STAT_REPLY_ESTABLISHED) == before + 1
                  && stat(MFW_STAT_EXT_PERMIT) == permit
                  && stat(MFW_STAT_EXT_IMPLICIT_DENY) == deny,
                  "counted as established only");
    }
    mfw_check(mfw_tc(.src = "1.1.1.7", .dst = "10.0.0.5", MFW_TCP,
                     .sport = 443, .dport = 40020, .tcp_flags = 0x04)
              == TC_ACT_UNSPEC, "no table: a RST passes");
    mfw_check(mfw_tc(.src = "1.1.1.7", .dst = "10.0.0.5", MFW_TCP,
                     .sport = 443, .dport = 40020, .tcp_flags = 0x02)
              == TC_ACT_SHOT, "no table: a SYN doesn't");
    /* path MTU errors need no table: they still pass */
    mfw_check(mfw_tc(.src = "9.9.9.9", .dst = "10.0.0.5", MFW_ICMP,
                     .icmp_type = 3, .icmp_code = 4,
                     .in_src = "10.0.0.5", .in_dst = "1.1.1.9",
                     .in_proto = IPPROTO_TCP, .in_sport = 22,
                     .in_dport = 50000)
              == TC_ACT_UNSPEC, "no table: frag needed still passes");
    mfw_check(mfw_tc(.src = "9.9.9.9", .dst = "10.0.0.5", MFW_ICMP,
                     .icmp_type = 3, .icmp_code = 4,
                     .in_src = "10.0.0.6", .in_dst = "1.1.1.9",
                     .in_proto = IPPROTO_TCP, .in_sport = 22,
                     .in_dport = 50000)
              == TC_ACT_SHOT, "no table: frag needed about another host's");
    mfw_check(mfw_tc(.src = "9.9.9.9", .dst = "10.0.0.5", MFW_ICMP,
                     .icmp_type = 3, .icmp_code = 3,
                     .in_src = "10.0.0.5", .in_dst = "8.8.8.8",
                     .in_proto = IPPROTO_UDP, .in_sport = 50000,
                     .in_dport = 53)
              == TC_ACT_SHOT, "no table: other errors go to the lists");
    mfw_check(mfw_tc(.src = "1.1.1.5", .dst = "10.0.0.5", MFW_ICMP,
                     .echo_reply = 1, .icmp_id = 0x77)
              == TC_ACT_SHOT, "no table: an echo reply goes to the lists");
    mfw_check(mfw_tc(.src = "8.8.8.8", .dst = "10.0.0.5", MFW_UDP,
                     .sport = 53, .dport = 50000)
              == TC_ACT_SHOT, "no table: UDP goes to the lists");
    mfw_check(mfw_tc(.src = "10.0.0.1", .dst = "255.255.255.255", MFW_UDP,
                     .sport = 67, .dport = 68)
              == TC_ACT_UNSPEC, "no table: DHCP still passes");

    set_no_flow_table(0);
    flows_clear(table);
}


/* The newest reply_miss sample, from every CPU's ring; 0 if none. */
static int
miss_newest(struct mfw_miss_sample *out)
{
    int                 c, i, ncpu;
    __u32               k = 0;
    struct mfw_misses  *r;

    ncpu = libbpf_num_possible_cpus();
    r = calloc(ncpu, sizeof(*r));

    if (r == NULL
        || bpf_map_lookup_elem(bpf_map__fd(mfw_skel->maps.misses), &k, r) != 0)
    {
        free(r);
        return 0;
    }

    memset(out, 0, sizeof(*out));

    for (c = 0; c < ncpu; c++) {
        for (i = 0; i < MFW_MISS_SAMPLES; i++) {
            if (r[c].s[i].time_ns > out->time_ns) {
                *out = r[c].s[i];
            }
        }
    }

    free(r);

    return out->time_ns != 0;
}


/*
 * reply_miss (Seawall proposal 0015 §7): a packet that looks like a reply
 * finds no flow and the extended list drops it: counted and sampled.
 * What doesn't look like one, or passes, isn't.
 */
static void
test_reply_miss(void)
{
    __u64                   miss;
    struct mfw_miss_sample  s;

    reset();
    add("100 permit tcp any host 10.0.0.5 eq 22");
    add("100 permit udp any any eq 5353");
    add("100 deny ip host 1.1.1.66 any");
    commit();

#define MISSED(want, desc, ...)                                            \
    do {                                                                   \
        miss = stat(MFW_STAT_REPLY_MISS);                                  \
        mfw_tc(__VA_ARGS__);                                               \
        mfw_check(stat(MFW_STAT_REPLY_MISS) - miss == (want), "%s", desc);  \
    } while (0)

    MISSED(1, "a bare ACK with no flow", .src = "1.1.1.7", .dst = "10.0.0.5",
           MFW_TCP, .sport = 443, .dport = 40007, .tcp_flags = 0x10);
    mfw_check(miss_newest(&s) && s.proto == IPPROTO_TCP
              && s.saddr == inet_addr("1.1.1.7")
              && s.daddr == inet_addr("10.0.0.5")
              && ntohs(s.sport) == 443 && ntohs(s.dport) == 40007
              && s.tcp_flags == 0x10 && s.ifindex == mfw_if0,
              "and sampled: addresses, ports, flags, interface");
    MISSED(1, "a RST", .src = "1.1.1.7", .dst = "10.0.0.5", MFW_TCP,
           .sport = 443, .dport = 40007, .tcp_flags = 0x04);
    MISSED(1, "dropped by an extended deny too", .src = "1.1.1.66",
           .dst = "10.0.0.5", MFW_TCP, .sport = 443, .dport = 40007,
           .tcp_flags = 0x10);
    MISSED(0, "a SYN doesn't look like a reply", .src = "1.1.1.7",
           .dst = "10.0.0.5", MFW_TCP, .sport = 443, .dport = 40007,
           .tcp_flags = 0x02);
    MISSED(1, "UDP to an ephemeral port", .src = "8.8.8.8", .dst = "10.0.0.5",
           MFW_UDP, .sport = 53, .dport = 50099);
    MISSED(1, "UDP to a recorded port", .src = "8.8.8.8", .dst = "10.0.0.5",
           MFW_UDP, .sport = 123, .dport = 123);
    MISSED(0, "UDP to another port doesn't", .src = "8.8.8.8",
           .dst = "10.0.0.5", MFW_UDP, .sport = 53, .dport = 5000);
    MISSED(1, "an echo reply", .src = "1.1.1.5", .dst = "10.0.0.5", MFW_ICMP,
           .echo_reply = 1, .icmp_id = 0x99);
    mfw_check(miss_newest(&s) && s.proto == IPPROTO_ICMP
              && s.icmp_type == 0 && s.sport == 0,
              "sampled with its ICMP type");
    MISSED(1, "an ICMP error about no flow", .src = "9.9.9.9",
           .dst = "10.0.0.5", MFW_ICMP, .icmp_type = 3, .icmp_code = 3,
           .in_src = "10.0.0.5", .in_dst = "8.8.8.8",
           .in_proto = IPPROTO_UDP, .in_sport = 50098, .in_dport = 53);
    MISSED(0, "a ping in doesn't", .src = "1.1.1.5", .dst = "10.0.0.5",
           MFW_ICMP, .icmp_type = 8, .icmp_id = 0x99);
    MISSED(0, "one the list permits isn't a miss", .src = "8.8.8.8",
           .dst = "10.0.0.5", MFW_UDP, .sport = 53, .dport = 5353);

    /* no extended list: nothing is dropped, nothing missed */
    reset();
    commit();
    MISSED(0, "no extended list", .src = "1.1.1.7", .dst = "10.0.0.5",
           MFW_TCP, .sport = 443, .dport = 40007, .tcp_flags = 0x10);

    /* without the table: UDP by Linux's default range */
    reset();
    add("100 permit tcp any host 10.0.0.5 eq 22");
    commit();
    set_no_flow_table(1);
    MISSED(1, "no table: UDP to an ephemeral port", .src = "8.8.8.8",
           .dst = "10.0.0.5", MFW_UDP, .sport = 53, .dport = 50000);
    MISSED(0, "no table: an ACK passes as established", .src = "1.1.1.7",
           .dst = "10.0.0.5", MFW_TCP, .sport = 443, .dport = 40007,
           .tcp_flags = 0x10);
    set_no_flow_table(0);

#undef MISSED
}


static void
test_fragments(void)
{
    __u32              k;
    __u64              off1;
    struct mfw_config  cfg = {};

    reset();
    add("10 deny host 6.6.6.6");
    add("100 deny udp any any eq 53");
    add("100 permit udp any any eq 4789");
    commit();

    mfw_check(mfw_tc(.src = "1.1.1.1", .dst = "2.2.2.2", MFW_UDP,
                     .dport = 4789, .frag_off = 0x2000) == TC_ACT_UNSPEC,
              "first frag has ports");
    mfw_check(mfw_tc(.src = "1.1.1.1", .dst = "2.2.2.2", MFW_UDP,
                     .dport = 53, .frag_off = 0x2000) == TC_ACT_SHOT,
              "first frag hits a port deny");
    mfw_check(mfw_tc(.src = "1.1.1.1", .dst = "2.2.2.2", MFW_UDP,
                     .dport = 80, .frag_off = 0x2000) == TC_ACT_SHOT,
              "first frag hits the implicit deny");
    mfw_check(mfw_tc(.src = "1.1.1.1", .dst = "2.2.2.2", MFW_UDP,
                     .frag_off = 185) == TC_ACT_UNSPEC,
              "non-first frag skips the extended list");
    mfw_check(mfw_tc(.src = "1.1.1.1", .dst = "2.2.2.2", .proto = 47,
                     .frag_off = 185) == TC_ACT_UNSPEC,
              "non-first frag of any protocol skips it");
    mfw_check(mfw_tc(.src = "6.6.6.6", .dst = "2.2.2.2", MFW_UDP,
                     .frag_off = 185) == TC_ACT_SHOT,
              "non-first frag still hits a standard deny");
    mfw_check(mfw_tc(.src = "6.6.6.6", .dst = "2.2.2.2", MFW_UDP,
                     .dport = 4789, .frag_off = 0x2000) == TC_ACT_SHOT,
              "first frag hits a standard deny");

    off1 = stat(MFW_STAT_TCP_FRAG_OFF1);

    mfw_check(mfw_tc(.src = "4.4.4.4", .dst = "2.2.2.2", MFW_TCP,
                     .frag_off = 1) == TC_ACT_SHOT,
              "TCP frag at offset 1 dropped");
    mfw_check(mfw_tc(.src = "4.4.4.4", .dst = "2.2.2.2", MFW_TCP,
                     .frag_off = 0x2001) == TC_ACT_SHOT,
              "TCP frag at offset 1 with MF dropped");
    mfw_check(stat(MFW_STAT_TCP_FRAG_OFF1) == off1 + 2,
              "tcp_frag_off1 counted");
    mfw_check(mfw_tc(.src = "4.4.4.4", .dst = "2.2.2.2", MFW_TCP,
                     .frag_off = 2) == TC_ACT_UNSPEC,
              "TCP frag at offset 2 passes");
    mfw_check(mfw_tc(.src = "4.4.4.4", .dst = "2.2.2.2", MFW_UDP,
                     .frag_off = 1) == TC_ACT_UNSPEC,
              "UDP frag at offset 1 passes");

    cfg.abi_version = MFW_ABI_VERSION;
    cfg.drop_ipv4_fragments = 1;
    k = 0;

    bpf_map_update_elem(bpf_map__fd(mfw_skel->maps.config), &k, &cfg,
                        BPF_ANY);

    mfw_check(mfw_tc(.src = "1.1.1.1", .dst = "2.2.2.2", MFW_UDP,
                     .frag_off = 0x2000) == TC_ACT_SHOT,
              "strict: first frag");
    mfw_check(mfw_tc(.src = "1.1.1.1", .dst = "2.2.2.2", MFW_UDP,
                     .frag_off = 185) == TC_ACT_SHOT,
              "strict: non-first frag");
    mfw_check(mfw_tc(.src = "1.1.1.1", .dst = "2.2.2.2", MFW_UDP,
                     .dport = 4789) == TC_ACT_UNSPEC,
              "strict: unfragmented ok");
}


static void
test_full_tables(void)
{
    int   i;
    char  line[96];

    reset();

    for (i = 0; i < MFW_MAX_STD_ACES - 1; i++) {
        snprintf(line, sizeof(line), "10 permit host 172.16.0.%d", i + 1);
        add(line);
    }

    add("10 deny host 192.0.2.1");

    for (i = 0; i < MFW_MAX_EXT_ACES - 1; i++) {
        snprintf(line, sizeof(line), "100 permit tcp any any eq %d", 1000 + i);
        add(line);
    }

    add("100 permit tcp any any eq 9");
    commit();

    mfw_check(mfw_tc(.src = "192.0.2.1", .dst = "1.1.1.1", MFW_UDP)
              == TC_ACT_SHOT, "64th std ACE");
    mfw_check(mfw_tc(.src = "1.1.1.1", .dst = "2.2.2.2", MFW_TCP,
                     .dport = 9) == TC_ACT_UNSPEC, "128th ext ACE");
    mfw_check(mfw_tc(.src = "1.1.1.1", .dst = "2.2.2.2", MFW_TCP,
                     .dport = 10) == TC_ACT_SHOT,
              "past the 128th: implicit deny");
}


/* Each interface is judged by its own lists; others are untouched. */
static void
test_per_interface(void)
{
    reset();
    add("100 permit tcp any any eq 22");
    commit_on(mfw_if0);

    memset(&mfw_rs, 0, sizeof(mfw_rs));
    add("10 deny host 192.0.2.9");
    commit_on(mfw_if1);

    mfw_check(mfw_tc_on(mfw_if0, .src = "1.1.1.1", .dst = "2.2.2.2",
                        MFW_TCP, .dport = 80) == TC_ACT_SHOT,
              "if0: extended implicit deny");
    mfw_check(mfw_tc_on(mfw_if1, .src = "1.1.1.1", .dst = "2.2.2.2",
                        MFW_TCP, .dport = 80) == TC_ACT_UNSPEC,
              "if1: no extended list, not on the blacklist");
    mfw_check(mfw_tc_on(mfw_if0, .src = "192.0.2.9", .dst = "2.2.2.2",
                        MFW_TCP, .dport = 22) == TC_ACT_UNSPEC,
              "if0: if1's blacklist does not apply");
    mfw_check(mfw_tc_on(mfw_if1, .src = "192.0.2.9", .dst = "2.2.2.2",
                        MFW_TCP, .dport = 22) == TC_ACT_SHOT,
              "if1: its blacklist");
    mfw_check(mfw_tc_on(1, .src = "1.1.1.1", .dst = "2.2.2.2", MFW_TCP,
                        .dport = 80) == TC_ACT_UNSPEC,
              "lo: no ruleset, open");

    /* replace if0's ruleset: the new one applies, if1 keeps its own */
    memset(&mfw_rs, 0, sizeof(mfw_rs));
    add("100 permit tcp any any eq 80");
    commit_on(mfw_if0);

    mfw_check(mfw_tc_on(mfw_if0, .src = "1.1.1.1", .dst = "2.2.2.2",
                        MFW_TCP, .dport = 80) == TC_ACT_UNSPEC,
              "if0: swapped ruleset applies");
    mfw_check(mfw_tc_on(mfw_if0, .src = "1.1.1.1", .dst = "2.2.2.2",
                        MFW_TCP, .dport = 22) == TC_ACT_SHOT,
              "if0: old ruleset gone");
    mfw_check(mfw_tc_on(mfw_if1, .src = "192.0.2.9", .dst = "2.2.2.2",
                        MFW_TCP, .dport = 22) == TC_ACT_SHOT,
              "if1: unchanged by if0's swap");

    /* removing if0's entry makes it fail-open again */
    bpf_map_delete_elem(bpf_map__fd(mfw_skel->maps.rulesets), &mfw_if0);

    mfw_check(mfw_tc_on(mfw_if0, .src = "1.1.1.1", .dst = "2.2.2.2",
                        MFW_TCP, .dport = 22) == TC_ACT_UNSPEC,
              "if0: entry removed, open");
}


static void
test_corrupt(void)
{
    reset();
    mfw_check(mfw_tc(.src = "1.1.1.1", .dst = "2.2.2.2", MFW_UDP, .ihl = 4)
              == TC_ACT_SHOT, "ihl<5 dropped");
}


/* A private network namespace with two dummy interfaces. */
static int
setup_netns(void)
{
    if (unshare(CLONE_NEWNET) != 0) {
        perror("unshare(CLONE_NEWNET) (root needed)");
        return -1;
    }

    if (system("ip link add mfwt0 type dummy "
               "&& ip link add mfwt1 type dummy") != 0)
    {
        fprintf(stderr, "cannot create dummy interfaces\n");
        return -1;
    }

    mfw_if0 = if_nametoindex("mfwt0");
    mfw_if1 = if_nametoindex("mfwt1");

    return mfw_if0 != 0 && mfw_if1 != 0 ? 0 : -1;
}


int
main(void)
{
    LIBBPF_OPTS(bpf_object_open_opts, opts);
    struct bpf_map  *m;

    if (setup_netns() != 0) {
        return 1;
    }

    mfw_skel = mfw_bpf__open_opts(&opts);
    if (mfw_skel == NULL) {
        perror("open");
        return 1;
    }

    bpf_object__for_each_map(m, mfw_skel->obj) {
        bpf_map__set_pin_path(m, NULL);  /* private maps: no pins */
    }

    /*
     * a table of sw_flowd's layout and its own size, bound as mfwd binds
     * the pinned one
     */
    mfw_flows_table = bpf_map_create(BPF_MAP_TYPE_LRU_HASH, "outbound",
                                     sizeof(struct sf_flow_key),
                                     sizeof(struct sf_flow), 1024, NULL);

    if (mfw_flows_table < 0
        || bpf_map__reuse_fd(mfw_skel->maps.flows, mfw_flows_table) != 0)
    {
        perror("flow table");
        return 1;
    }

    /* and its config: the default ephemeral range, and ntpd's 123 */
    {
        int               zero = 0, cfd;
        struct sf_config  c = { .port_lo = 32768, .port_hi = 60999,
                                .record = { 123 } };

        cfd = bpf_map_create(BPF_MAP_TYPE_ARRAY, "config", sizeof(__u32),
                             sizeof(struct sf_config), 1, NULL);

        if (cfd < 0
            || bpf_map_update_elem(cfd, &zero, &c, BPF_ANY) != 0
            || bpf_map__reuse_fd(mfw_skel->maps.flows_config, cfd) != 0)
        {
            perror("flow config");
            return 1;
        }
    }

    if (mfw_bpf__load(mfw_skel) != 0) {
        fprintf(stderr, "load failed (root needed)\n");
        return 1;
    }

    test_unbound();
    test_standard();
    test_extended();
    test_combined();
    test_established();
    test_reply();
    test_reply_miss();
    test_fragments();
    test_full_tables();
    test_per_interface();
    test_corrupt();

    /* every run counted exactly one outcome */
    mfw_check(stat(MFW_STAT_PASS) + stat(MFW_STAT_DROP) > 0,
              "outcome stats");
    mfw_check(stat(MFW_STAT_STD_DENY) > 0
              && stat(MFW_STAT_EXT_IMPLICIT_DENY) > 0
              && stat(MFW_STAT_EXT_PERMIT) > 0, "reason stats");

    mfw_bpf__destroy(mfw_skel);

    if (mfw_failures != 0) {
        printf("%d failure(s)\n", mfw_failures);
        return 1;
    }

    printf("test_bpf: all tests passed\n");

    return 0;
}
