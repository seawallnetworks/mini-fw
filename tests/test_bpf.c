// SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
/* Dataplane tests via BPF_PROG_TEST_RUN: feed crafted frames to the TC
 * ingress program and check verdicts (TC_ACT_UNSPEC: passed on, TC_ACT_SHOT).
 * Each frame goes through the XDP entry too, whose verdict must be the
 * same (XDP_PASS, XDP_DROP). Needs root. Runs in a private network
 * namespace with two dummy interfaces, so the per-interface rulesets have
 * real ifindexes; touches no host interface or pins. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <net/if.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "mfw_policy.h"
#include "mfw.skel.h"
#include <sw_flowd/sw_flowd.h>

static struct mfw_bpf *skel;
static int flows_table;          /* sw_flowd's, as mfwd binds it at load */
static int failures;
static __u32 if0, if1;           /* the dummy interfaces mfwt0, mfwt1 */

#define CHECK(cond, ...) do { \
    if (!(cond)) { failures++; printf("FAIL %s:%d: ", __FILE__, __LINE__); \
                   printf(__VA_ARGS__); printf("\n"); } } while (0)

/* ---- packet builder ---- */

struct pkt_spec {
    const char *src, *dst;
    __u8 proto;
    __u16 sport, dport;
    __u8 tcp_flags;      /* default SYN */
    int vlans;           /* 0..3 tags */
    __u16 frag_off;      /* host order: IP_MF | offset */
    __u8 ihl;            /* default 5 */
    __u16 ethertype;     /* default IPv4 */
};

static int build(const struct pkt_spec *s, __u8 *buf)
{
    __u8 *p = buf;
    struct ethhdr *eth = (void *)p;

    memset(buf, 0, 256);
    memset(eth->h_dest, 0x02, ETH_ALEN);
    memset(eth->h_source, 0x04, ETH_ALEN);
    p += sizeof(*eth);
    __u8 *proto = p - 2;         /* ethertype slot to fill next */
    __be16 v;

    for (int i = 0; i < s->vlans; i++) {
        v = htons(i == 0 && s->vlans > 1 ? 0x88A8 : 0x8100);
        memcpy(proto, &v, 2);
        p[1] = 10 + i;           /* VID */
        proto = p + 2;
        p += 4;
    }
    v = htons(s->ethertype ? s->ethertype : ETH_P_IP);
    memcpy(proto, &v, 2);
    if (s->ethertype && s->ethertype != ETH_P_IP)
        return p - buf + 40;     /* e.g. ARP: payload is irrelevant, but
                                  * an skb test run of IPv6 needs 40 */

    struct iphdr *ip = (void *)p;

    ip->version = 4;
    ip->ihl = s->ihl ? s->ihl : 5;
    ip->ttl = 64;
    ip->protocol = s->proto;
    ip->saddr = inet_addr(s->src);
    ip->daddr = inet_addr(s->dst);
    ip->frag_off = htons(s->frag_off);
    ip->id = htons(0x1234);
    p += 20;

    if (!(s->frag_off & 0x1FFF)) {
        if (s->proto == IPPROTO_TCP) {
            struct tcphdr *th = (void *)p;

            th->source = htons(s->sport);
            th->dest = htons(s->dport);
            th->doff = 5;
            p[13] = s->tcp_flags ? s->tcp_flags : 0x02;
            p += sizeof(*th);
        } else if (s->proto == IPPROTO_UDP) {
            struct udphdr *uh = (void *)p;

            uh->source = htons(s->sport);
            uh->dest = htons(s->dport);
            uh->len = htons(8);
            p += sizeof(*uh);
        } else if (s->proto == IPPROTO_ICMP) {
            p[0] = 8;            /* echo request */
            p += 8;
        }
    }
    p += 16;                     /* a little payload */
    ip->tot_len = htons(p - (__u8 *)ip);
    return p - buf;
}

/* The packet as if it arrived on ifindex; RUN_ERR if it couldn't run
 * (-1 is TC_ACT_UNSPEC). */
#define RUN_ERR  (-100)

static int run_prog(struct bpf_program *prog, void *ctx, __u32 ctx_size,
                    __u8 *buf, int len)
{
    LIBBPF_OPTS(bpf_test_run_opts, opts, .data_in = buf, .data_size_in = len,
                .ctx_in = ctx, .ctx_size_in = ctx_size, .repeat = 1);

    if (bpf_prog_test_run_opts(bpf_program__fd(prog), &opts)) {
        perror("bpf_prog_test_run_opts");
        failures++;
        return RUN_ERR;
    }
    return (int)opts.retval;
}

/* The counters, all CPUs': put back after the XDP run, so they count
 * the TC run alone. */
static void stats_copy(struct mfw_stat_value *save, int restore)
{
    int ncpu = libbpf_num_possible_cpus(), fd = bpf_map__fd(skel->maps.stats);

    for (__u32 id = 0; id < MFW_STAT_MAX; id++) {
        if (restore)
            bpf_map_update_elem(fd, &id, save + id * ncpu, BPF_ANY);
        else
            bpf_map_lookup_elem(fd, &id, save + id * ncpu);
    }
}

/* TC's verdict on the frame, which XDP's must match. */
static int run(__u32 ifindex, const struct pkt_spec *s)
{
    struct mfw_stat_value save[MFW_STAT_MAX * libbpf_num_possible_cpus()];
    struct __sk_buff ctx = { .ingress_ifindex = ifindex };
    __u8 buf[256];
    int len = build(s, buf), xdp, tc;
    /* the frame's bounds, as the kernel checks them */
    struct xdp_md xctx = { .data_end = len, .ingress_ifindex = ifindex };

    stats_copy(save, 0);
    xdp = run_prog(skel->progs.mfw_xdp, &xctx, sizeof(xctx), buf, len);
    stats_copy(save, 1);
    tc = run_prog(skel->progs.mfw_tc, &ctx, sizeof(ctx), buf, len);
    CHECK(xdp == (tc == TC_ACT_SHOT ? XDP_DROP : XDP_PASS),
          "XDP verdict %d, TC verdict %d", xdp, tc);
    return tc;
}

/* on if0 unless said otherwise */
#define TC(...)         run(if0, &(struct pkt_spec){ __VA_ARGS__ })
#define TC_ON(i, ...)   run((i), &(struct pkt_spec){ __VA_ARGS__ })

/* ---- rule loading (mirrors mfw_policy_compile() and dataplane.c) ---- */

static struct mfw_ruleset rs;   /* being built */

/* Clears the ruleset being built and every installed one. */
static void reset(void)
{
    struct mfw_config cfg = { .abi_version = MFW_ABI_VERSION };
    __u32 k = 0;

    memset(&rs, 0, sizeof(rs));
    bpf_map_update_elem(bpf_map__fd(skel->maps.config), &k, &cfg, BPF_ANY);
    bpf_map_delete_elem(bpf_map__fd(skel->maps.rulesets), &if0);
    bpf_map_delete_elem(bpf_map__fd(skel->maps.rulesets), &if1);
}

static void add(const char *line)
{
    char buf[256], *argv[32], err[160];
    struct mfw_rule r;
    int argc = 0;

    snprintf(buf, sizeof(buf), "%s", line);
    for (char *t = strtok(buf, " "); t; t = strtok(NULL, " "))
        argv[argc++] = t;
    if (mfw_parse_ace(argc, argv, &r, err, sizeof(err))) {
        printf("bad test rule '%s': %s\n", line, err);
        failures++;
        return;
    }
    r.direction = MFW_DIR_INGRESS;
    /* as mfw_policy_compile() sets it: an hour for TCP, a minute for UDP */
    if (r.flags & MFW_RULE_F_REPLY)
        r.reply_idle = r.proto == MFW_PROTO_TCP ? 3600 : 60;
    if (r.kind == MFW_ACL_STANDARD) {
        rs.std_acl = r.acl_id;
        rs.std[rs.n_std++] = r;
    } else {
        rs.ext_acl = r.acl_id;
        rs.ext[rs.n_ext++] = r;
    }
}

/* Swaps the ruleset built so far in on ifindex, as dataplane.c does. */
static void commit_on(__u32 ifindex)
{
    __u32 zero = 0;
    int fd = bpf_map_create(BPF_MAP_TYPE_ARRAY, "mfw_ruleset", sizeof(__u32),
                            sizeof(struct mfw_ruleset), 1, NULL);

    if (fd < 0 || bpf_map_update_elem(fd, &zero, &rs, BPF_ANY) ||
        bpf_map_update_elem(bpf_map__fd(skel->maps.rulesets), &ifindex, &fd, BPF_ANY)) {
        perror("install ruleset");
        failures++;
    }
    if (fd >= 0)
        close(fd);   /* the outer map holds the inner one now */
}

static void commit(void)
{
    commit_on(if0);
}

static __u64 stat(__u32 id)
{
    int ncpu = libbpf_num_possible_cpus();
    struct mfw_stat_value vals[ncpu];
    __u64 sum = 0;

    if (bpf_map_lookup_elem(bpf_map__fd(skel->maps.stats), &id, vals))
        return 0;
    for (int i = 0; i < ncpu; i++)
        sum += vals[i].count;
    return sum;
}

#define TCP .proto = IPPROTO_TCP
#define UDP .proto = IPPROTO_UDP

static void test_unbound(void)
{
    reset();
    CHECK(TC(.src = "10.0.0.1", .dst = "10.0.0.5", TCP, .dport = 22) == TC_ACT_UNSPEC,
          "no ruleset: open");
    commit();
    CHECK(TC(.src = "10.0.0.1", .dst = "10.0.0.5", TCP, .dport = 22) == TC_ACT_UNSPEC,
          "ruleset with nothing bound: open");
}

static void test_standard(void)
{
    reset();
    add("10 deny host 10.0.0.1");
    add("10 permit 10.0.0.0 0.0.0.255");
    add("10 deny 10.0.0.0/8");
    commit();
    CHECK(TC(.src = "10.0.0.1", .dst = "1.1.1.1", UDP) == TC_ACT_SHOT, "explicit deny");
    CHECK(TC(.src = "10.0.0.2", .dst = "1.1.1.1", UDP) == TC_ACT_UNSPEC, "earlier permit wins");
    CHECK(TC(.src = "10.9.0.2", .dst = "1.1.1.1", UDP) == TC_ACT_SHOT, "later deny");
    CHECK(TC(.src = "192.168.1.1", .dst = "1.1.1.1", UDP) == TC_ACT_UNSPEC, "miss → pass (blacklist)");
    CHECK(TC(.src = "10.0.0.1", .dst = "1.1.1.1", .proto = 47) == TC_ACT_SHOT, "std matches any proto");
    CHECK(TC(.src = "10.0.0.1", .dst = "1.1.1.1", UDP, .vlans = 1) == TC_ACT_SHOT, "802.1Q peel");
    CHECK(TC(.src = "10.0.0.1", .dst = "1.1.1.1", UDP, .vlans = 2) == TC_ACT_SHOT, "QinQ peel");
    CHECK(TC(.src = "10.0.0.1", .dst = "1.1.1.1", UDP, .vlans = 3) == TC_ACT_UNSPEC, ">2 tags → non-IPv4 pass");
    CHECK(TC(.ethertype = ETH_P_ARP) == TC_ACT_UNSPEC, "ARP pass");
    CHECK(TC(.ethertype = ETH_P_ARP, .vlans = 1) == TC_ACT_UNSPEC, "tagged ARP pass");
    CHECK(TC(.ethertype = ETH_P_IPV6) == TC_ACT_UNSPEC, "IPv6 pass");
    CHECK(TC(.src = "10.0.0.1", .dst = "1.1.1.1", UDP, .frag_off = 100) == TC_ACT_SHOT,
          "non-first frag still matches saddr");
}

static void test_extended(void)
{
    reset();
    add("100 deny tcp host 10.0.0.66 any eq 22");
    add("100 permit tcp any host 10.0.0.5 eq 22");
    add("100 permit udp any eq 53 any");
    add("100 permit icmp any any");
    commit();
    CHECK(TC(.src = "1.2.3.4", .dst = "10.0.0.5", TCP, .sport = 40000, .dport = 22) == TC_ACT_UNSPEC, "ssh ok");
    CHECK(TC(.src = "10.0.0.66", .dst = "10.0.0.5", TCP, .sport = 40000, .dport = 22) == TC_ACT_SHOT,
          "deny before permit");
    CHECK(TC(.src = "1.2.3.4", .dst = "10.0.0.5", TCP, .sport = 40000, .dport = 23) == TC_ACT_SHOT,
          "implicit deny");
    CHECK(TC(.src = "1.2.3.4", .dst = "10.0.0.6", TCP, .sport = 40000, .dport = 22) == TC_ACT_SHOT,
          "wrong dst");
    CHECK(TC(.src = "8.8.8.8", .dst = "10.0.0.5", UDP, .sport = 53, .dport = 5555) == TC_ACT_UNSPEC,
          "dns reply by sport");
    CHECK(TC(.src = "8.8.8.8", .dst = "10.0.0.5", .proto = IPPROTO_ICMP) == TC_ACT_UNSPEC, "icmp");
    CHECK(TC(.src = "8.8.8.8", .dst = "10.0.0.5", .proto = 47) == TC_ACT_SHOT, "gre implicit deny");
    CHECK(TC(.src = "1.2.3.4", .dst = "10.0.0.5", TCP, .dport = 22, .vlans = 2) == TC_ACT_UNSPEC,
          "QinQ + extended");

    /* empty bound list = implicit deny only */
    reset();
    rs.ext_acl = 101;
    commit();
    CHECK(TC(.src = "1.2.3.4", .dst = "10.0.0.5", .proto = IPPROTO_ICMP) == TC_ACT_SHOT,
          "empty bound ext list denies");
}

/* Both lists bound: standard deny is final; otherwise extended decides. */
static void test_combined(void)
{
    reset();
    add("10 deny host 203.0.113.66");
    add("10 permit 203.0.113.0 0.0.0.255");
    add("100 permit tcp any any eq 22");
    commit();
    CHECK(TC(.src = "203.0.113.66", .dst = "10.0.0.5", TCP, .dport = 22) == TC_ACT_SHOT,
          "std deny beats ext permit");
    CHECK(TC(.src = "203.0.113.7", .dst = "10.0.0.5", TCP, .dport = 80) == TC_ACT_SHOT,
          "std permit does not bypass ext implicit deny");
    CHECK(TC(.src = "203.0.113.7", .dst = "10.0.0.5", TCP, .dport = 22) == TC_ACT_UNSPEC,
          "std permit then ext permit");
    CHECK(TC(.src = "198.51.100.1", .dst = "10.0.0.5", TCP, .dport = 22) == TC_ACT_UNSPEC,
          "std miss then ext permit");
}

static void test_established(void)
{
    reset();
    add("100 permit tcp any any established");
    commit();
    CHECK(TC(.src = "1.1.1.1", .dst = "2.2.2.2", TCP, .tcp_flags = 0x02) == TC_ACT_SHOT, "SYN blocked");
    CHECK(TC(.src = "1.1.1.1", .dst = "2.2.2.2", TCP, .tcp_flags = 0x12) == TC_ACT_UNSPEC, "SYN-ACK ok");
    CHECK(TC(.src = "1.1.1.1", .dst = "2.2.2.2", TCP, .tcp_flags = 0x10) == TC_ACT_UNSPEC, "ACK ok");
    CHECK(TC(.src = "1.1.1.1", .dst = "2.2.2.2", TCP, .tcp_flags = 0x04) == TC_ACT_UNSPEC, "RST ok");
}

/* bpf_ktime_get_coarse_ns()'s clock, which sw_flowd and mfw_tc read: a
 * last_seen from the fine one could be ahead of mfw_tc's now. */
static __u64 now_ns(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC_COARSE, &ts);
    return ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

/* A flow the host opened, as sw_flowd records it: to raddr:rport from
 * lport, last out ago_s seconds ago. */
static void flow_add(int table, __u8 proto, const char *raddr, __u16 rport,
                     __u16 lport, __u64 ago_s)
{
    struct sf_flow_key k = { .family = SF_FAMILY_V4, .protocol = proto,
                             .rport = htons(rport), .lport = htons(lport) };
    struct sf_flow f = { .last_seen = now_ns() - ago_s * 1000000000ULL };
    __be32 a = inet_addr(raddr);

    memcpy(k.raddr, &a, 4);
    if (bpf_map_update_elem(table, &k, &f, BPF_ANY)) {
        perror("flow_add");
        failures++;
    }
}

/* "reply": only replies to flows in sw_flowd's table, within the idle
 * limits; nothing while the table is empty, as without sw_flowd. */
static void test_reply(void)
{
    int table = flows_table;

    reset();
    add("100 permit tcp any any reply");
    add("100 permit udp any any reply");
    commit();
    CHECK(TC(.src = "1.1.1.1", .dst = "10.0.0.5", TCP, .sport = 443, .dport = 40000,
             .tcp_flags = 0x10) == TC_ACT_SHOT, "empty table: reply matches nothing");

    flow_add(table, IPPROTO_TCP, "1.1.1.1", 443, 40000, 0);
    flow_add(table, IPPROTO_TCP, "1.1.1.2", 443, 40001, 7200);   /* idle 2 h */
    flow_add(table, IPPROTO_UDP, "8.8.8.8", 53, 50000, 10);
    flow_add(table, IPPROTO_UDP, "8.8.4.4", 53, 50001, 120);     /* idle 2 min */

    CHECK(TC(.src = "1.1.1.1", .dst = "10.0.0.5", TCP, .sport = 443, .dport = 40000,
             .tcp_flags = 0x12) == TC_ACT_UNSPEC, "SYN-ACK of a flow the host opened");
    CHECK(TC(.src = "1.1.1.1", .dst = "10.0.0.5", TCP, .sport = 443, .dport = 40000,
             .tcp_flags = 0x10) == TC_ACT_UNSPEC, "ACK of it");
    CHECK(TC(.src = "1.1.1.1", .dst = "10.0.0.5", TCP, .sport = 443, .dport = 40000,
             .tcp_flags = 0x04) == TC_ACT_UNSPEC, "RST of it");
    CHECK(TC(.src = "1.1.1.1", .dst = "10.0.0.5", TCP, .sport = 443, .dport = 40000,
             .tcp_flags = 0x02) == TC_ACT_SHOT, "a SYN is no reply");
    CHECK(TC(.src = "1.1.1.1", .dst = "10.0.0.5", TCP, .sport = 443, .dport = 40002,
             .tcp_flags = 0x10) == TC_ACT_SHOT, "ACK to another local port");
    CHECK(TC(.src = "1.1.1.1", .dst = "10.0.0.5", TCP, .sport = 444, .dport = 40000,
             .tcp_flags = 0x10) == TC_ACT_SHOT, "ACK from another remote port");
    CHECK(TC(.src = "1.1.1.3", .dst = "10.0.0.5", TCP, .sport = 443, .dport = 40000,
             .tcp_flags = 0x10) == TC_ACT_SHOT, "ACK from another address");
    CHECK(TC(.src = "1.1.1.2", .dst = "10.0.0.5", TCP, .sport = 443, .dport = 40001,
             .tcp_flags = 0x10) == TC_ACT_SHOT, "a flow idle past reply-idle-tcp");
    CHECK(TC(.src = "8.8.8.8", .dst = "10.0.0.5", UDP, .sport = 53, .dport = 50000)
          == TC_ACT_UNSPEC, "UDP reply");
    CHECK(TC(.src = "8.8.8.8", .dst = "10.0.0.5", UDP, .sport = 53, .dport = 50001)
          == TC_ACT_SHOT, "UDP to another local port");
    CHECK(TC(.src = "8.8.4.4", .dst = "10.0.0.5", UDP, .sport = 53, .dport = 50001)
          == TC_ACT_SHOT, "a UDP flow idle past reply-idle-udp");
    CHECK(TC(.src = "1.1.1.1", .dst = "10.0.0.5", UDP, .sport = 443, .dport = 40000)
          == TC_ACT_SHOT, "UDP doesn't match a TCP flow");

    /* the ACE's other fields still apply: the lookup is last */
    reset();
    add("100 permit tcp host 9.9.9.9 any reply");
    commit();
    CHECK(TC(.src = "1.1.1.1", .dst = "10.0.0.5", TCP, .sport = 443, .dport = 40000,
             .tcp_flags = 0x10) == TC_ACT_SHOT, "reply from outside the ACE's source");
}

static void test_fragments(void)
{
    reset();
    add("10 deny host 6.6.6.6");
    add("100 deny udp any any eq 53");
    add("100 permit udp any any eq 4789");
    commit();
    CHECK(TC(.src = "1.1.1.1", .dst = "2.2.2.2", UDP, .dport = 4789, .frag_off = 0x2000) == TC_ACT_UNSPEC,
          "first frag has ports");
    CHECK(TC(.src = "1.1.1.1", .dst = "2.2.2.2", UDP, .dport = 53, .frag_off = 0x2000) == TC_ACT_SHOT,
          "first frag hits a port deny");
    CHECK(TC(.src = "1.1.1.1", .dst = "2.2.2.2", UDP, .dport = 80, .frag_off = 0x2000) == TC_ACT_SHOT,
          "first frag hits the implicit deny");
    CHECK(TC(.src = "1.1.1.1", .dst = "2.2.2.2", UDP, .frag_off = 185) == TC_ACT_UNSPEC,
          "non-first frag skips the extended list");
    CHECK(TC(.src = "1.1.1.1", .dst = "2.2.2.2", .proto = 47, .frag_off = 185) == TC_ACT_UNSPEC,
          "non-first frag of any protocol skips it");
    CHECK(TC(.src = "6.6.6.6", .dst = "2.2.2.2", UDP, .frag_off = 185) == TC_ACT_SHOT,
          "non-first frag still hits a standard deny");
    CHECK(TC(.src = "6.6.6.6", .dst = "2.2.2.2", UDP, .dport = 4789, .frag_off = 0x2000) == TC_ACT_SHOT,
          "first frag hits a standard deny");

    __u64 off1 = stat(MFW_STAT_TCP_FRAG_OFF1);

    CHECK(TC(.src = "4.4.4.4", .dst = "2.2.2.2", TCP, .frag_off = 1) == TC_ACT_SHOT,
          "TCP frag at offset 1 dropped");
    CHECK(TC(.src = "4.4.4.4", .dst = "2.2.2.2", TCP, .frag_off = 0x2001) == TC_ACT_SHOT,
          "TCP frag at offset 1 with MF dropped");
    CHECK(stat(MFW_STAT_TCP_FRAG_OFF1) == off1 + 2, "tcp_frag_off1 counted");
    CHECK(TC(.src = "4.4.4.4", .dst = "2.2.2.2", TCP, .frag_off = 2) == TC_ACT_UNSPEC,
          "TCP frag at offset 2 passes");
    CHECK(TC(.src = "4.4.4.4", .dst = "2.2.2.2", UDP, .frag_off = 1) == TC_ACT_UNSPEC,
          "UDP frag at offset 1 passes");

    struct mfw_config cfg = { .abi_version = MFW_ABI_VERSION, .drop_ipv4_fragments = 1 };
    __u32 k = 0;

    bpf_map_update_elem(bpf_map__fd(skel->maps.config), &k, &cfg, BPF_ANY);
    CHECK(TC(.src = "1.1.1.1", .dst = "2.2.2.2", UDP, .frag_off = 0x2000) == TC_ACT_SHOT, "strict: first frag");
    CHECK(TC(.src = "1.1.1.1", .dst = "2.2.2.2", UDP, .frag_off = 185) == TC_ACT_SHOT, "strict: non-first frag");
    CHECK(TC(.src = "1.1.1.1", .dst = "2.2.2.2", UDP, .dport = 4789) == TC_ACT_UNSPEC, "strict: unfragmented ok");
}

static void test_full_tables(void)
{
    char line[96];

    reset();
    for (int i = 0; i < MFW_MAX_STD_ACES - 1; i++) {
        snprintf(line, sizeof(line), "10 permit host 172.16.0.%d", i + 1);
        add(line);
    }
    add("10 deny host 192.0.2.1");
    for (int i = 0; i < MFW_MAX_EXT_ACES - 1; i++) {
        snprintf(line, sizeof(line), "100 permit tcp any any eq %d", 1000 + i);
        add(line);
    }
    add("100 permit tcp any any eq 9");
    commit();
    CHECK(TC(.src = "192.0.2.1", .dst = "1.1.1.1", UDP) == TC_ACT_SHOT, "64th std ACE");
    CHECK(TC(.src = "1.1.1.1", .dst = "2.2.2.2", TCP, .dport = 9) == TC_ACT_UNSPEC, "128th ext ACE");
    CHECK(TC(.src = "1.1.1.1", .dst = "2.2.2.2", TCP, .dport = 10) == TC_ACT_SHOT,
          "past the 128th: implicit deny");
}

/* Each interface is judged by its own lists; others are untouched. */
static void test_per_interface(void)
{
    reset();
    add("100 permit tcp any any eq 22");
    commit_on(if0);

    memset(&rs, 0, sizeof(rs));
    add("10 deny host 192.0.2.9");
    commit_on(if1);

    CHECK(TC_ON(if0, .src = "1.1.1.1", .dst = "2.2.2.2", TCP, .dport = 80) == TC_ACT_SHOT,
          "if0: extended implicit deny");
    CHECK(TC_ON(if1, .src = "1.1.1.1", .dst = "2.2.2.2", TCP, .dport = 80) == TC_ACT_UNSPEC,
          "if1: no extended list, not on the blacklist");
    CHECK(TC_ON(if0, .src = "192.0.2.9", .dst = "2.2.2.2", TCP, .dport = 22) == TC_ACT_UNSPEC,
          "if0: if1's blacklist does not apply");
    CHECK(TC_ON(if1, .src = "192.0.2.9", .dst = "2.2.2.2", TCP, .dport = 22) == TC_ACT_SHOT,
          "if1: its blacklist");
    CHECK(TC_ON(1, .src = "1.1.1.1", .dst = "2.2.2.2", TCP, .dport = 80) == TC_ACT_UNSPEC,
          "lo: no ruleset, open");

    /* replace if0's ruleset: the new one applies, if1 keeps its own */
    memset(&rs, 0, sizeof(rs));
    add("100 permit tcp any any eq 80");
    commit_on(if0);
    CHECK(TC_ON(if0, .src = "1.1.1.1", .dst = "2.2.2.2", TCP, .dport = 80) == TC_ACT_UNSPEC,
          "if0: swapped ruleset applies");
    CHECK(TC_ON(if0, .src = "1.1.1.1", .dst = "2.2.2.2", TCP, .dport = 22) == TC_ACT_SHOT,
          "if0: old ruleset gone");
    CHECK(TC_ON(if1, .src = "192.0.2.9", .dst = "2.2.2.2", TCP, .dport = 22) == TC_ACT_SHOT,
          "if1: unchanged by if0's swap");

    /* removing if0's entry makes it fail-open again */
    bpf_map_delete_elem(bpf_map__fd(skel->maps.rulesets), &if0);
    CHECK(TC_ON(if0, .src = "1.1.1.1", .dst = "2.2.2.2", TCP, .dport = 22) == TC_ACT_UNSPEC,
          "if0: entry removed, open");
}

static void test_corrupt(void)
{
    reset();
    CHECK(TC(.src = "1.1.1.1", .dst = "2.2.2.2", UDP, .ihl = 4) == TC_ACT_SHOT, "ihl<5 dropped");
}

/* A private network namespace with two dummy interfaces. */
static int setup_netns(void)
{
    if (unshare(CLONE_NEWNET)) {
        perror("unshare(CLONE_NEWNET) (root needed)");
        return -1;
    }
    if (system("ip link add mfwt0 type dummy && ip link add mfwt1 type dummy")) {
        fprintf(stderr, "cannot create dummy interfaces\n");
        return -1;
    }
    if0 = if_nametoindex("mfwt0");
    if1 = if_nametoindex("mfwt1");
    return if0 && if1 ? 0 : -1;
}

int main(void)
{
    LIBBPF_OPTS(bpf_object_open_opts, opts);
    struct bpf_map *m;

    if (setup_netns())
        return 1;
    skel = mfw_bpf__open_opts(&opts);
    if (!skel) {
        perror("open");
        return 1;
    }
    bpf_object__for_each_map(m, skel->obj)
        bpf_map__set_pin_path(m, NULL);  /* private maps: no pins */
    /* a table of sw_flowd's layout and its own size, bound as mfwd binds
     * the pinned one */
    flows_table = bpf_map_create(BPF_MAP_TYPE_LRU_HASH, "outbound",
                                 sizeof(struct sf_flow_key), sizeof(struct sf_flow),
                                 1024, NULL);
    if (flows_table < 0 || bpf_map__reuse_fd(skel->maps.flows, flows_table)) {
        perror("flow table");
        return 1;
    }
    if (mfw_bpf__load(skel)) {
        fprintf(stderr, "load failed (root needed)\n");
        return 1;
    }

    test_unbound();
    test_standard();
    test_extended();
    test_combined();
    test_established();
    test_reply();
    test_fragments();
    test_full_tables();
    test_per_interface();
    test_corrupt();

    /* every run counted exactly one outcome */
    CHECK(stat(MFW_STAT_PASS) + stat(MFW_STAT_DROP) > 0, "outcome stats");
    CHECK(stat(MFW_STAT_STD_DENY) > 0 && stat(MFW_STAT_EXT_IMPLICIT_DENY) > 0 &&
          stat(MFW_STAT_EXT_PERMIT) > 0, "reason stats");

    mfw_bpf__destroy(skel);
    if (failures) {
        printf("%d failure(s)\n", failures);
        return 1;
    }
    printf("test_bpf: all tests passed\n");
    return 0;
}
