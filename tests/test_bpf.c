// SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
/* Dataplane tests via BPF_PROG_TEST_RUN: feed crafted frames to the XDP
 * program and check verdicts. Needs root; touches no interface or pins. */
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "mfw_cli.h"
#include "mfw.skel.h"

static struct mfw_bpf *skel;
static int failures;

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
        return p - buf + 28;     /* e.g. ARP: payload is irrelevant */

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

static int run(struct bpf_program *prog, const struct pkt_spec *s)
{
    __u8 buf[256];
    LIBBPF_OPTS(bpf_test_run_opts, opts, .data_in = buf, .data_size_in = build(s, buf),
                .repeat = 1);

    if (bpf_prog_test_run_opts(bpf_program__fd(prog), &opts)) {
        perror("bpf_prog_test_run_opts");
        failures++;
        return -1;
    }
    return opts.retval;
}

#define XDP(...)    run(skel->progs.mfw_xdp,        &(struct pkt_spec){ __VA_ARGS__ })

/* ---- rule loading (mirrors acl.c materialization) ---- */

static struct mfw_rule std[MFW_MAX_STD_ACES], ext[MFW_MAX_EXT_ACES];
static int n_std, n_ext;

static void reset(void)
{
    struct mfw_config cfg = { .abi_version = MFW_ABI_VERSION };
    __u32 k = 0;

    n_std = n_ext = 0;
    memset(std, 0, sizeof(std));
    memset(ext, 0, sizeof(ext));
    bpf_map_update_elem(bpf_map__fd(skel->maps.config), &k, &cfg, BPF_ANY);
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
    if (r.kind == MFW_ACL_STANDARD)
        std[n_std++] = r;
    else
        ext[n_ext++] = r;
}

static void implicit_deny(void)
{
    struct mfw_rule r = { .action = MFW_ACTION_DENY, .direction = MFW_DIR_INGRESS, .enabled = 1,
                          .kind = MFW_ACL_EXTENDED, .flags = MFW_RULE_F_IMPLICIT };
    ext[n_ext++] = r;
}

static void commit(void)
{
    for (__u32 i = 0; i < MFW_MAX_STD_ACES; i++)
        bpf_map_update_elem(bpf_map__fd(skel->maps.acl_std), &i, &std[i], BPF_ANY);
    for (__u32 i = 0; i < MFW_MAX_EXT_ACES; i++)
        bpf_map_update_elem(bpf_map__fd(skel->maps.acl_ext), &i, &ext[i], BPF_ANY);
}

#define TCP .proto = IPPROTO_TCP
#define UDP .proto = IPPROTO_UDP

static void test_unbound(void)
{
    reset();
    commit();
    CHECK(XDP(.src = "10.0.0.1", .dst = "10.0.0.5", TCP, .dport = 22) == XDP_PASS, "xdp open");
}

static void test_standard_xdp(void)
{
    reset();
    add("10 deny host 10.0.0.1");
    add("10 permit 10.0.0.0 0.0.0.255");
    add("10 deny 10.0.0.0/8");
    commit();
    CHECK(XDP(.src = "10.0.0.1", .dst = "1.1.1.1", UDP) == XDP_DROP, "explicit deny");
    CHECK(XDP(.src = "10.0.0.2", .dst = "1.1.1.1", UDP) == XDP_PASS, "earlier permit wins");
    CHECK(XDP(.src = "10.9.0.2", .dst = "1.1.1.1", UDP) == XDP_DROP, "later deny");
    CHECK(XDP(.src = "192.168.1.1", .dst = "1.1.1.1", UDP) == XDP_PASS, "miss → pass (blacklist)");
    CHECK(XDP(.src = "10.0.0.1", .dst = "1.1.1.1", .proto = 47) == XDP_DROP, "std matches any proto");
    CHECK(XDP(.src = "10.0.0.1", .dst = "1.1.1.1", UDP, .vlans = 1) == XDP_DROP, "802.1Q peel");
    CHECK(XDP(.src = "10.0.0.1", .dst = "1.1.1.1", UDP, .vlans = 2) == XDP_DROP, "QinQ peel");
    CHECK(XDP(.src = "10.0.0.1", .dst = "1.1.1.1", UDP, .vlans = 3) == XDP_PASS, ">2 tags → non-IPv4 pass");
    CHECK(XDP(.ethertype = ETH_P_ARP) == XDP_PASS, "ARP pass");
    CHECK(XDP(.ethertype = ETH_P_ARP, .vlans = 1) == XDP_PASS, "tagged ARP pass");
    CHECK(XDP(.ethertype = ETH_P_IPV6) == XDP_PASS, "IPv6 pass");
    CHECK(XDP(.src = "10.0.0.1", .dst = "1.1.1.1", UDP, .frag_off = 100) == XDP_DROP,
          "non-first frag still matches saddr");
}

static void test_extended(void)
{
    reset();
    add("100 deny tcp host 10.0.0.66 any eq 22");
    add("100 permit tcp any host 10.0.0.5 eq 22");
    add("100 permit udp any eq 53 any");
    add("100 permit icmp any any");
    implicit_deny();
    commit();
    CHECK(XDP(.src = "1.2.3.4", .dst = "10.0.0.5", TCP, .sport = 40000, .dport = 22) == XDP_PASS, "ssh ok");
    CHECK(XDP(.src = "10.0.0.66", .dst = "10.0.0.5", TCP, .sport = 40000, .dport = 22) == XDP_DROP,
          "deny before permit");
    CHECK(XDP(.src = "1.2.3.4", .dst = "10.0.0.5", TCP, .sport = 40000, .dport = 23) == XDP_DROP,
          "implicit deny");
    CHECK(XDP(.src = "1.2.3.4", .dst = "10.0.0.6", TCP, .sport = 40000, .dport = 22) == XDP_DROP,
          "wrong dst");
    CHECK(XDP(.src = "8.8.8.8", .dst = "10.0.0.5", UDP, .sport = 53, .dport = 5555) == XDP_PASS,
          "dns reply by sport");
    CHECK(XDP(.src = "8.8.8.8", .dst = "10.0.0.5", .proto = IPPROTO_ICMP) == XDP_PASS, "icmp");
    CHECK(XDP(.src = "8.8.8.8", .dst = "10.0.0.5", .proto = 47) == XDP_DROP, "gre implicit deny");
    CHECK(XDP(.src = "1.2.3.4", .dst = "10.0.0.5", TCP, .dport = 22, .vlans = 2) == XDP_PASS,
          "QinQ + extended");

    /* empty bound list = implicit deny only */
    reset();
    implicit_deny();
    commit();
    CHECK(XDP(.src = "1.2.3.4", .dst = "10.0.0.5", .proto = IPPROTO_ICMP) == XDP_DROP,
          "empty bound ext list denies");
}

/* Both lists bound: standard deny is final; otherwise extended decides. */
static void test_combined(void)
{
    reset();
    add("10 deny host 203.0.113.66");
    add("10 permit 203.0.113.0 0.0.0.255");
    add("100 permit tcp any any eq 22");
    implicit_deny();
    commit();
    CHECK(XDP(.src = "203.0.113.66", .dst = "10.0.0.5", TCP, .dport = 22) == XDP_DROP,
          "std deny beats ext permit");
    CHECK(XDP(.src = "203.0.113.7", .dst = "10.0.0.5", TCP, .dport = 80) == XDP_DROP,
          "std permit does not bypass ext implicit deny");
    CHECK(XDP(.src = "203.0.113.7", .dst = "10.0.0.5", TCP, .dport = 22) == XDP_PASS,
          "std permit then ext permit");
    CHECK(XDP(.src = "198.51.100.1", .dst = "10.0.0.5", TCP, .dport = 22) == XDP_PASS,
          "std miss then ext permit");
}

static void test_established(void)
{
    reset();
    add("100 permit tcp any any established");
    implicit_deny();
    commit();
    CHECK(XDP(.src = "1.1.1.1", .dst = "2.2.2.2", TCP, .tcp_flags = 0x02) == XDP_DROP, "SYN blocked");
    CHECK(XDP(.src = "1.1.1.1", .dst = "2.2.2.2", TCP, .tcp_flags = 0x12) == XDP_PASS, "SYN-ACK ok");
    CHECK(XDP(.src = "1.1.1.1", .dst = "2.2.2.2", TCP, .tcp_flags = 0x10) == XDP_PASS, "ACK ok");
    CHECK(XDP(.src = "1.1.1.1", .dst = "2.2.2.2", TCP, .tcp_flags = 0x04) == XDP_PASS, "RST ok");
}

static void test_fragments(void)
{
    reset();
    add("100 permit udp any any eq 4789");
    add("100 permit ip host 3.3.3.3 any");
    implicit_deny();
    commit();
    CHECK(XDP(.src = "1.1.1.1", .dst = "2.2.2.2", UDP, .dport = 4789, .frag_off = 0x2000) == XDP_PASS,
          "first frag has ports");
    CHECK(XDP(.src = "1.1.1.1", .dst = "2.2.2.2", UDP, .frag_off = 185) == XDP_DROP,
          "non-first frag cannot match a port ACE (no frag tracking yet)");
    CHECK(XDP(.src = "3.3.3.3", .dst = "2.2.2.2", UDP, .frag_off = 185) == XDP_PASS,
          "non-first frag matches a port-less ACE");

    struct mfw_config cfg = { .abi_version = MFW_ABI_VERSION, .drop_ipv4_fragments = 1 };
    __u32 k = 0;

    bpf_map_update_elem(bpf_map__fd(skel->maps.config), &k, &cfg, BPF_ANY);
    CHECK(XDP(.src = "1.1.1.1", .dst = "2.2.2.2", UDP, .frag_off = 0x2000) == XDP_DROP, "strict: xdp");
    CHECK(XDP(.src = "3.3.3.3", .dst = "2.2.2.2", UDP, .frag_off = 185) == XDP_DROP, "strict: non-first frag");
    CHECK(XDP(.src = "1.1.1.1", .dst = "2.2.2.2", UDP, .dport = 4789) == XDP_PASS, "strict: unfragmented ok");
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
    for (int i = 0; i < MFW_MAX_EXT_ACES - 2; i++) {
        snprintf(line, sizeof(line), "100 permit tcp any any eq %d", 1000 + i);
        add(line);
    }
    add("100 permit tcp any any eq 9");
    implicit_deny();
    commit();
    CHECK(XDP(.src = "192.0.2.1", .dst = "1.1.1.1", UDP) == XDP_DROP, "64th std ACE");
    CHECK(XDP(.src = "1.1.1.1", .dst = "2.2.2.2", TCP, .dport = 9) == XDP_PASS, "127th ext ACE");
    CHECK(XDP(.src = "1.1.1.1", .dst = "2.2.2.2", TCP, .dport = 10) == XDP_DROP, "128th = implicit");
}

static void test_corrupt(void)
{
    reset();
    commit();
    CHECK(XDP(.src = "1.1.1.1", .dst = "2.2.2.2", UDP, .ihl = 4) == XDP_DROP, "ihl<5 xdp");
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

int main(void)
{
    LIBBPF_OPTS(bpf_object_open_opts, opts);
    struct bpf_map *m;

    skel = mfw_bpf__open_opts(&opts);
    if (!skel) {
        perror("open");
        return 1;
    }
    bpf_object__for_each_map(m, skel->obj)
        bpf_map__set_pin_path(m, NULL);  /* private maps: no pins */
    if (mfw_bpf__load(skel)) {
        fprintf(stderr, "load failed (root needed)\n");
        return 1;
    }

    test_unbound();
    test_standard_xdp();
    test_extended();
    test_combined();
    test_established();
    test_fragments();
    test_full_tables();
    test_corrupt();

    /* every XDP run counted exactly one outcome */
    CHECK(stat(MFW_STAT_XDP_PASS) + stat(MFW_STAT_XDP_DROP) > 0, "xdp outcome stats");
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
