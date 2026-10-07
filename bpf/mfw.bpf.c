// SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
/* mini-fw dataplane — step 1: stateless, ingress-only ACLs for a local host.
 * One XDP program evaluates, in order:
 *
 *   1. standard ACL (1–99): source-only blacklist; explicit deny → DROP,
 *      permit or miss → continue.
 *   2. extended ACL (100–199): permit → PASS; deny or no match → DROP
 *      (implicit deny when bound).
 *
 * Egress is not filtered. Unbound lists are fail-open. Non-IPv4 always
 * passes. No conntrack yet, so return traffic must be permitted explicitly
 * (or via "established").
 */
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "mfw.h"

#ifndef ETH_P_8021Q
#define ETH_P_8021Q  0x8100
#endif
#ifndef ETH_P_8021AD
#define ETH_P_8021AD 0x88A8
#endif

#define IP_MF     0x2000
#define IP_OFFSET 0x1FFF

struct vlan_hdr {
    __be16 h_vlan_TCI;
    __be16 h_vlan_encapsulated_proto;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MFW_MAX_STD_ACES);
    __type(key, __u32);
    __type(value, struct mfw_rule);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} acl_std SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MFW_MAX_EXT_ACES);
    __type(key, __u32);
    __type(value, struct mfw_rule);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} acl_ext SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct mfw_config);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} config SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, MFW_STAT_MAX);
    __type(key, __u32);
    __type(value, struct mfw_stat_value);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} stats SEC(".maps");

struct pkt_info {
    __be32 saddr;
    __be32 daddr;
    __u16  sport;     /* host order; valid only if has_ports */
    __u16  dport;
    __u8   proto;
    __u8   tcp_flags; /* byte 13 of the TCP header */
    __u8   is_frag;   /* MF set or offset != 0 */
    __u8   has_ports; /* TCP/UDP header present (not a non-first fragment) */
};

enum {
    PARSE_IPV4     = 0,
    PARSE_NON_IPV4 = 1,
    PARSE_ERR      = -1,
};

enum {
    MATCH_DENY    = 0,
    MATCH_PERMIT  = 1,
    MATCH_MISS    = -1,  /* list bound, no explicit ACE matched */
    MATCH_UNBOUND = -2,  /* map holds no ACE: no access-group */
};

#define TCP_FLAG_RST 0x04
#define TCP_FLAG_ACK 0x10

static __always_inline void stat_inc(__u32 id)
{
    struct mfw_stat_value *v = bpf_map_lookup_elem(&stats, &id);

    if (v)
        v->count++;
}

static __always_inline int drop_frags(void)
{
    __u32 k = 0;
    struct mfw_config *cfg = bpf_map_lookup_elem(&config, &k);

    return cfg && cfg->drop_ipv4_fragments;
}

/* Ethernet → (≤2 VLAN tags) → IPv4 → TCP/UDP ports. */
static __always_inline int parse_pkt(void *data, void *data_end,
                                     struct pkt_info *p)
{
    struct ethhdr *eth = data;
    __u32 off = sizeof(*eth);
    __be16 proto;
    int i;

    if ((void *)(eth + 1) > data_end)
        return PARSE_NON_IPV4;  /* runt frame: not ours to judge */
    proto = eth->h_proto;

#pragma unroll
    for (i = 0; i < 2; i++) {
        struct vlan_hdr *vh;

        if (proto != bpf_htons(ETH_P_8021Q) && proto != bpf_htons(ETH_P_8021AD))
            break;
        vh = data + off;
        if ((void *)(vh + 1) > data_end)
            return PARSE_ERR;
        proto = vh->h_vlan_encapsulated_proto;
        off += sizeof(*vh);
    }
    if (proto != bpf_htons(ETH_P_IP))
        return PARSE_NON_IPV4;

    struct iphdr *ip = data + off;

    if ((void *)(ip + 1) > data_end)
        return PARSE_ERR;
    if (ip->version != 4 || ip->ihl < 5)
        return PARSE_ERR;
    __u32 ihl = ip->ihl * 4;

    if (data + off + ihl > data_end)
        return PARSE_ERR;

    __u16 frag = bpf_ntohs(ip->frag_off);

    p->saddr = ip->saddr;
    p->daddr = ip->daddr;
    p->proto = ip->protocol;
    p->is_frag = (frag & (IP_MF | IP_OFFSET)) != 0;
    p->has_ports = 0;
    p->sport = p->dport = 0;
    p->tcp_flags = 0;

    if (frag & IP_OFFSET)
        return PARSE_IPV4;  /* non-first fragment: no L4 header */

    void *l4 = data + off + ihl;

    if (p->proto == IPPROTO_TCP) {
        struct tcphdr *th = l4;

        if ((void *)(th + 1) > data_end)
            return PARSE_ERR;
        p->sport = bpf_ntohs(th->source);
        p->dport = bpf_ntohs(th->dest);
        p->tcp_flags = ((__u8 *)th)[13];
        p->has_ports = 1;
    } else if (p->proto == IPPROTO_UDP) {
        struct udphdr *uh = l4;

        if ((void *)(uh + 1) > data_end)
            return PARSE_ERR;
        p->sport = bpf_ntohs(uh->source);
        p->dport = bpf_ntohs(uh->dest);
        p->has_ports = 1;
    }
    return PARSE_IPV4;
}

static __always_inline int cidr_match(__be32 addr, const struct mfw_cidr *c)
{
    __u32 mask;

    if (c->prefix > 32)
        return 0;
    mask = c->prefix ? bpf_htonl(~0u << (32 - c->prefix)) : 0;
    return (addr & mask) == (c->addr & mask);
}

static __always_inline int port_in_range(__u16 port, const struct mfw_port_range *r)
{
    if (r->min == 0 && r->max == 0)
        return 1;
    return port >= r->min && port <= r->max;
}

static __always_inline int port_any(const struct mfw_port_range *r)
{
    return r->min == 0 && r->max == 0;
}

/* Standard ACL: blacklist. Callers treat only MATCH_DENY as drop. */
static __always_inline int match_std(__be32 saddr)
{
    int i;

    for (i = 0; i < MFW_MAX_STD_ACES; i++) {
        __u32 key = i;  /* separate key: verifier must keep i in a register */
        struct mfw_rule *r = bpf_map_lookup_elem(&acl_std, &key);

        if (!r || !r->enabled)
            return i ? MATCH_MISS : MATCH_UNBOUND;  /* ACEs packed from 0 */
        if (!cidr_match(saddr, &r->src))
            continue;
        return r->action == MFW_ACTION_ALLOW ? MATCH_PERMIT : MATCH_DENY;
    }
    return MATCH_MISS;
}

/* L3/L4 fields of one extended ACE vs the packet. A global (non-static)
 * function is verified once on its own, which keeps the 128-ACE loop below
 * from multiplying verifier states by every branch in here. */
__noinline int mfw_ext_ace_match(const struct mfw_rule *r, const struct pkt_info *p)
{
    if (!r || !p)
        return 0;
    if (r->proto != MFW_PROTO_ANY && r->proto != p->proto)
        return 0;
    if (!cidr_match(p->saddr, &r->src) || !cidr_match(p->daddr, &r->dst))
        return 0;
    if (p->proto != IPPROTO_TCP && p->proto != IPPROTO_UDP)
        return 1;  /* ports ignored for ICMP and other protocols */
    if (!p->has_ports)
        /* Non-first fragment: no ports, so an ACE that constrains ports
         * (or TCP flags) cannot match. */
        return port_any(&r->sport) && port_any(&r->dport) &&
               !(r->flags & MFW_RULE_F_ESTABLISHED);
    if (!port_in_range(p->sport, &r->sport) || !port_in_range(p->dport, &r->dport))
        return 0;
    if ((r->flags & MFW_RULE_F_ESTABLISHED) &&
        !(p->tcp_flags & (TCP_FLAG_ACK | TCP_FLAG_RST)))
        return 0;
    return 1;
}

/* Extended ACL. Reaching the synthetic implicit-deny ACE reports MATCH_MISS
 * (counted separately from explicit deny ACEs). */
static __always_inline int match_ext(const struct pkt_info *p)
{
    int i;

    for (i = 0; i < MFW_MAX_EXT_ACES; i++) {
        __u32 key = i;  /* separate key: verifier must keep i in a register */
        struct mfw_rule *r = bpf_map_lookup_elem(&acl_ext, &key);

        if (!r || !r->enabled)
            return i ? MATCH_MISS : MATCH_UNBOUND;
        if (r->flags & MFW_RULE_F_IMPLICIT)
            return MATCH_MISS;
        if (mfw_ext_ace_match(r, p))
            return r->action == MFW_ACTION_ALLOW ? MATCH_PERMIT : MATCH_DENY;
    }
    return MATCH_MISS;
}

SEC("xdp")
int mfw_xdp(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct pkt_info p = {};
    int pr = parse_pkt(data, data_end, &p);
    int std;

    if (pr == PARSE_NON_IPV4) {
        stat_inc(MFW_STAT_NON_IPV4);
        goto pass;
    }
    if (pr == PARSE_ERR) {
        stat_inc(MFW_STAT_PARSE_ERR);
        goto drop;
    }
    if (p.is_frag && drop_frags()) {
        stat_inc(MFW_STAT_FRAG_DROP);
        goto drop;
    }

    /* 1. Standard blacklist: only an explicit deny is final. */
    std = match_std(p.saddr);
    if (std == MATCH_DENY) {
        stat_inc(MFW_STAT_STD_DENY);
        goto drop;
    }

    /* 2. Extended list decides everything else. */
    switch (match_ext(&p)) {
    case MATCH_PERMIT:
        stat_inc(MFW_STAT_EXT_PERMIT);
        goto pass;
    case MATCH_DENY:
        stat_inc(MFW_STAT_EXT_DENY);
        goto drop;
    case MATCH_MISS:
        stat_inc(MFW_STAT_EXT_IMPLICIT_DENY);
        goto drop;
    default:  /* extended unbound: fail-open */
        if (std == MATCH_PERMIT)
            stat_inc(MFW_STAT_STD_PERMIT);
        goto pass;
    }
pass:
    stat_inc(MFW_STAT_XDP_PASS);
    return XDP_PASS;
drop:
    stat_inc(MFW_STAT_XDP_DROP);
    return XDP_DROP;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
