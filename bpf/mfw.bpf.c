// SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
/* mini-fw dataplane — step 1: stateless, ingress-only ACLs for a local host.
 * One TC ingress program (tcx), attached to every protected interface,
 * looks up the ruleset of the interface the packet arrived on and
 * evaluates, in order:
 *
 *   1. standard ACL (1–99): source-only blacklist; explicit deny → DROP,
 *      permit or miss → continue.
 *   2. extended ACL (100–199): permit → PASS; deny or no match → DROP
 *      (implicit deny when bound).
 *
 * Egress is not filtered. Unbound lists, and interfaces without a ruleset,
 * are fail-open. Non-IPv4 always passes. No conntrack yet, so return traffic must be permitted explicitly
 * (or via "established").
 *
 * TC, not XDP: XDP is left to a DDoS gate such as voidGate, which drops
 * floods before the stack builds an skb; mini-fw sees what it passed.
 * "Pass" is TCX_NEXT, so a tc program after mini-fw still runs.
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

/* The most parse_pkt() reads: Ethernet, 2 VLAN tags, IPv4 with options,
 * TCP. */
#define MFW_HDR_MAX  (14 + 2 * 4 + 60 + 20)

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

/* ifindex → inner map holding that interface's one mfw_ruleset. Sizes,
 * not BTF types: clang emits struct mfw_ruleset only as a forward
 * declaration here, and userspace creates the inner maps without BTF. */
struct ruleset_map {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(struct mfw_ruleset));
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
    __uint(max_entries, MFW_MAX_IFACES);
    __type(key, __u32);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __array(values, struct ruleset_map);
} rulesets SEC(".maps");

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
    __u16  sport;     /* host order; 0 unless TCP/UDP */
    __u16  dport;
    __u8   proto;
    __u8   tcp_flags; /* byte 13 of the TCP header */
    __u8   is_frag;   /* MF set or offset != 0 */
    __u8   pad;
};

enum {
    PARSE_IPV4       = 0,
    PARSE_NON_IPV4   = 1,
    PARSE_LATER_FRAG = 2,   /* non-first fragment: no L4 header */
    PARSE_ERR        = -1,
    PARSE_TCP_OFF1   = -2,  /* TCP fragment at offset 1 */
};

enum {
    MATCH_DENY    = 0,
    MATCH_PERMIT  = 1,
    MATCH_MISS    = -1,  /* list bound, no explicit ACE matched */
    MATCH_UNBOUND = -2,  /* no access-group for this list */
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
    /* The kernel's own IPv4 sanity check (ip_rcv_core()), made early:
     * frames the stack would drop as header errors, not a protocol
     * filter. Other ethertypes passed above, and IP protocols other
     * than TCP/UDP are left to the lists. */
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
    p->sport = p->dport = 0;
    p->tcp_flags = 0;

    /* A TCP fragment at offset 1 (8 bytes) can only exist to overwrite
     * the flags and window of the first fragment's header after it was
     * checked (RFC 1858 §3.2); no real stack sends one. */
    if ((frag & IP_OFFSET) == 1 && p->proto == IPPROTO_TCP)
        return PARSE_TCP_OFF1;
    if (frag & IP_OFFSET)
        return PARSE_LATER_FRAG;

    void *l4 = data + off + ihl;

    if (p->proto == IPPROTO_TCP) {
        struct tcphdr *th = l4;

        /* A first fragment too short for its ports would slip past
         * port ACEs (tiny-fragment attack, RFC 1858). */
        if ((void *)(th + 1) > data_end)
            return PARSE_ERR;
        p->sport = bpf_ntohs(th->source);
        p->dport = bpf_ntohs(th->dest);
        p->tcp_flags = ((__u8 *)th)[13];
    } else if (p->proto == IPPROTO_UDP) {
        struct udphdr *uh = l4;

        if ((void *)(uh + 1) > data_end)
            return PARSE_ERR;
        p->sport = bpf_ntohs(uh->source);
        p->dport = bpf_ntohs(uh->dest);
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

/* Standard ACL: blacklist. Callers treat only MATCH_DENY as drop. */
static __always_inline int match_std(const struct mfw_ruleset *rs, __be32 saddr)
{
    int i;

    if (!rs || !rs->std_acl)
        return MATCH_UNBOUND;
    for (i = 0; i < MFW_MAX_STD_ACES; i++) {
        const struct mfw_rule *r = &rs->std[i];

        if (i >= rs->n_std)
            break;
        if (!cidr_match(saddr, &r->src))
            continue;
        return r->action == MFW_ACTION_PERMIT ? MATCH_PERMIT : MATCH_DENY;
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
    if (!port_in_range(p->sport, &r->sport) || !port_in_range(p->dport, &r->dport))
        return 0;
    if ((r->flags & MFW_RULE_F_ESTABLISHED) &&
        !(p->tcp_flags & (TCP_FLAG_ACK | TCP_FLAG_RST)))
        return 0;
    return 1;
}

/* Extended ACL. Running off the end of a bound list reports MATCH_MISS:
 * the implicit deny, counted separately from explicit deny ACEs. A bound
 * list with no ACEs denies everything. */
static __always_inline int match_ext(const struct mfw_ruleset *rs,
                                     const struct pkt_info *p)
{
    int i;

    if (!rs || !rs->ext_acl)
        return MATCH_UNBOUND;
    for (i = 0; i < MFW_MAX_EXT_ACES; i++) {
        const struct mfw_rule *r = &rs->ext[i];

        if (i >= rs->n_ext)
            break;
        if (mfw_ext_ace_match(r, p))
            return r->action == MFW_ACTION_PERMIT ? MATCH_PERMIT : MATCH_DENY;
    }
    return MATCH_MISS;
}

/* The ruleset of the interface the packet arrived on, or NULL. */
static __always_inline const struct mfw_ruleset *ruleset_of(__u32 ifindex)
{
    __u32 zero = 0;
    void *inner = bpf_map_lookup_elem(&rulesets, &ifindex);

    if (!inner)
        return NULL;
    return bpf_map_lookup_elem(inner, &zero);
}

SEC("tcx/ingress")
int mfw_tc(struct __sk_buff *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct pkt_info p = {};
    const struct mfw_ruleset *rs;
    int pr, std;

    /* After GRO the headers may not all be in the skb's linear part,
     * the only part a TC program reads directly. A pull that fails
     * leaves a short view, which parse_pkt() drops as malformed. */
    if (data + MFW_HDR_MAX > data_end) {
        bpf_skb_pull_data(ctx, ctx->len < MFW_HDR_MAX ? ctx->len : MFW_HDR_MAX);
        data = (void *)(long)ctx->data;
        data_end = (void *)(long)ctx->data_end;
    }
    pr = parse_pkt(data, data_end, &p);

    if (pr == PARSE_NON_IPV4) {
        stat_inc(MFW_STAT_NON_IPV4);
        goto pass;
    }
    if (pr == PARSE_ERR) {
        stat_inc(MFW_STAT_PARSE_ERR);
        goto drop;
    }
    if (pr == PARSE_TCP_OFF1) {
        stat_inc(MFW_STAT_TCP_FRAG_OFF1);
        goto drop;
    }
    if (p.is_frag && drop_frags()) {
        stat_inc(MFW_STAT_FRAG_DROP);
        goto drop;
    }
    rs = ruleset_of(ctx->ingress_ifindex);

    /* 1. Standard blacklist: only an explicit deny is final. */
    std = match_std(rs, p.saddr);
    if (std == MATCH_DENY) {
        stat_inc(MFW_STAT_STD_DENY);
        goto drop;
    }

    /* Non-first fragments skip the extended list: the first fragment
     * carries the ports and is filtered, and without it the kernel cannot
     * reassemble the datagram, so the rest expires in its reassembly
     * queue. */
    if (pr == PARSE_LATER_FRAG)
        goto pass;

    /* 2. Extended list decides everything else. */
    switch (match_ext(rs, &p)) {
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
    stat_inc(MFW_STAT_PASS);
    return TCX_NEXT;
drop:
    stat_inc(MFW_STAT_DROP);
    return TCX_DROP;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
