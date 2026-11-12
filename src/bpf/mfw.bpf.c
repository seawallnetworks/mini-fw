
/* SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause */

/*
 * mini-fw dataplane — step 1: stateless, ingress-only ACLs for a local
 * host. One program, attached to every protected interface, looks up the
 * ruleset of the interface the packet arrived on and evaluates, in order:
 *
 *   1. standard ACL (1–99): source-only blacklist; explicit deny → DROP,
 *      permit or miss → continue.
 *   2. replies, where an extended list is bound: a reply to a flow the
 *      host opened, in sw_flowd's table (Seawall proposal 0015 §4) →
 *      PASS, with no rule. Without the table, TCP with ACK or RST, as
 *      "established" would.
 *   3. extended ACL (100–199): permit → PASS; deny or no match → DROP
 *      (implicit deny when bound).
 *
 * Egress is not filtered. With no extended list bound there is no implicit
 * deny: whatever the standard list does not deny passes, and an interface
 * without a ruleset gets only the header checks. This is the default, not
 * a failure mode. Non-IPv4 always passes. No conntrack of its own: the
 * host's own flows are sw_flowd's, which records them at egress.
 *
 * Two entries share mfw_judge(): mfw_xdp, run by libxdp's dispatcher after
 * a DDoS gate such as voidgate, and mfw_tc, at TC ingress when another
 * program holds the XDP hook. At TC "pass" is TC_ACT_UNSPEC (tcx's
 * TCX_NEXT, which Linux 6.1's headers lack), so a tc program after
 * mini-fw still runs; "drop" is TC_ACT_SHOT (TCX_DROP).
 */


/*
 * libpkt, the stack's parser (Seawall proposal 0010): Ethernet, up to two
 * VLAN tags, IPv4, TCP/UDP. IPv4 only until mini-fw filters IPv6: an IPv6
 * frame is PKT_NOT_IP, as any other ethertype.
 */
#define PKT_NO_IPV6

#include "mfw.h"

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <libpkt/parse.h>
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/pkt_cls.h>
/* sw_flowd's ICMP error check, SF_DEFINE_ICMP_ERR_REPLY() */
#define SF_ICMP_ERR_REPLY
#include <sw_flowd/sw_flowd.h>
#include <xdp/xdp_helpers.h>


/* the replies' idle limits are in seconds, bpf_ktime_get_coarse_ns() in ns */
#define MFW_NSEC_PER_SEC  1000000000ULL

/* which entry mfw_judge() runs in: a constant, so each keeps its own call */
#define MFW_HOOK_XDP  0
#define MFW_HOOK_TC   1

/* mfw_reply()'s answers */
#define MFW_REPLY_NO           0
#define MFW_REPLY_YES          1
#define MFW_REPLY_ESTABLISHED  2   /* no table: TCP with ACK or RST */


/* mfw_judge()'s verdict; each entry turns it into its hook's */
typedef enum {
    mfw_pass = 0,
    mfw_drop
} mfw_verdict_e;


typedef enum {
    mfw_match_deny = 0,
    mfw_match_permit = 1,
    mfw_match_miss = -1,        /* list bound, no explicit ACE matched */
    mfw_match_unbound = -2      /* no access-group for this list */
} mfw_match_e;


static __always_inline void stat_inc(__u32 id);
static __always_inline int cfg_drop_ipv4_fragments(void);
static __always_inline int cfg_no_flow_table(void);

static __always_inline __be32 ipv4_addr(const __u8 *a);
static __always_inline int cidr_match(__be32 addr, const struct mfw_cidr *c);
static __always_inline int port_in_range(__u16 port,
    const struct mfw_port_range *r);

__noinline int mfw_ext_ace_match(const struct mfw_rule *r,
    const struct pkt_meta *p);

static __always_inline mfw_match_e match_std(const struct mfw_ruleset *rs,
    __be32 saddr);
static __always_inline mfw_match_e match_ext(const struct mfw_ruleset *rs,
    const struct pkt_meta *p);

static __always_inline const struct mfw_ruleset *ruleset_of(__u32 ifindex);
static __always_inline int reply_checked(__u32 ifindex);
static __always_inline int mfw_reply(const struct mfw_ruleset *rs,
    const struct pkt_meta *p, void *ctx, int hook);
static __always_inline mfw_verdict_e mfw_judge(int rc,
    const struct pkt_meta *p, __u32 ifindex, void *ctx, int hook);

int mfw_xdp(struct xdp_md *ctx);
int mfw_tc(struct __sk_buff *ctx);


/*
 * ifindex → inner map holding that interface's one mfw_ruleset. Sizes,
 * not BTF types: clang emits struct mfw_ruleset only as a forward
 * declaration here, and userspace creates the inner maps without BTF.
 */
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


/*
 * sw_flowd's table and its config (Seawall proposal 0015): mfwd binds
 * their pinned maps here before the load (bpf_map__reuse_fd), the table
 * with sw_flowd's size. Without them, these are maps of mini-fw's own
 * that stay empty: no reply.
 */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1);
    __type(key, struct sf_flow_key);
    __type(value, struct sf_flow);
} flows SEC(".maps");


struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct sf_config);
} flows_config SEC(".maps");


/*
 * sw_flowd's ICMP error check on the table, for each entry: global
 * functions, which the verifier walks once, not once a path (sw_flowd.h)
 */
SF_DEFINE_ICMP_ERR_REPLY(mfw_icmp_err_xdp, struct xdp_md, flows)
SF_DEFINE_ICMP_ERR_REPLY(mfw_icmp_err_tc, struct __sk_buff, flows)


/*
 * libxdp's dispatcher runs mini-fw after voidgate (priority 10), and only
 * a pass goes on to the next program.
 */
struct {
    __uint(priority, 20);
    __uint(XDP_PASS, 1);
} XDP_RUN_CONFIG(mfw_xdp);


char LICENSE[] SEC("license") = "Dual BSD/GPL";


static __always_inline void
stat_inc(__u32 id)
{
    struct mfw_stat_value  *v;

    v = bpf_map_lookup_elem(&stats, &id);
    if (v != NULL) {
        v->count++;
    }
}


static __always_inline int
cfg_drop_ipv4_fragments(void)
{
    __u32               k;
    struct mfw_config  *cfg;

    k = 0;
    cfg = bpf_map_lookup_elem(&config, &k);

    return cfg != NULL && cfg->drop_ipv4_fragments;
}


/* did mfwd start without sw_flowd's table? */
static __always_inline int
cfg_no_flow_table(void)
{
    __u32               k;
    struct mfw_config  *cfg;

    k = 0;
    cfg = bpf_map_lookup_elem(&config, &k);

    return cfg != NULL && cfg->no_flow_table;
}


/*
 * An IPv4 address of pkt_meta's, which keeps it in bytes. libpkt aligns
 * the addresses to 8: said here, the copy is one 4-byte load.
 */
static __always_inline __be32
ipv4_addr(const __u8 *a)
{
    __be32  addr;

    __builtin_memcpy(&addr, __builtin_assume_aligned(a, 4), sizeof(addr));

    return addr;
}

_Static_assert(_Alignof(struct pkt_meta) >= 4,
               "libpkt too old: pkt_meta's addresses not aligned");


static __always_inline int
cidr_match(__be32 addr, const struct mfw_cidr *c)
{
    __u32  mask;

    if (c->prefix > 32) {
        return 0;
    }

    mask = c->prefix ? bpf_htonl(~0u << (32 - c->prefix)) : 0;

    return (addr & mask) == (c->addr & mask);
}


static __always_inline int
port_in_range(__u16 port, const struct mfw_port_range *r)
{
    if (r->min == 0 && r->max == 0) {
        return 1;
    }

    return port >= r->min && port <= r->max;
}


/*
 * L3/L4 fields of one extended ACE vs the packet. A global (non-static)
 * function is verified once on its own, which keeps the 128-ACE loop below
 * from multiplying verifier states by every branch in here.
 */
__noinline int
mfw_ext_ace_match(const struct mfw_rule *r, const struct pkt_meta *p)
{
    if (r == NULL || p == NULL) {
        return 0;
    }

    if (r->proto != MFW_PROTO_ANY && r->proto != p->l4_proto) {
        return 0;
    }

    if (!cidr_match(ipv4_addr(p->addr_src), &r->src)
        || !cidr_match(ipv4_addr(p->addr_dst), &r->dst))
    {
        return 0;
    }

    /* ports ignored for ICMP and other protocols */
    if (p->l4_proto != IPPROTO_TCP && p->l4_proto != IPPROTO_UDP) {
        return 1;
    }

    if (!port_in_range(bpf_ntohs(p->sport), &r->sport)
        || !port_in_range(bpf_ntohs(p->dport), &r->dport))
    {
        return 0;
    }

    if ((r->flags & MFW_RULE_F_ESTABLISHED)
        && !(p->tcp_flags & (PKT_TCP_ACK | PKT_TCP_RST)))
    {
        return 0;
    }

    return 1;
}


/* Standard ACL: blacklist. Callers treat only mfw_match_deny as drop. */
static __always_inline mfw_match_e
match_std(const struct mfw_ruleset *rs, __be32 saddr)
{
    int                     i;
    const struct mfw_rule  *r;

    if (rs == NULL || !rs->std_acl) {
        return mfw_match_unbound;
    }

    for (i = 0; i < MFW_MAX_STD_ACES; i++) {
        if (i >= rs->n_std) {
            break;
        }

        r = &rs->std[i];

        if (cidr_match(saddr, &r->src)) {
            return r->action == MFW_ACTION_PERMIT ? mfw_match_permit
                                                  : mfw_match_deny;
        }
    }

    return mfw_match_miss;
}


/*
 * Extended ACL. Running off the end of a bound list reports
 * mfw_match_miss: the implicit deny, counted separately from explicit
 * deny ACEs. A bound list with no ACEs denies everything.
 */
static __always_inline mfw_match_e
match_ext(const struct mfw_ruleset *rs, const struct pkt_meta *p)
{
    int                     i;
    const struct mfw_rule  *r;

    if (rs == NULL || !rs->ext_acl) {
        return mfw_match_unbound;
    }

    for (i = 0; i < MFW_MAX_EXT_ACES; i++) {
        if (i >= rs->n_ext) {
            break;
        }

        r = &rs->ext[i];

        if (mfw_ext_ace_match(r, p)) {
            return r->action == MFW_ACTION_PERMIT ? mfw_match_permit
                                                  : mfw_match_deny;
        }
    }

    return mfw_match_miss;
}


/* the ruleset of the interface the packet arrived on, or NULL */
static __always_inline const struct mfw_ruleset *
ruleset_of(__u32 ifindex)
{
    void   *inner;
    __u32   zero;

    zero = 0;

    inner = bpf_map_lookup_elem(&rulesets, &ifindex);
    if (inner == NULL) {
        return NULL;
    }

    return bpf_map_lookup_elem(inner, &zero);
}


/*
 * Does mfw_judge() look replies up on ifindex: an extended list bound,
 * and sw_flowd's table read? Else an ICMP error's embedded header isn't
 * read, and mfw_tc doesn't pull it.
 */
static __always_inline int
reply_checked(__u32 ifindex)
{
    const struct mfw_ruleset  *rs;

    rs = ruleset_of(ifindex);

    return rs != NULL && rs->ext_acl != 0 && !cfg_no_flow_table();
}


/*
 * Is p, parsed PKT_OK, a reply to a flow the host opened (Seawall proposal
 * 0015 §2 and §4)? What sw_flowd's sf_is_reply() says is one, within rs's
 * idle limits: TCP with ACK or RST, UDP to the ephemeral range, an echo
 * reply. Or an ICMP error about a packet the host sent: of a flow in the
 * table, or a path MTU error, which passes without one, since it may be
 * about a connection the host accepted (a client of its own web server
 * across a tunnel), and the table holds only the host's own. Without
 * sw_flowd's table, MFW_REPLY_ESTABLISHED for TCP with ACK or RST: the
 * protection "established" gave, weaker than the table's, better than
 * cutting the host off.
 */
static __always_inline int
mfw_reply(const struct mfw_ruleset *rs, const struct pkt_meta *p, void *ctx,
    int hook)
{
    int             r;
    struct sf_idle  idle;

    if (cfg_no_flow_table()) {
        return p->l4_proto == IPPROTO_TCP
               && (p->tcp_flags & (PKT_TCP_ACK | PKT_TCP_RST))
               ? MFW_REPLY_ESTABLISHED : MFW_REPLY_NO;
    }

    idle.tcp_ns = rs->reply_idle_tcp * MFW_NSEC_PER_SEC;
    idle.udp_ns = rs->reply_idle_udp * MFW_NSEC_PER_SEC;

    if (sf_is_reply(&flows, &flows_config, p, &idle) == SF_REPLY) {
        return MFW_REPLY_YES;
    }

    if (!sf_is_icmp_err(p)) {
        return MFW_REPLY_NO;
    }

    if (hook == MFW_HOOK_XDP) {
        r = mfw_icmp_err_xdp(ctx, &idle);

    } else {
        r = mfw_icmp_err_tc(ctx, &idle);
    }

    /* SF_REPLY, or SF_PMTU_NO_FLOW */
    return r != SF_MISS ? MFW_REPLY_YES : MFW_REPLY_NO;
}


/*
 * The verdict on a packet that arrived on ifindex, from what pkt_parse()
 * returned for it: rc, and p. The entries parse, each from its own
 * context, of hook's kind; only an ICMP error's reply check reads the
 * packet again, from ctx, in a global function (mfw_reply()).
 */
static __always_inline mfw_verdict_e
mfw_judge(int rc, const struct pkt_meta *p, __u32 ifindex, void *ctx,
    int hook)
{
    int                        nonfirst;
    mfw_match_e                std;
    const struct mfw_ruleset  *rs;

    /*
     * libpkt reports how far it got; what that is worth is mini-fw's.
     * Another ethertype is not ours to judge.
     */
    if (rc == PKT_NOT_IP) {
        stat_inc(MFW_STAT_NON_IPV4);
        goto pass;
    }

    /*
     * The kernel's own IPv4 sanity check (ip_rcv_core()), made early, and
     * any header cut short, a VLAN tag's included: a first fragment too
     * short for its ports would slip past port ACEs (tiny-fragment
     * attack, RFC 1858).
     */
    if (rc == PKT_SHORT || rc == PKT_BAD_L3) {
        stat_inc(MFW_STAT_PARSE_ERR);
        goto drop;
    }

    /*
     * PKT_OK, or PKT_NO_L4: a non-first fragment, or an IP protocol
     * without ports. Only PKT_NO_L4 can be a non-first fragment; asked
     * of PKT_OK too, the verifier would follow both answers. A TCP
     * fragment at offset 1 (8 bytes) can only exist to overwrite the
     * flags and window of the first fragment's header after it was
     * checked (RFC 1858 §3.2); no real stack sends one.
     */
    nonfirst = rc == PKT_NO_L4 && p->frag_off != 0;

    if (nonfirst && p->frag_off == 1 && p->l4_proto == IPPROTO_TCP) {
        stat_inc(MFW_STAT_TCP_FRAG_OFF1);
        goto drop;
    }

    if ((p->flags & PKT_F_FRAG) && cfg_drop_ipv4_fragments()) {
        stat_inc(MFW_STAT_FRAG_DROP);
        goto drop;
    }

    rs = ruleset_of(ifindex);

    /* 1. Standard blacklist: only an explicit deny is final. */
    std = match_std(rs, ipv4_addr(p->addr_src));
    if (std == mfw_match_deny) {
        stat_inc(MFW_STAT_STD_DENY);
        goto drop;
    }

    /*
     * Non-first fragments skip the extended list: the first fragment
     * carries the ports and is filtered, and without it the kernel cannot
     * reassemble the datagram, so the rest expires in its reassembly
     * queue.
     */
    if (nonfirst) {
        goto pass;
    }

    /*
     * 2. Replies to the host's own flows, before the extended list, which
     * then says only who may connect in; where none is bound, everything
     * passes anyway, and nothing is looked up.
     */
    if (rc == PKT_OK && rs != NULL && rs->ext_acl != 0) {
        switch (mfw_reply(rs, p, ctx, hook)) {
        case MFW_REPLY_YES:
            stat_inc(MFW_STAT_REPLY);
            goto pass;

        case MFW_REPLY_ESTABLISHED:
            stat_inc(MFW_STAT_REPLY_ESTABLISHED);
            goto pass;
        }
    }

    /* 3. Extended list decides everything else. */
    switch (match_ext(rs, p)) {
    case mfw_match_permit:
        stat_inc(MFW_STAT_EXT_PERMIT);
        goto pass;

    case mfw_match_deny:
        stat_inc(MFW_STAT_EXT_DENY);
        goto drop;

    case mfw_match_miss:
        stat_inc(MFW_STAT_EXT_IMPLICIT_DENY);
        goto drop;

    default:
        /* extended unbound: fail-open */
        if (std == mfw_match_permit) {
            stat_inc(MFW_STAT_STD_PERMIT);
        }

        goto pass;
    }

pass:

    stat_inc(MFW_STAT_PASS);

    return mfw_pass;

drop:

    stat_inc(MFW_STAT_DROP);

    return mfw_drop;
}


/*
 * xdp.frags: the headers are in the first buffer, the only one read here,
 * so mini-fw runs on an interface with a jumbo MTU too.
 */
SEC("xdp.frags")
int
mfw_xdp(struct xdp_md *ctx)
{
    int              rc;
    void            *data, *data_end;
    mfw_verdict_e    v;
    struct pkt_meta  p;

    data = (void *) (long) ctx->data;
    data_end = (void *) (long) ctx->data_end;

    rc = pkt_parse(data, data_end, &p);

    v = mfw_judge(rc, &p, ctx->ingress_ifindex, ctx, MFW_HOOK_XDP);
    if (v == mfw_drop) {
        return XDP_DROP;
    }

    return XDP_PASS;
}


SEC("tcx/ingress")
int
mfw_tc(struct __sk_buff *ctx)
{
    int              rc;
    void            *data, *data_end;
    __u32            want;
    mfw_verdict_e    v;
    struct pkt_meta  p;

    data = (void *) (long) ctx->data;
    data_end = (void *) (long) ctx->data_end;

    /*
     * After GRO the headers may not all be in the skb's linear part, the
     * only part a TC program reads directly. Parse what is there first,
     * and pull only if a header was cut short and the linear part ends
     * before the bytes pkt_parse() could use (PKT_HDR_MAX); if it already
     * holds them, the packet is short for real. Pulling up front would
     * hit every packet whose linear part is under PKT_HDR_MAX, even one
     * that holds all its headers, and the pull makes the skb writable,
     * copying the head of a cloned skb. A pull that fails leaves a short
     * view, which the second parse reports short again.
     */
    rc = pkt_parse(data, data_end, &p);

    if (rc == PKT_SHORT) {
        want = ctx->len < PKT_HDR_MAX ? ctx->len : PKT_HDR_MAX;

        if (data + want > data_end) {
            bpf_skb_pull_data(ctx, want);
            data = (void *) (long) ctx->data;
            data_end = (void *) (long) ctx->data_end;
            rc = pkt_parse(data, data_end, &p);
        }
    }

    /*
     * An ICMP error's embedded header lies past PKT_HDR_MAX, and the
     * reply check reads it from the skb as it is: pull that far for one,
     * where the check runs. A pull makes the skb writable, copying a
     * cloned skb's head: not for errors nothing will read.
     */
    if (rc == PKT_OK && sf_is_icmp_err(&p)
        && reply_checked(ctx->ingress_ifindex))
    {
        want = ctx->len < PKT_ICMP_ERR_MAX ? ctx->len : PKT_ICMP_ERR_MAX;

        if (data + want > data_end) {
            bpf_skb_pull_data(ctx, want);
            data = (void *) (long) ctx->data;
            data_end = (void *) (long) ctx->data_end;
            rc = pkt_parse(data, data_end, &p);
        }
    }

    v = mfw_judge(rc, &p, ctx->ingress_ifindex, ctx, MFW_HOOK_TC);
    if (v == mfw_drop) {
        return TC_ACT_SHOT;
    }

    return TC_ACT_UNSPEC;
}
