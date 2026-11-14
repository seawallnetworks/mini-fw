
/* SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause */

/*
 * mfw.h — shared between BPF and userspace (fixed width, no padding holes).
 *
 * Step 1 (stateless, ingress only): standard and extended ACLs both run in
 * one program, at XDP in libxdp's dispatcher or at TC ingress. Egress is
 * not filtered (local-VM protection only). Each interface has its own
 * ruleset (struct mfw_ruleset), found by the ifindex the packet arrived
 * on. Replies to the flows the host opened, in sw_flowd's table, pass
 * before the extended list, with no rule (Seawall proposal 0015 §4);
 * mfw.h itself doesn't need sw_flowd.h, so front ends build without it.
 */


#ifndef _MFW_H_INCLUDED_
#define _MFW_H_INCLUDED_


#include <linux/types.h>


#define MFW_MAX_STD_ACES  64     /* a ruleset's std[] */
#define MFW_MAX_EXT_ACES  128    /* a ruleset's ext[] */
#define MFW_MAX_IFACES    64     /* interfaces with a ruleset */

/* under the stack's bpffs directory, beside sw_flowd's flows/ */
#define MFW_PIN_PATH  "/sys/fs/bpf/seawall/mfw"

/*
 * Layout of the pinned maps, shown by mfwd -V; a starting mfwd replaces
 * the pins, of any version. 2: per-interface rulesets; 3: no unused
 * fields; 4: replies pass by default, the idle limits in the ruleset;
 * 5: reply_dhcp, reply_miss and its samples
 */
#define MFW_ABI_VERSION  5

/* mfw_rule.flags */
#define MFW_RULE_F_ESTABLISHED  (1 << 0)  /* established: ACK or RST set */

/*
 * The idle limits of replies, in seconds: how long after a flow last left
 * its replies still pass ("set reply-idle-tcp|reply-idle-udp N")
 */
#define MFW_REPLY_IDLE_TCP  86400
#define MFW_REPLY_IDLE_UDP  180
#define MFW_REPLY_IDLE_MAX  31536000  /* a year */


/* Rule action */
enum mfw_action {
    MFW_ACTION_DENY   = 0,
    MFW_ACTION_PERMIT = 1,
};


/* L4 proto filter: 0 = any */
enum mfw_proto {
    MFW_PROTO_ANY  = 0,
    MFW_PROTO_ICMP = 1,   /* IPPROTO_ICMP */
    MFW_PROTO_TCP  = 6,
    MFW_PROTO_UDP  = 17,
};


/* ACL list kind (userspace validates range; BPF only sees compiled ACEs) */
enum mfw_acl_kind {
    MFW_ACL_STANDARD = 1,  /* lists 1–99: source only; dst/proto/ports unused */
    MFW_ACL_EXTENDED = 2,  /* lists 100–199: full L4 match */
};


struct mfw_cidr {
    __be32                 addr;      /* IPv4 address, network order */
    __u8                   prefix;    /* 0..32; a larger never matches */
    __u8                   pad[3];
};


/* An inclusive range, host byte order; (0,0) is any, so port 0 can't be one. */
struct mfw_port_range {
    __u16                  min;
    __u16                  max;
};


/*
 * One ACE — Cisco "access-list N …" line. Same layout for standard and
 * extended; standard match ignores dst/proto/ports. A ruleset holds them
 * packed from index 0; its n_std / n_ext say how many are in use.
 */
struct mfw_rule {
    __u16                  acl_id;    /* 1–99 standard, 100–199 extended */
    __u16                  seq;       /* line order; lower first */
    __u8                   action;    /* MFW_ACTION_PERMIT / DENY */
    __u8                   proto;     /* 0=any/ip; ignored for standard */
    __u8                   kind;      /* MFW_ACL_STANDARD | _EXTENDED */
    __u8                   flags;     /* MFW_RULE_F_* */
    struct mfw_cidr        src;
    struct mfw_cidr        dst;       /* any for standard */
    struct mfw_port_range  sport;     /* any for standard */
    struct mfw_port_range  dport;
};


/*
 * Everything one interface enforces: its bound standard and extended
 * lists, compiled. The value of the single entry of an inner map in the
 * "rulesets" map-in-map. Userspace never changes an installed one: it
 * fills a new inner map and swaps it in, so a packet sees either the old
 * ruleset or the new one, never a mix. A packet no ACE of a bound
 * extended list matches is dropped (implicit deny); with none bound, it
 * passes. Where one is bound, a reply to a flow the host opened passes
 * before it, within the policy's idle limits, which travel here with
 * the rules.
 */
struct mfw_ruleset {
    __u16                  std_acl;   /* bound standard list, 0 = none */
    __u16                  ext_acl;   /* bound extended list, 0 = none */
    __u16                  n_std;     /* std[0 .. n_std) in use */
    __u16                  n_ext;     /* ext[0 .. n_ext) in use */
    __u32                  reply_idle_tcp;  /* seconds: set reply-idle-tcp */
    __u32                  reply_idle_udp;  /* seconds: set reply-idle-udp */
    struct mfw_rule        std[MFW_MAX_STD_ACES];
    struct mfw_rule        ext[MFW_MAX_EXT_ACES];
};


/*
 * Settings for every interface: the single entry (key 0) of the "config"
 * array map. mfwd writes it; BPF reads drop_ipv4_fragments and
 * no_flow_table. All zeros is a new map that mfwd has yet to set up:
 * abi_version is 0.
 */
struct mfw_config {
    __u8                   drop_ipv4_fragments;  /* 1: drop all fragments */
    __u8                   abi_version;          /* MFW_ABI_VERSION */
    /*
     * 1: mfwd started without sw_flowd's table, and replies fall back to
     * "established": TCP with ACK or RST passes, and fragmentation needed,
     * which needs no table; UDP and other ICMP go to the lists
     */
    __u8                   no_flow_table;
    __u8                   pad0;
    __u32                  generation;           /* bumped on every apply */
};


/*
 * Stats: every packet increments exactly one OUTCOME and at most one
 * REASON. STATS names each counter, and libmfw reads them by name; its
 * mfw_stats() fills an array indexed by these ids, so a front end must
 * be built against the mfw.h of the libmfw.a it links.
 */
/*
 * reply_miss's samples (Seawall proposal 0015 §7): a packet that looked
 * like a reply (TCP with ACK or RST, UDP to a port sw_flowd's replies come
 * back to, an echo reply, an ICMP error) found no flow, and the extended
 * list dropped it. Each CPU keeps its last MFW_MISS_SAMPLES in a ring of
 * its own, so a flood writes no line another CPU shares; mfwd merges them
 * and keeps the newest.
 */
#define MFW_MISS_SAMPLES  16

struct mfw_miss_sample {
    __u64                  time_ns;     /* CLOCK_MONOTONIC; 0: an empty slot */
    __u32                  ifindex;
    __be32                 saddr;
    __be32                 daddr;
    __be16                 sport;       /* TCP and UDP */
    __be16                 dport;
    __u8                   proto;       /* IPPROTO_* */
    __u8                   tcp_flags;   /* PKT_TCP_* */
    __u8                   icmp_type;
    __u8                   icmp_code;
    __u32                  pad;
};

/* PERCPU_ARRAY[1], pinned as maps/misses: s[next % MFW_MISS_SAMPLES] is
 * written next */
struct mfw_misses {
    __u32                  next;
    __u32                  pad;
    struct mfw_miss_sample s[MFW_MISS_SAMPLES];
};


enum mfw_stat_id {
    /* Outcomes; named xdp_pass and xdp_drop in STATS, whichever the hook */
    MFW_STAT_PASS = 0,
    MFW_STAT_DROP,
    /* Reasons */
    MFW_STAT_STD_DENY,          /* standard list: explicit deny */
    MFW_STAT_STD_PERMIT,        /* standard explicit permit, extended unbound */
    MFW_STAT_EXT_PERMIT,        /* extended list: explicit permit */
    MFW_STAT_EXT_DENY,          /* extended list: explicit deny */
    MFW_STAT_EXT_IMPLICIT_DENY, /* extended list: no ACE matched */
    MFW_STAT_PARSE_ERR,         /* a header cut short or malformed */
    MFW_STAT_FRAG_DROP,         /* drop_ipv4_fragments=1 */
    MFW_STAT_NON_IPV4,          /* passed untouched */
    MFW_STAT_TCP_FRAG_OFF1,     /* TCP fragment at offset 1 (RFC 1858) */
    MFW_STAT_REPLY,             /* a reply to a flow the host opened */
    MFW_STAT_REPLY_ESTABLISHED, /* no sw_flowd table: TCP with ACK or RST */
    MFW_STAT_REPLY_DHCP,        /* UDP from 67 to 68, a DHCP server's */
    MFW_STAT_REPLY_MISS,        /* looked like a reply, no flow, dropped */
    MFW_STAT_MAX,
};


struct mfw_stat_value {
    __u64                  count;
};


#endif /* _MFW_H_INCLUDED_ */
