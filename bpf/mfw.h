/* SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause */
/* mfw.h — shared between BPF and userspace (fixed width, no padding holes).
 *
 * Step 1 (stateless, ingress only): standard and extended ACLs both run in
 * one XDP program. Egress is not filtered (local-VM protection only).
 */
#ifndef MFW_H
#define MFW_H

#include <linux/types.h>

#define MFW_MAX_STD_ACES       64     /* standard ACL map */
#define MFW_MAX_EXT_ACES       128    /* extended ACL map */
#define MFW_PIN_PATH           "/sys/fs/bpf/mfw"
#define MFW_ABI_VERSION        1

/* Rule action */
enum mfw_action {
    MFW_ACTION_DENY  = 0,
    MFW_ACTION_ALLOW = 1,
};

/* Direction flags (bitmask). Step 1 binds ingress only; kept for ABI. */
enum mfw_dir {
    MFW_DIR_INGRESS = 1 << 0,  /* in  */
    MFW_DIR_EGRESS  = 1 << 1,  /* out */
    MFW_DIR_BOTH    = MFW_DIR_INGRESS | MFW_DIR_EGRESS,
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
    MFW_ACL_STANDARD = 1,  /* lists 1–99: source only; dst/proto/ports ignored */
    MFW_ACL_EXTENDED = 2,  /* lists 100–199: full L4 match */
};

/* mfw_rule.flags */
#define MFW_RULE_F_ESTABLISHED  (1 << 0)  /* Cisco "established": TCP with ACK or RST */
#define MFW_RULE_F_IMPLICIT     (1 << 1)  /* synthetic trailing "deny ip any any" */

struct mfw_cidr {
    __be32 addr;   /* IPv4 network address, big-endian wire order ONLY */
    __u8   prefix; /* 0..32; BPF skips rule if >32 */
    __u8   pad[3];
};

struct mfw_port_range {
    __u16 min;    /* host byte order */
    __u16 max;    /* inclusive; (0,0) = any; cannot match real port 0 */
};

/*
 * One ACE — Cisco "access-list N …" line.
 * Same layout for standard and extended; standard match ignores
 * dst/proto/ports. Maps acl_std and acl_ext both hold mfw_rule[], packed
 * from index 0 (first !enabled entry terminates the scan; an empty map
 * means the list is not bound).
 */
struct mfw_rule {
    __u16 acl_id;       /* 1–99 standard, 100–199 extended */
    __u16 seq;          /* line order; lower first */
    __u8  action;       /* MFW_ACTION_ALLOW / DENY */
    __u8  proto;        /* 0=any/ip; ignored for standard */
    __u8  direction;    /* MFW_DIR_*; always MFW_DIR_INGRESS in step 1 */
    __u8  enabled;
    __u8  kind;         /* MFW_ACL_STANDARD | MFW_ACL_EXTENDED */
    __u8  flags;        /* MFW_RULE_F_* */
    __u8  pad0[2];
    struct mfw_cidr src;
    struct mfw_cidr dst;           /* any for standard */
    struct mfw_port_range sport;   /* any for standard */
    struct mfw_port_range dport;
    __u32 rule_id;      /* stable id for delete */
    __u32 pad1;
};

struct mfw_config {
    __u8  default_action;      /* ABI: always MFW_ACTION_DENY in v1; BPF ignores */
    __u8  drop_ipv4_fragments; /* 1 = XDP_DROP all IPv4 fragments */
    __u8  abi_version;         /* MFW_ABI_VERSION */
    __u8  pad0;
    __u32 generation;          /* bumped on rule updates */
};

/* Stats: every packet increments exactly one OUTCOME and at most one REASON.
 * Append new ids at the end so the pinned stats layout stays stable. */
enum mfw_stat_id {
    /* Outcomes */
    MFW_STAT_XDP_PASS = 0,
    MFW_STAT_XDP_DROP,
    /* Reasons */
    MFW_STAT_STD_DENY,          /* standard list: explicit deny */
    MFW_STAT_STD_PERMIT,        /* standard list: explicit permit, no extended list */
    MFW_STAT_EXT_PERMIT,        /* extended list: explicit permit */
    MFW_STAT_EXT_DENY,          /* extended list: explicit deny */
    MFW_STAT_EXT_IMPLICIT_DENY, /* extended list: no ACE matched */
    MFW_STAT_PARSE_ERR,         /* corrupt IPv4 */
    MFW_STAT_FRAG_DROP,         /* drop_ipv4_fragments=1 */
    MFW_STAT_NON_IPV4,          /* passed untouched */
    MFW_STAT_MAX,
};

struct mfw_stat_value {
    __u64 count;
};

#endif /* MFW_H */
