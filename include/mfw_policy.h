/* SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause */
/*
 * mfw_policy.h — parse, check and compile mini-fw policies. Part of
 * libmfw.a: pure C, no libbpf, no privileges, so a front end such as
 * sw_configd checks a policy with exactly the rules mfwd applies.
 *
 * A policy is the whole desired state, as sent with APPLY, one item per
 * line:
 *
 *     acl 10 10 deny host 203.0.113.66
 *     acl 100 10 permit tcp any host 10.0.0.5 eq 22
 *     bind eth0 in 10
 *     bind eth0 in 100
 *     set drop-ipv4-fragments 0
 *     set reply-idle-tcp 86400
 *     set reply-idle-udp 180
 *
 * "acl <list> <seq> <ACE>" defines one ACE in Cisco syntax; "bind <if> in
 * <list>" puts a list on an interface (one standard and one extended list
 * per interface); the "set" items are global. An extended tcp or udp ACE
 * that ends in "reply" matches only replies to flows the host opened, as
 * sw_flowd recorded them, that last left within reply-idle-tcp or
 * reply-idle-udp seconds (default 86400 and 180); without sw_flowd it
 * matches nothing. '#' starts a comment, to the end of the line; blank
 * lines are ignored. Lists that are not bound are kept but enforce
 * nothing.
 */
#ifndef MFW_POLICY_H
#define MFW_POLICY_H

#include <net/if.h>
#include <stddef.h>
#include "mfw.h"

#define MFW_ACL_MAX     4096   /* ACEs in one policy, all lists */
#define MFW_ERR_LEN     256    /* enough for any error message below */

static inline int mfw_is_std(int acl_id)
{
    return acl_id >= 1 && acl_id <= 99;
}

static inline int mfw_is_ext(int acl_id)
{
    return acl_id >= 100 && acl_id <= 199;
}

/* ---- one ACE ---- */

/* Parse "A.B.C.D" (network order). 0 on success. */
int mfw_parse_ipv4(const char *s, __be32 *out);
/* Contiguous wildcard → prefix length, or -1 if non-contiguous. */
int mfw_wildcard_to_prefix(__be32 wildcard);
/*
 * Parse one Cisco ACE: argv = { "<list>", ["<seq>"], "permit|deny", ... }.
 * seq is left 0 when not given. Returns 0, or -1 with a message in err.
 */
int mfw_parse_ace(int argc, char **argv, struct mfw_rule *out,
                  char *err, size_t errlen);
/* The same from one string, split at blanks. */
int mfw_parse_ace_line(const char *line, struct mfw_rule *out,
                       char *err, size_t errlen);
/* Render an ACE back to Cisco syntax, without list and seq. */
void mfw_format_ace(const struct mfw_rule *r, char *buf, size_t len);

/* ---- a whole policy ---- */

/* The lists bound on one interface (inbound; egress is not filtered). */
struct mfw_bind {
    char  ifname[IF_NAMESIZE];
    __u16 std_acl;              /* 0 = none */
    __u16 ext_acl;              /* 0 = none */
};

struct mfw_policy {
    struct mfw_rule *rules;     /* sorted by (acl_id, seq); malloc'd */
    int              n_rules;
    struct mfw_bind  binds[MFW_MAX_IFACES];   /* sorted by ifname */
    int              n_binds;
    int              drop_ipv4_fragments;
    __u32            reply_idle_tcp;    /* seconds */
    __u32            reply_idle_udp;
};

/*
 * Parse and check a policy. On error, returns -1 and err says which line
 * and why: "line 3: non-contiguous wildcard '0.0.2.255' not supported".
 * Checks: syntax, duplicate (list, seq), at most one standard and one
 * extended list per interface, at most MFW_MAX_IFACES interfaces and
 * MFW_ACL_MAX ACEs, and that every bound list fits its ruleset (64
 * standard, 128 extended ACEs). On success *p must be freed with
 * mfw_policy_free().
 */
int mfw_policy_parse(const char *text, struct mfw_policy *p,
                     char *err, size_t errlen);
void mfw_policy_free(struct mfw_policy *p);

/* The ruleset for p->binds[i], ready for the dataplane. */
void mfw_policy_compile(const struct mfw_policy *p, int i,
                        struct mfw_ruleset *rs);

/*
 * The policy in canonical form, as mfwd stores and SHOW prints it: acl
 * lines by (list, seq), then bind lines by interface, then the set lines.
 * Parsing it gives the same policy. malloc'd; NULL without memory.
 */
char *mfw_policy_format(const struct mfw_policy *p);

#endif /* MFW_POLICY_H */
