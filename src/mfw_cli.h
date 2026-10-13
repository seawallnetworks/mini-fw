/* SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause */
/* Internal userspace declarations for the mfw CLI. */
#ifndef MFW_CLI_H
#define MFW_CLI_H

#include <stddef.h>
#include <stdint.h>
#include "mfw_uapi.h"

/* Exit codes (design: API / Interface Changes) */
#define EXIT_OK          0
#define EXIT_USAGE       1
#define EXIT_KERNEL      2
#define EXIT_NOT_ATTACHED 3
#define EXIT_VALIDATION  4

#define MFW_MAPS_DIR   MFW_PIN_PATH "/maps"
#define MFW_LINK_DIR   MFW_PIN_PATH "/link"
#define MFW_STATE_DIR  MFW_PIN_PATH "/state"   /* userspace-only maps */

#define MFW_ACL_DB_MAX 4096

/* state/bindings: ifindex → the inbound lists bound on that interface
 * (egress is not filtered; both lists run in XDP) */
struct mfw_binding {
    __u16 std_acl;     /* standard list (1-99), 0 = none */
    __u16 ext_acl;     /* extended list (100-199), 0 = none */
    char  ifname[16];  /* for display and to notice a reused ifindex */
};

/* acl_db key: one ACE per (list, seq) */
static inline __u32 mfw_db_key(__u16 acl_id, __u16 seq)
{
    return ((__u32)acl_id << 16) | seq;
}

static inline int mfw_is_std(int acl_id) { return acl_id >= 1 && acl_id <= 99; }
static inline int mfw_is_ext(int acl_id) { return acl_id >= 100 && acl_id <= 199; }

/* ---- acl_parse.c (pure; unit-tested) ---- */

/* Parse "A.B.C.D" (network order). 0 on success. */
int mfw_parse_ipv4(const char *s, __be32 *out);
/* Contiguous wildcard → prefix length, or -1 if non-contiguous. */
int mfw_wildcard_to_prefix(__be32 wildcard);
/*
 * Parse one Cisco ACE: argv = { "<list>", ["<seq>"], "permit|deny", ... }.
 * seq is left 0 when not given. Returns EXIT_OK, or EXIT_VALIDATION /
 * EXIT_USAGE with a message in err.
 */
int mfw_parse_ace(int argc, char **argv, struct mfw_rule *out,
                  char *err, size_t errlen);
/* Render an ACE back to Cisco syntax (without list number). */
void mfw_format_ace(const struct mfw_rule *r, char *buf, size_t len);

/* ---- acl.c ---- */
int cmd_access_list(int argc, char **argv);
int cmd_no_access_list(int argc, char **argv);
int cmd_access_group(int argc, char **argv, int negate);
int cmd_show_access_lists(int argc, char **argv);
int cmd_show_access_group(int argc, char **argv);
/* Build each attached interface's ruleset and swap it in, if the dataplane
 * maps are pinned. */
int mfw_materialize(void);
/* Remove ifindex's ruleset (detach); bindings are kept for a re-attach. */
void mfw_forget_iface(__u32 ifindex);

/* ---- loader.c ---- */
int cmd_attach(int argc, char **argv);
int cmd_detach(int argc, char **argv);
int mfw_ensure_dir(const char *path);
int mfw_open_pinned(const char *path);   /* fd or -errno */
int mfw_iface_attached(const char *ifname);

/* ---- stats.c ---- */
int cmd_stats(int argc, char **argv);
int cmd_set(int argc, char **argv);

#endif /* MFW_CLI_H */
