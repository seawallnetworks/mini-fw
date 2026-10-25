// SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
/* A whole policy: parse and check the APPLY text, compile one interface's
 * ruleset, print the canonical form. Part of libmfw.a: no libbpf, no
 * kernel, so front ends check policies with mfwd's own rules. */
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mfw_policy.h"

/* Puts "line N: <message>" (or just the message for line 0) in err. */
static int fail(char *err, size_t len, int line, const char *fmt, ...)
{
    char msg[MFW_ERR_LEN];
    va_list ap;

    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);
    if (line)
        snprintf(err, len, "line %d: %s", line, msg);
    else
        snprintf(err, len, "%s", msg);
    return -1;
}

static int parse_num(const char *s, long min, long max, long *out)
{
    char *end;
    long v;

    if (!s || !*s)
        return -1;
    errno = 0;
    v = strtol(s, &end, 10);
    if (errno || *end || v < min || v > max)
        return -1;
    *out = v;
    return 0;
}

/* What the kernel accepts as a device name (dev_valid_name). */
static int valid_ifname(const char *s)
{
    if (!*s || strlen(s) >= IF_NAMESIZE || !strcmp(s, ".") || !strcmp(s, ".."))
        return 0;
    for (; *s; s++)
        if (*s == '/' || *s == ':' || *s <= ' ' || *s == 0x7f)
            return 0;
    return 1;
}

/* Line numbers of the bind lines, for errors found after parsing. */
struct bind_lines {
    int std[MFW_MAX_IFACES];
    int ext[MFW_MAX_IFACES];
};

/* acl <list> <seq> permit|deny ... */
static int parse_acl(struct mfw_policy *p, int argc, char **argv, int line,
                     char *err, size_t len)
{
    char msg[MFW_ERR_LEN];
    struct mfw_rule r;
    long seq;

    if (argc < 4)
        return fail(err, len, line, "expected: acl <list> <seq> permit|deny ...");
    if (parse_num(argv[2], 1, 65535, &seq))
        return fail(err, len, line, "sequence number must be 1-65535, got '%s'", argv[2]);
    if (mfw_parse_ace(argc - 1, argv + 1, &r, msg, sizeof(msg)))
        return fail(err, len, line, "%s", msg);
    for (int i = 0; i < p->n_rules; i++)
        if (p->rules[i].acl_id == r.acl_id && p->rules[i].seq == r.seq)
            return fail(err, len, line, "list %u already has sequence %u",
                        r.acl_id, r.seq);
    if (p->n_rules == MFW_ACL_MAX)
        return fail(err, len, line, "more than %d ACEs", MFW_ACL_MAX);
    r.rule_id = ((__u32)r.acl_id << 16) | r.seq;
    r.direction = MFW_DIR_INGRESS;
    p->rules[p->n_rules++] = r;
    return 0;
}

/* bind <ifname> in <list> */
static int parse_bind(struct mfw_policy *p, struct bind_lines *bl, int argc,
                      char **argv, int line, char *err, size_t len)
{
    struct mfw_bind *b = NULL;
    long acl;
    int i;

    if (argc != 4)
        return fail(err, len, line, "expected: bind <interface> in <list>");
    if (!valid_ifname(argv[1]))
        return fail(err, len, line, "bad interface name '%s'", argv[1]);
    if (!strcmp(argv[2], "out"))
        return fail(err, len, line, "'out' is not supported: egress is not filtered");
    if (strcmp(argv[2], "in"))
        return fail(err, len, line, "direction must be 'in'");
    if (parse_num(argv[3], 1, 199, &acl))
        return fail(err, len, line,
                    "list number must be 1-99 (standard) or 100-199 (extended)");

    for (i = 0; i < p->n_binds; i++)
        if (!strcmp(p->binds[i].ifname, argv[1]))
            b = &p->binds[i];
    if (!b) {
        if (p->n_binds == MFW_MAX_IFACES)
            return fail(err, len, line, "more than %d interfaces", MFW_MAX_IFACES);
        i = p->n_binds++;
        b = &p->binds[i];
        snprintf(b->ifname, sizeof(b->ifname), "%s", argv[1]);
    } else {
        i = b - p->binds;
    }

    if (mfw_is_std(acl)) {
        if (b->std_acl)
            return fail(err, len, line, "%s already has standard list %u",
                        b->ifname, b->std_acl);
        b->std_acl = acl;
        bl->std[i] = line;
    } else {
        if (b->ext_acl)
            return fail(err, len, line, "%s already has extended list %u",
                        b->ifname, b->ext_acl);
        b->ext_acl = acl;
        bl->ext[i] = line;
    }
    return 0;
}

/* set drop-ipv4-fragments 0|1, set reply-idle-tcp|reply-idle-udp N */
static int parse_set(struct mfw_policy *p, int argc, char **argv, int line,
                     char *err, size_t len)
{
    long v;

    if (argc == 3 && (!strcmp(argv[1], "reply-idle-tcp") ||
                      !strcmp(argv[1], "reply-idle-udp"))) {
        if (parse_num(argv[2], 1, MFW_REPLY_IDLE_MAX, &v))
            return fail(err, len, line, "%s must be 1-%d seconds", argv[1],
                        MFW_REPLY_IDLE_MAX);
        if (!strcmp(argv[1], "reply-idle-tcp"))
            p->reply_idle_tcp = v;
        else
            p->reply_idle_udp = v;
        return 0;
    }
    if (argc != 3 || strcmp(argv[1], "drop-ipv4-fragments") ||
        (strcmp(argv[2], "0") && strcmp(argv[2], "1")))
        return fail(err, len, line, "expected: set drop-ipv4-fragments 0|1, "
                    "or set reply-idle-tcp|reply-idle-udp <seconds>");
    p->drop_ipv4_fragments = argv[2][0] == '1';
    return 0;
}

static int parse_line(struct mfw_policy *p, struct bind_lines *bl, char *s,
                      int line, char *err, size_t len)
{
    char *argv[40], *save = NULL, *hash = strchr(s, '#');
    int argc = 0;

    if (hash)  /* a comment, to the end of the line */
        *hash = '\0';
    for (char *t = strtok_r(s, " \t\r", &save); t; t = strtok_r(NULL, " \t\r", &save)) {
        if (argc == 40)
            return fail(err, len, line, "too many words");
        argv[argc++] = t;
    }
    if (!argc)
        return 0;
    if (!strcmp(argv[0], "acl"))
        return parse_acl(p, argc, argv, line, err, len);
    if (!strcmp(argv[0], "bind"))
        return parse_bind(p, bl, argc, argv, line, err, len);
    if (!strcmp(argv[0], "set"))
        return parse_set(p, argc, argv, line, err, len);
    return fail(err, len, line, "unknown keyword '%s' (acl, bind or set)", argv[0]);
}

static int rule_cmp(const void *a, const void *b)
{
    const struct mfw_rule *x = a, *y = b;

    if (x->acl_id != y->acl_id)
        return x->acl_id - y->acl_id;
    return x->seq - y->seq;
}

static int count_list(const struct mfw_policy *p, __u16 acl)
{
    int n = 0;

    for (int i = 0; i < p->n_rules; i++)
        n += p->rules[i].acl_id == acl;
    return n;
}

/* Every bound list must fit its half of the ruleset. */
static int check_sizes(const struct mfw_policy *p, const struct bind_lines *bl,
                       char *err, size_t len)
{
    for (int i = 0; i < p->n_binds; i++) {
        const struct mfw_bind *b = &p->binds[i];
        int n;

        if (b->std_acl && (n = count_list(p, b->std_acl)) > MFW_MAX_STD_ACES)
            return fail(err, len, bl->std[i],
                        "standard list %u has %d ACEs; at most %d can be bound",
                        b->std_acl, n, MFW_MAX_STD_ACES);
        if (b->ext_acl && (n = count_list(p, b->ext_acl)) > MFW_MAX_EXT_ACES)
            return fail(err, len, bl->ext[i],
                        "extended list %u has %d ACEs; at most %d can be bound",
                        b->ext_acl, n, MFW_MAX_EXT_ACES);
    }
    return 0;
}

static int bind_cmp(const void *a, const void *b)
{
    const struct mfw_bind *x = a, *y = b;

    return strcmp(x->ifname, y->ifname);
}

int mfw_policy_parse(const char *text, struct mfw_policy *p,
                     char *err, size_t errlen)
{
    struct bind_lines bl = {};
    char *copy, *line, *next;
    int n = 0, rc = 0;

    memset(p, 0, sizeof(*p));
    p->reply_idle_tcp = MFW_REPLY_IDLE_TCP;
    p->reply_idle_udp = MFW_REPLY_IDLE_UDP;
    copy = strdup(text);
    p->rules = calloc(MFW_ACL_MAX, sizeof(*p->rules));
    if (!copy || !p->rules) {
        free(copy);
        mfw_policy_free(p);
        return fail(err, errlen, 0, "out of memory");
    }

    for (line = copy; line && !rc; line = next) {
        next = strchr(line, '\n');
        if (next)
            *next++ = '\0';
        rc = parse_line(p, &bl, line, ++n, err, errlen);
    }
    free(copy);

    if (!rc)
        rc = check_sizes(p, &bl, err, errlen);
    if (rc) {
        mfw_policy_free(p);
        return -1;
    }
    qsort(p->rules, p->n_rules, sizeof(*p->rules), rule_cmp);
    qsort(p->binds, p->n_binds, sizeof(*p->binds), bind_cmp);
    return 0;
}

void mfw_policy_free(struct mfw_policy *p)
{
    free(p->rules);
    memset(p, 0, sizeof(*p));
}

/* The ACEs of list acl, in seq order, into out[]. Returns how many. */
static int copy_list(const struct mfw_policy *p, __u16 acl, struct mfw_rule *out, int max)
{
    int n = 0;

    for (int i = 0; i < p->n_rules && n < max; i++)
        if (p->rules[i].acl_id == acl)
            out[n++] = p->rules[i];
    return n;
}

void mfw_policy_compile(const struct mfw_policy *p, int i, struct mfw_ruleset *rs)
{
    const struct mfw_bind *b = &p->binds[i];

    memset(rs, 0, sizeof(*rs));
    rs->std_acl = b->std_acl;
    rs->ext_acl = b->ext_acl;
    if (b->std_acl)
        rs->n_std = copy_list(p, b->std_acl, rs->std, MFW_MAX_STD_ACES);
    /* a bound extended list denies what it does not permit, even when empty */
    if (b->ext_acl)
        rs->n_ext = copy_list(p, b->ext_acl, rs->ext, MFW_MAX_EXT_ACES);
    /* each "reply" ACE carries its protocol's idle limit: no map for it */
    for (int j = 0; j < rs->n_ext; j++)
        if (rs->ext[j].flags & MFW_RULE_F_REPLY)
            rs->ext[j].reply_idle = rs->ext[j].proto == MFW_PROTO_TCP
                                    ? p->reply_idle_tcp : p->reply_idle_udp;
}

char *mfw_policy_format(const struct mfw_policy *p)
{
    size_t size = (size_t)p->n_rules * 160 + (size_t)p->n_binds * 2 * 48 + 128;
    char *buf = malloc(size), ace[160];
    size_t off = 0;

    if (!buf)
        return NULL;
    buf[0] = '\0';
    for (int i = 0; i < p->n_rules; i++) {
        mfw_format_ace(&p->rules[i], ace, sizeof(ace));
        off += snprintf(buf + off, size - off, "acl %u %u %s\n",
                        p->rules[i].acl_id, p->rules[i].seq, ace);
    }
    for (int i = 0; i < p->n_binds; i++) {
        if (p->binds[i].std_acl)
            off += snprintf(buf + off, size - off, "bind %s in %u\n",
                            p->binds[i].ifname, p->binds[i].std_acl);
        if (p->binds[i].ext_acl)
            off += snprintf(buf + off, size - off, "bind %s in %u\n",
                            p->binds[i].ifname, p->binds[i].ext_acl);
    }
    snprintf(buf + off, size - off, "set drop-ipv4-fragments %d\n"
             "set reply-idle-tcp %u\nset reply-idle-udp %u\n",
             p->drop_ipv4_fragments, p->reply_idle_tcp, p->reply_idle_udp);
    return buf;
}
