// SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
/* Cisco IOS ACE parsing / formatting. No libbpf, no kernel: unit-testable. */
#include <arpa/inet.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mfw_cli.h"

static int fail(char *err, size_t len, int code, const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    vsnprintf(err, len, fmt, ap);
    va_end(ap);
    return code;
}

static int parse_uint(const char *s, long min, long max, long *out)
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

int mfw_parse_ipv4(const char *s, __be32 *out)
{
    struct in_addr a;

    if (!s || inet_pton(AF_INET, s, &a) != 1)
        return -1;
    *out = a.s_addr;
    return 0;
}

int mfw_wildcard_to_prefix(__be32 wildcard)
{
    __u32 w = ntohl(wildcard);
    int host_bits = 0;

    /* Contiguous wildcard = 0…01…1 (low bits set). */
    while (host_bits < 32 && (w & (1u << host_bits)))
        host_bits++;
    if (host_bits < 32 && (w >> host_bits) != 0)
        return -1;
    return 32 - host_bits;
}

static __be32 prefix_mask(int prefix)
{
    return prefix ? htonl(~0u << (32 - prefix)) : 0;
}

/*
 * Address operand: "any" | "host A" | "A/P" | "A W" (wildcard).
 * Standard lists also accept a bare "A" (= host A) as the last token.
 */
static int parse_addr(int argc, char **argv, int *i, int bare_host_ok,
                      struct mfw_cidr *c, char *err, size_t errlen)
{
    const char *tok = *i < argc ? argv[*i] : NULL;
    __be32 a, w;
    long p;

    memset(c, 0, sizeof(*c));
    if (!tok)
        return fail(err, errlen, EXIT_USAGE, "missing address");

    if (!strcmp(tok, "any")) {
        (*i)++;
        return EXIT_OK;
    }
    if (!strcmp(tok, "host")) {
        if (*i + 1 >= argc || mfw_parse_ipv4(argv[*i + 1], &a))
            return fail(err, errlen, EXIT_VALIDATION,
                        "'host' needs an IPv4 address");
        c->addr = a;
        c->prefix = 32;
        *i += 2;
        return EXIT_OK;
    }

    const char *slash = strchr(tok, '/');

    if (slash) {
        char ip[INET_ADDRSTRLEN];
        size_t n = slash - tok;

        if (n >= sizeof(ip))
            return fail(err, errlen, EXIT_VALIDATION, "bad CIDR '%s'", tok);
        memcpy(ip, tok, n);
        ip[n] = '\0';
        if (mfw_parse_ipv4(ip, &a) || parse_uint(slash + 1, 0, 32, &p))
            return fail(err, errlen, EXIT_VALIDATION, "bad CIDR '%s'", tok);
        c->prefix = (__u8)p;
        c->addr = a & prefix_mask(c->prefix);
        (*i)++;
        return EXIT_OK;
    }

    if (mfw_parse_ipv4(tok, &a))
        return fail(err, errlen, EXIT_VALIDATION, "bad address '%s'", tok);

    if (*i + 1 < argc && mfw_parse_ipv4(argv[*i + 1], &w) == 0) {
        int pfx = mfw_wildcard_to_prefix(w);

        if (pfx < 0)
            return fail(err, errlen, EXIT_VALIDATION,
                        "non-contiguous wildcard '%s' not supported",
                        argv[*i + 1]);
        c->prefix = (__u8)pfx;
        c->addr = a & prefix_mask(pfx);
        *i += 2;
        return EXIT_OK;
    }
    if (!bare_host_ok)
        return fail(err, errlen, EXIT_VALIDATION,
                    "'%s' needs a wildcard (or use 'host %s')", tok, tok);
    c->addr = a;
    c->prefix = 32;
    (*i)++;
    return EXIT_OK;
}

/* Optional port operand: "eq N" | "range LO HI" | "gt N" | "lt N". */
static int parse_port(int argc, char **argv, int *i, int ports_ok,
                      struct mfw_port_range *r, char *err, size_t errlen)
{
    const char *op = *i < argc ? argv[*i] : NULL;
    long a, b;

    r->min = r->max = 0;
    if (!op || (strcmp(op, "eq") && strcmp(op, "range") &&
                strcmp(op, "gt") && strcmp(op, "lt")))
        return EXIT_OK;  /* omitted = any */
    if (!ports_ok)
        return fail(err, errlen, EXIT_VALIDATION,
                    "ports are only valid with tcp or udp");

    if (!strcmp(op, "range")) {
        if (*i + 2 >= argc || parse_uint(argv[*i + 1], 1, 65535, &a) ||
            parse_uint(argv[*i + 2], 1, 65535, &b) || a > b)
            return fail(err, errlen, EXIT_VALIDATION,
                        "'range' needs LO HI with 1 <= LO <= HI <= 65535");
        *i += 3;
    } else {
        if (*i + 1 >= argc || parse_uint(argv[*i + 1], 1, 65535, &a))
            return fail(err, errlen, EXIT_VALIDATION,
                        "'%s' needs a port 1-65535", op);
        b = a;
        if (!strcmp(op, "gt")) {
            if (a == 65535)
                return fail(err, errlen, EXIT_VALIDATION, "'gt 65535' matches nothing");
            a = a + 1;
            b = 65535;
        } else if (!strcmp(op, "lt")) {
            if (a == 1)
                return fail(err, errlen, EXIT_VALIDATION, "'lt 1' matches nothing");
            b = a - 1;
            a = 1;
        }
        *i += 2;
    }
    r->min = (__u16)a;
    r->max = (__u16)b;
    return EXIT_OK;
}

static int parse_proto(const char *s, __u8 *proto)
{
    long v;

    if (!strcmp(s, "ip"))        *proto = MFW_PROTO_ANY;
    else if (!strcmp(s, "tcp"))  *proto = MFW_PROTO_TCP;
    else if (!strcmp(s, "udp"))  *proto = MFW_PROTO_UDP;
    else if (!strcmp(s, "icmp")) *proto = MFW_PROTO_ICMP;
    else if (parse_uint(s, 0, 255, &v) == 0) *proto = (__u8)v;
    else return -1;
    return 0;
}

int mfw_parse_ace(int argc, char **argv, struct mfw_rule *out,
                  char *err, size_t errlen)
{
    long acl, seq = 0;
    int i = 0, rc;

    memset(out, 0, sizeof(*out));
    if (argc < 2)
        return fail(err, errlen, EXIT_USAGE, "usage: access-list <list> [seq] permit|deny ...");
    if (parse_uint(argv[i++], 1, 199, &acl))
        return fail(err, errlen, EXIT_VALIDATION,
                    "list number must be 1-99 (standard) or 100-199 (extended)");

    if (strcmp(argv[i], "permit") && strcmp(argv[i], "deny")) {
        if (parse_uint(argv[i], 1, 65535, &seq))
            return fail(err, errlen, EXIT_VALIDATION,
                        "expected permit|deny or a sequence number 1-65535, got '%s'", argv[i]);
        i++;
    }
    if (i >= argc || (strcmp(argv[i], "permit") && strcmp(argv[i], "deny")))
        return fail(err, errlen, EXIT_USAGE, "expected permit|deny");

    out->acl_id = (__u16)acl;
    out->seq = (__u16)seq;
    out->action = !strcmp(argv[i++], "permit") ? MFW_ACTION_ALLOW : MFW_ACTION_DENY;
    out->enabled = 1;

    if (mfw_is_std(acl)) {
        out->kind = MFW_ACL_STANDARD;
        rc = parse_addr(argc, argv, &i, 1, &out->src, err, errlen);
        if (rc)
            return rc;
        if (i < argc)
            return fail(err, errlen, EXIT_VALIDATION,
                        "standard lists (1-99) match source only; unexpected '%s'", argv[i]);
        return EXIT_OK;
    }

    out->kind = MFW_ACL_EXTENDED;
    if (i >= argc)
        return fail(err, errlen, EXIT_USAGE, "extended ACE needs a protocol");
    if (parse_proto(argv[i], &out->proto))
        return fail(err, errlen, EXIT_VALIDATION,
                    "unknown protocol '%s' (ip|tcp|udp|icmp|0-255)", argv[i]);
    i++;

    int ports_ok = out->proto == MFW_PROTO_TCP || out->proto == MFW_PROTO_UDP;

    if ((rc = parse_addr(argc, argv, &i, 0, &out->src, err, errlen)) ||
        (rc = parse_port(argc, argv, &i, ports_ok, &out->sport, err, errlen)) ||
        (rc = parse_addr(argc, argv, &i, 0, &out->dst, err, errlen)) ||
        (rc = parse_port(argc, argv, &i, ports_ok, &out->dport, err, errlen)))
        return rc;

    if (i < argc && !strcmp(argv[i], "established")) {
        if (out->proto != MFW_PROTO_TCP)
            return fail(err, errlen, EXIT_VALIDATION,
                        "'established' is only valid with tcp");
        out->flags |= MFW_RULE_F_ESTABLISHED;
        i++;
    }
    if (i < argc)
        return fail(err, errlen, EXIT_VALIDATION, "unexpected '%s'", argv[i]);
    return EXIT_OK;
}

static size_t fmt_addr(const struct mfw_cidr *c, char *buf, size_t len)
{
    char ip[INET_ADDRSTRLEN];
    struct in_addr a = { .s_addr = c->addr };
    struct in_addr w = { .s_addr = ~prefix_mask(c->prefix) };
    char wc[INET_ADDRSTRLEN];

    inet_ntop(AF_INET, &a, ip, sizeof(ip));
    if (c->prefix == 0)
        return snprintf(buf, len, "any");
    if (c->prefix == 32)
        return snprintf(buf, len, "host %s", ip);
    inet_ntop(AF_INET, &w, wc, sizeof(wc));
    return snprintf(buf, len, "%s %s", ip, wc);
}

static size_t fmt_port(const struct mfw_port_range *r, char *buf, size_t len)
{
    if (r->min == 0 && r->max == 0)
        return snprintf(buf, len, "%s", "");
    if (r->min == r->max)
        return snprintf(buf, len, " eq %u", r->min);
    if (r->max == 65535 && r->min > 1)
        return snprintf(buf, len, " gt %u", r->min - 1);
    if (r->min == 1 && r->max < 65535)
        return snprintf(buf, len, " lt %u", r->max + 1);
    return snprintf(buf, len, " range %u %u", r->min, r->max);
}

void mfw_format_ace(const struct mfw_rule *r, char *buf, size_t len)
{
    char src[48], dst[48], sp[24], dp[24], proto[8];
    const char *act = r->action == MFW_ACTION_ALLOW ? "permit" : "deny";

    fmt_addr(&r->src, src, sizeof(src));
    if (r->kind == MFW_ACL_STANDARD) {
        snprintf(buf, len, "%s %s", act, src);
        return;
    }
    fmt_addr(&r->dst, dst, sizeof(dst));
    fmt_port(&r->sport, sp, sizeof(sp));
    fmt_port(&r->dport, dp, sizeof(dp));
    switch (r->proto) {
    case MFW_PROTO_ANY:  snprintf(proto, sizeof(proto), "ip");   break;
    case MFW_PROTO_TCP:  snprintf(proto, sizeof(proto), "tcp");  break;
    case MFW_PROTO_UDP:  snprintf(proto, sizeof(proto), "udp");  break;
    case MFW_PROTO_ICMP: snprintf(proto, sizeof(proto), "icmp"); break;
    default:             snprintf(proto, sizeof(proto), "%u", r->proto); break;
    }
    snprintf(buf, len, "%s %s %s%s %s%s%s", act, proto, src, sp, dst, dp,
             (r->flags & MFW_RULE_F_ESTABLISHED) ? " established" : "");
}
