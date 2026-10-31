
/* SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause */

/* Unit tests for Cisco ACE parsing (no kernel needed). */


#include "mfw_policy.h"

#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>


#define mfw_check(cond, ...)                                                 \
    do {                                                                     \
        if (!(cond)) {                                                       \
            mfw_failures++;                                                  \
            printf("FAIL %s:%d: ", __FILE__, __LINE__);                      \
            printf(__VA_ARGS__);                                             \
            printf("\n");                                                    \
        }                                                                    \
    } while (0)


static int split(char *buf, char **argv, int max);
static int parse(const char *line, struct mfw_rule *r, char *err);
static void roundtrip(const char *line, const char *want);
static void reject(const char *line);
static void test_wildcard(void);
static void test_fields(void);


static int  mfw_failures;


/* Split a string into argv (modifies buf). */
static int
split(char *buf, char **argv, int max)
{
    int    n;
    char  *t;

    n = 0;

    for (t = strtok(buf, " "); t != NULL && n < max; t = strtok(NULL, " ")) {
        argv[n++] = t;
    }

    return n;
}


static int
parse(const char *line, struct mfw_rule *r, char *err)
{
    int    argc;
    char  *argv[32], buf[256];

    snprintf(buf, sizeof(buf), "%s", line);
    argc = split(buf, argv, 32);

    return mfw_parse_ace(argc, argv, r, err, 160);
}


/* Parse, then format, and compare with the expected canonical rendering. */
static void
roundtrip(const char *line, const char *want)
{
    int              rc;
    struct mfw_rule  r, r2;
    char             err[160], out[160];

    rc = parse(line, &r, err);
    mfw_check(rc == 0, "'%s' rejected: %s", line, err);

    if (rc != 0) {
        return;
    }

    mfw_format_ace(&r, out, sizeof(out));
    mfw_check(strcmp(out, want) == 0, "'%s' → '%s', want '%s'", line, out,
              want);

    rc = mfw_parse_ace_line(line, &r2, err, sizeof(err));
    mfw_check(rc == 0 && memcmp(&r, &r2, sizeof(r)) == 0,
              "'%s': mfw_parse_ace_line differs", line);
}


/* Must be refused, with a reason; mfw_parse_ace_line() must agree. */
static void
reject(const char *line)
{
    int              rc;
    struct mfw_rule  r;
    char             err[160], err2[160];

    err[0] = '\0';
    err2[0] = '\0';

    rc = parse(line, &r, err);
    mfw_check(rc == -1 && err[0] != '\0',
              "'%s' rc=%d, want -1 and a reason (%s)", line, rc, err);

    rc = mfw_parse_ace_line(line, &r, err2, sizeof(err2));
    mfw_check(rc == -1 && strcmp(err, err2) == 0,
              "'%s': mfw_parse_ace_line rc=%d (%s)", line, rc, err2);
}


static void
test_wildcard(void)
{
    __be32  w;

    mfw_parse_ipv4("0.0.0.255", &w);
    mfw_check(mfw_wildcard_to_prefix(w) == 24, "0.0.0.255");
    mfw_parse_ipv4("0.0.0.0", &w);
    mfw_check(mfw_wildcard_to_prefix(w) == 32, "0.0.0.0");
    mfw_parse_ipv4("255.255.255.255", &w);
    mfw_check(mfw_wildcard_to_prefix(w) == 0, "255.255.255.255");
    mfw_parse_ipv4("0.0.1.255", &w);
    mfw_check(mfw_wildcard_to_prefix(w) == 23, "0.0.1.255");
    mfw_parse_ipv4("0.0.2.255", &w);
    mfw_check(mfw_wildcard_to_prefix(w) == -1, "0.0.2.255 non-contiguous");
    mfw_parse_ipv4("255.0.0.0", &w);
    mfw_check(mfw_wildcard_to_prefix(w) == -1,
              "255.0.0.0 is a mask, not a wildcard");
}


static void
test_fields(void)
{
    struct mfw_rule  r;
    char             err[160];

    mfw_check(parse("10 deny host 192.168.1.10", &r, err) == 0, "%s", err);
    mfw_check(r.acl_id == 10 && r.seq == 0 && r.kind == MFW_ACL_STANDARD,
              "std fields");
    mfw_check(r.action == MFW_ACTION_DENY && r.src.prefix == 32,
              "std deny host");
    mfw_check(r.src.addr == inet_addr("192.168.1.10"),
              "addr is network order");

    mfw_check(parse("100 25 permit tcp any range 1024 65535 10.0.0.0/8 eq 22",
                    &r, err) == 0, "%s", err);
    mfw_check(r.seq == 25 && r.proto == MFW_PROTO_TCP
              && r.kind == MFW_ACL_EXTENDED, "ext fields");
    mfw_check(r.sport.min == 1024 && r.sport.max == 65535, "sport range");
    mfw_check(r.dport.min == 22 && r.dport.max == 22, "dport eq");
    mfw_check(r.dst.prefix == 8 && r.dst.addr == inet_addr("10.0.0.0"),
              "dst cidr");

    /* host bits are normalized away */
    mfw_check(parse("10 permit 192.168.1.77 0.0.0.255", &r, err) == 0,
              "%s", err);
    mfw_check(r.src.addr == inet_addr("192.168.1.0") && r.src.prefix == 24,
              "normalize");
}


int
main(void)
{
    test_wildcard();
    test_fields();

    /* Standard */
    roundtrip("10 deny host 192.168.1.10", "deny host 192.168.1.10");
    roundtrip("10 permit 192.168.1.0 0.0.0.255",
              "permit 192.168.1.0 0.0.0.255");
    roundtrip("10 permit any", "permit any");
    roundtrip("10 deny 10.1.0.0/16", "deny 10.1.0.0 0.0.255.255");
    roundtrip("10 deny 10.1.2.3", "deny host 10.1.2.3");  /* bare host (IOS) */
    roundtrip("99 5 deny any", "deny any");

    /* Extended */
    roundtrip("100 permit tcp any host 10.0.0.5 eq 22",
              "permit tcp any host 10.0.0.5 eq 22");
    roundtrip("100 permit udp any eq 53 any", "permit udp any eq 53 any");
    roundtrip("100 permit tcp any any gt 1023", "permit tcp any any gt 1023");
    roundtrip("100 permit tcp any any lt 1024", "permit tcp any any lt 1024");
    roundtrip("100 permit tcp any any range 1 65535",
              "permit tcp any any range 1 65535");
    roundtrip("100 permit tcp any any established",
              "permit tcp any any established");
    roundtrip("100 permit tcp any any reply", "permit tcp any any reply");
    roundtrip("100 permit udp any eq 53 any reply",
              "permit udp any eq 53 any reply");
    roundtrip("110 deny ip host 10.0.0.5 10.0.0.0 0.0.0.255",
              "deny ip host 10.0.0.5 10.0.0.0 0.0.0.255");
    roundtrip("199 permit icmp any any", "permit icmp any any");
    roundtrip("150 permit 47 any any", "permit 47 any any");

    /* Rejections */
    reject("0 deny any");
    reject("200 deny ip any any");
    reject("10 deny host 10.0.0.1 eq 22");          /* ports on std */
    reject("10 deny host 10.0.0.1 host 10.0.0.2");  /* dst on std */
    reject("10 deny 10.0.0.0 0.0.2.255");           /* non-contiguous */
    reject("10 deny 10.0.0.0/33");
    reject("10 deny host 300.1.1.1");
    reject("100 permit icmp any eq 5 any");         /* ports on icmp */
    reject("100 permit ip any any eq 80");
    reject("100 permit udp any any established");
    reject("100 permit ip any any reply");          /* tcp or udp only */
    reject("100 permit icmp any any reply");
    reject("100 permit tcp any any established reply");
    reject("10 permit any reply");                  /* std: source only */
    reject("100 permit tcp any any range 90 80");
    reject("100 permit tcp any any eq 0");          /* port 0 = any sentinel */
    reject("100 permit tcp 10.0.0.1 any");          /* ext: wildcard or host */
    reject("100 permit bogus any any");
    reject("100 permit");
    reject("100 frob ip any any");
    reject("100 0 permit ip any any");              /* seq 0 */

    if (mfw_failures != 0) {
        printf("%d failure(s)\n", mfw_failures);
        return 1;
    }

    printf("test_acl: all tests passed\n");

    return 0;
}
