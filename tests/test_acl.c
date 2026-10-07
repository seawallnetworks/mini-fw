// SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
/* Unit tests for Cisco ACE parsing (no kernel needed). */
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>

#include "mfw_cli.h"

static int failures;

#define CHECK(cond, ...) do { \
    if (!(cond)) { failures++; printf("FAIL %s:%d: ", __FILE__, __LINE__); \
                   printf(__VA_ARGS__); printf("\n"); } } while (0)

/* Split a string into argv (modifies buf). */
static int split(char *buf, char **argv, int max)
{
    int n = 0;

    for (char *t = strtok(buf, " "); t && n < max; t = strtok(NULL, " "))
        argv[n++] = t;
    return n;
}

static int parse(const char *line, struct mfw_rule *r, char *err)
{
    char buf[256], *argv[32];
    int argc;

    snprintf(buf, sizeof(buf), "%s", line);
    argc = split(buf, argv, 32);
    return mfw_parse_ace(argc, argv, r, err, 160);
}

/* Parse, then format, and compare with the expected canonical rendering. */
static void roundtrip(const char *line, const char *want)
{
    struct mfw_rule r;
    char err[160], out[160];
    int rc = parse(line, &r, err);

    CHECK(rc == EXIT_OK, "'%s' rejected: %s", line, err);
    if (rc)
        return;
    mfw_format_ace(&r, out, sizeof(out));
    CHECK(!strcmp(out, want), "'%s' → '%s', want '%s'", line, out, want);
}

static void reject(const char *line, int want_rc)
{
    struct mfw_rule r;
    char err[160] = "";
    int rc = parse(line, &r, err);

    CHECK(rc == want_rc, "'%s' rc=%d want %d (%s)", line, rc, want_rc, err);
}

static void test_wildcard(void)
{
    __be32 w;

    mfw_parse_ipv4("0.0.0.255", &w);
    CHECK(mfw_wildcard_to_prefix(w) == 24, "0.0.0.255");
    mfw_parse_ipv4("0.0.0.0", &w);
    CHECK(mfw_wildcard_to_prefix(w) == 32, "0.0.0.0");
    mfw_parse_ipv4("255.255.255.255", &w);
    CHECK(mfw_wildcard_to_prefix(w) == 0, "255.255.255.255");
    mfw_parse_ipv4("0.0.1.255", &w);
    CHECK(mfw_wildcard_to_prefix(w) == 23, "0.0.1.255");
    mfw_parse_ipv4("0.0.2.255", &w);
    CHECK(mfw_wildcard_to_prefix(w) == -1, "0.0.2.255 non-contiguous");
    mfw_parse_ipv4("255.0.0.0", &w);
    CHECK(mfw_wildcard_to_prefix(w) == -1, "255.0.0.0 is a mask, not a wildcard");
}

static void test_fields(void)
{
    struct mfw_rule r;
    char err[160];

    CHECK(parse("10 deny host 192.168.1.10", &r, err) == 0, "%s", err);
    CHECK(r.acl_id == 10 && r.seq == 0 && r.kind == MFW_ACL_STANDARD, "std fields");
    CHECK(r.action == MFW_ACTION_DENY && r.src.prefix == 32, "std deny host");
    CHECK(r.src.addr == inet_addr("192.168.1.10"), "addr is network order");

    CHECK(parse("100 25 permit tcp any range 1024 65535 10.0.0.0/8 eq 22", &r, err) == 0, "%s", err);
    CHECK(r.seq == 25 && r.proto == MFW_PROTO_TCP && r.kind == MFW_ACL_EXTENDED, "ext fields");
    CHECK(r.sport.min == 1024 && r.sport.max == 65535, "sport range");
    CHECK(r.dport.min == 22 && r.dport.max == 22, "dport eq");
    CHECK(r.dst.prefix == 8 && r.dst.addr == inet_addr("10.0.0.0"), "dst cidr");

    /* host bits are normalized away */
    CHECK(parse("10 permit 192.168.1.77 0.0.0.255", &r, err) == 0, "%s", err);
    CHECK(r.src.addr == inet_addr("192.168.1.0") && r.src.prefix == 24, "normalize");
}

int main(void)
{
    test_wildcard();
    test_fields();

    /* Standard */
    roundtrip("10 deny host 192.168.1.10", "deny host 192.168.1.10");
    roundtrip("10 permit 192.168.1.0 0.0.0.255", "permit 192.168.1.0 0.0.0.255");
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
    roundtrip("100 permit tcp any any range 1 65535", "permit tcp any any range 1 65535");
    roundtrip("100 permit tcp any any established", "permit tcp any any established");
    roundtrip("110 deny ip host 10.0.0.5 10.0.0.0 0.0.0.255",
              "deny ip host 10.0.0.5 10.0.0.0 0.0.0.255");
    roundtrip("199 permit icmp any any", "permit icmp any any");
    roundtrip("150 permit 47 any any", "permit 47 any any");

    /* Rejections */
    reject("0 deny any", EXIT_VALIDATION);
    reject("200 deny ip any any", EXIT_VALIDATION);
    reject("10 deny host 10.0.0.1 eq 22", EXIT_VALIDATION);       /* ports on std */
    reject("10 deny host 10.0.0.1 host 10.0.0.2", EXIT_VALIDATION); /* dst on std */
    reject("10 deny 10.0.0.0 0.0.2.255", EXIT_VALIDATION);       /* non-contiguous */
    reject("10 deny 10.0.0.0/33", EXIT_VALIDATION);
    reject("10 deny host 300.1.1.1", EXIT_VALIDATION);
    reject("100 permit icmp any eq 5 any", EXIT_VALIDATION);     /* ports on icmp */
    reject("100 permit ip any any eq 80", EXIT_VALIDATION);
    reject("100 permit udp any any established", EXIT_VALIDATION);
    reject("100 permit tcp any any range 90 80", EXIT_VALIDATION);
    reject("100 permit tcp any any eq 0", EXIT_VALIDATION);      /* port 0 = any sentinel */
    reject("100 permit tcp 10.0.0.1 any", EXIT_VALIDATION);      /* ext needs wildcard/host */
    reject("100 permit bogus any any", EXIT_VALIDATION);
    reject("100 permit", EXIT_USAGE);
    reject("100 frob ip any any", EXIT_VALIDATION);
    reject("100 0 permit ip any any", EXIT_VALIDATION);          /* seq 0 */

    if (failures) {
        printf("%d failure(s)\n", failures);
        return 1;
    }
    printf("test_acl: all tests passed\n");
    return 0;
}
