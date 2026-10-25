// SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
/* Unit tests for whole policies: parse, checks, canonical form, compile.
 * No kernel needed. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mfw_policy.h"

static int failures;

#define CHECK(cond, ...) do { \
    if (!(cond)) { failures++; printf("FAIL %s:%d: ", __FILE__, __LINE__); \
                   printf(__VA_ARGS__); printf("\n"); } } while (0)

/* Must be refused with exactly this message. */
static void reject(const char *text, const char *want)
{
    struct mfw_policy p;
    char err[MFW_ERR_LEN] = "";
    int rc = mfw_policy_parse(text, &p, err, sizeof(err));

    CHECK(rc == -1, "accepted: %s", text);
    CHECK(!strcmp(err, want), "error '%s', want '%s'", err, want);
    if (rc == 0)
        mfw_policy_free(&p);
}

/* A policy with n ACEs in list acl, bound (or not) on eth0. */
static char *big_list(int acl, int n, int bind)
{
    size_t size = (size_t)n * 64 + 64, off = 0;
    char *s = malloc(size);

    for (int i = 0; i < n; i++)
        off += snprintf(s + off, size - off, mfw_is_std(acl) ?
                        "acl %d %d permit host 10.0.%d.%d\n" :
                        "acl %d %d permit tcp any any eq %d\n",
                        acl, i + 1, mfw_is_std(acl) ? i / 256 : 1000 + i, i % 256);
    if (bind)
        snprintf(s + off, size - off, "bind eth0 in %d\n", acl);
    return s;
}

static void test_parse_and_format(void)
{
    const char *text =
        "# a comment, then a blank line\n"
        "\n"
        "bind eth1 in 110\n"
        "acl 100 20 permit udp any eq 53 any\n"
        "acl 10 10 deny host 203.0.113.66\r\n"
        "  acl 100 10   permit tcp any host 10.0.0.5 eq 22   # ssh\n"
        "bind eth0 in 100\n"
        "bind eth0 in 10\n"
        "acl 110 5 permit icmp any any\n"
        "acl 110 10 permit tcp any any reply\n"
        "set reply-idle-udp 60\n"
        "set drop-ipv4-fragments 1";        /* no final newline */
    const char *canon =
        "acl 10 10 deny host 203.0.113.66\n"
        "acl 100 10 permit tcp any host 10.0.0.5 eq 22\n"
        "acl 100 20 permit udp any eq 53 any\n"
        "acl 110 5 permit icmp any any\n"
        "acl 110 10 permit tcp any any reply\n"
        "bind eth0 in 10\n"
        "bind eth0 in 100\n"
        "bind eth1 in 110\n"
        "set drop-ipv4-fragments 1\n"
        "set reply-idle-tcp 86400\n"
        "set reply-idle-udp 60\n";
    struct mfw_policy p, q;
    char err[MFW_ERR_LEN], *out, *again;

    CHECK(mfw_policy_parse(text, &p, err, sizeof(err)) == 0, "rejected: %s", err);
    CHECK(p.n_rules == 5 && p.n_binds == 2 && p.drop_ipv4_fragments == 1,
          "%d rules, %d binds", p.n_rules, p.n_binds);
    CHECK(p.reply_idle_tcp == MFW_REPLY_IDLE_TCP && p.reply_idle_udp == 60,
          "reply idle %u/%u", p.reply_idle_tcp, p.reply_idle_udp);
    CHECK(!strcmp(p.binds[0].ifname, "eth0") && p.binds[0].std_acl == 10 &&
          p.binds[0].ext_acl == 100, "eth0 binds");
    CHECK(!strcmp(p.binds[1].ifname, "eth1") && p.binds[1].std_acl == 0 &&
          p.binds[1].ext_acl == 110, "eth1 binds");

    out = mfw_policy_format(&p);
    CHECK(out && !strcmp(out, canon), "canonical form:\n%s", out);

    /* the canonical form parses back to itself */
    CHECK(mfw_policy_parse(out, &q, err, sizeof(err)) == 0, "canonical rejected: %s", err);
    again = mfw_policy_format(&q);
    CHECK(again && !strcmp(again, out), "round trip differs:\n%s", again);
    free(again);
    mfw_policy_free(&q);
    free(out);
    mfw_policy_free(&p);

    /* empty policy: nothing bound, fragments passed */
    CHECK(mfw_policy_parse("", &p, err, sizeof(err)) == 0, "empty rejected: %s", err);
    out = mfw_policy_format(&p);
    CHECK(out && !strcmp(out, "set drop-ipv4-fragments 0\n"
                         "set reply-idle-tcp 86400\nset reply-idle-udp 180\n"),
          "empty: %s", out);
    free(out);
    mfw_policy_free(&p);
}

static void test_rejections(void)
{
    reject("frob 1\n", "line 1: unknown keyword 'frob' (acl, bind or set)");
    reject("acl 100\n", "line 1: expected: acl <list> <seq> permit|deny ...");
    reject("\nacl 100 permit ip any any\n",
           "line 2: sequence number must be 1-65535, got 'permit'");
    reject("acl 100 0 permit ip any any\n",
           "line 1: sequence number must be 1-65535, got '0'");
    reject("acl 10 10 deny 10.0.0.0 0.0.2.255\n",
           "line 1: non-contiguous wildcard '0.0.2.255' not supported");
    reject("acl 100 10 permit ip any any\nacl 100 10 deny ip any any\n",
           "line 2: list 100 already has sequence 10");
    reject("bind eth0 out 100\n", "line 1: 'out' is not supported: egress is not filtered");
    reject("bind eth0 on 100\n", "line 1: direction must be 'in'");
    reject("bind eth0 in 200\n",
           "line 1: list number must be 1-99 (standard) or 100-199 (extended)");
    reject("bind eth0 in\n", "line 1: expected: bind <interface> in <list>");
    reject("bind eth/0 in 10\n", "line 1: bad interface name 'eth/0'");
    reject("bind abcdefghijklmnop in 10\n", "line 1: bad interface name 'abcdefghijklmnop'");
    reject("bind eth0 in 10\nbind eth0 in 20\n", "line 2: eth0 already has standard list 10");
    reject("bind eth0 in 100\nbind eth0 in 100\n", "line 2: eth0 already has extended list 100");
    reject("set drop-ipv4-fragments 2\n", "line 1: expected: set drop-ipv4-fragments 0|1, "
           "or set reply-idle-tcp|reply-idle-udp <seconds>");
    reject("set frob 1\n", "line 1: expected: set drop-ipv4-fragments 0|1, "
           "or set reply-idle-tcp|reply-idle-udp <seconds>");
    reject("set reply-idle-tcp 0\n", "line 1: reply-idle-tcp must be 1-31536000 seconds");
    reject("set reply-idle-udp 31536001\n",
           "line 1: reply-idle-udp must be 1-31536000 seconds");
    reject("set reply-idle-udp\n", "line 1: expected: set drop-ipv4-fragments 0|1, "
           "or set reply-idle-tcp|reply-idle-udp <seconds>");
}

static void test_limits(void)
{
    struct mfw_policy p;
    char err[MFW_ERR_LEN], *s, *t;
    size_t size, off;

    /* full lists bind; one more ACE does not, and the error names the bind */
    s = big_list(10, MFW_MAX_STD_ACES, 1);
    CHECK(mfw_policy_parse(s, &p, err, sizeof(err)) == 0, "64 std: %s", err);
    mfw_policy_free(&p);
    free(s);
    s = big_list(10, MFW_MAX_STD_ACES + 1, 1);
    reject(s, "line 66: standard list 10 has 65 ACEs; at most 64 can be bound");
    free(s);
    s = big_list(100, MFW_MAX_EXT_ACES, 1);
    CHECK(mfw_policy_parse(s, &p, err, sizeof(err)) == 0, "128 ext: %s", err);
    mfw_policy_free(&p);
    free(s);
    s = big_list(100, MFW_MAX_EXT_ACES + 1, 1);
    reject(s, "line 130: extended list 100 has 129 ACEs; at most 128 can be bound");
    free(s);

    /* an unbound list may be longer */
    s = big_list(100, 300, 0);
    CHECK(mfw_policy_parse(s, &p, err, sizeof(err)) == 0, "300 unbound: %s", err);
    mfw_policy_free(&p);
    free(s);

    /* MFW_ACL_MAX ACEs in all */
    s = big_list(100, MFW_ACL_MAX + 1, 0);
    reject(s, "line 4097: more than 4096 ACEs");
    free(s);

    /* MFW_MAX_IFACES interfaces */
    size = (MFW_MAX_IFACES + 1) * 32;
    t = malloc(size);
    off = 0;
    for (int i = 0; i <= MFW_MAX_IFACES; i++)
        off += snprintf(t + off, size - off, "bind if%d in 10\n", i);
    reject(t, "line 65: more than 64 interfaces");
    free(t);
}

static void test_compile(void)
{
    const char *text =
        "acl 10 20 deny host 192.0.2.2\n"
        "acl 10 10 deny host 192.0.2.1\n"
        "acl 100 10 permit tcp any any eq 22\n"
        "acl 20 10 deny any\n"
        "acl 102 10 permit tcp any any reply\n"
        "acl 102 20 permit udp any any reply\n"
        "acl 102 30 permit udp any any\n"
        "bind eth0 in 10\n"
        "bind eth0 in 100\n"
        "bind eth1 in 101\n"        /* bound but no ACEs */
        "bind eth2 in 102\n"
        "set reply-idle-udp 60\n";
    struct mfw_policy p;
    struct mfw_ruleset rs;
    char err[MFW_ERR_LEN];

    if (mfw_policy_parse(text, &p, err, sizeof(err))) {
        CHECK(0, "rejected: %s", err);
        return;
    }
    mfw_policy_compile(&p, 0, &rs);
    CHECK(rs.std_acl == 10 && rs.n_std == 2 && rs.ext_acl == 100 && rs.n_ext == 1,
          "eth0: std %u/%u ext %u/%u", rs.std_acl, rs.n_std, rs.ext_acl, rs.n_ext);
    CHECK(rs.std[0].seq == 10 && rs.std[1].seq == 20, "eth0: seq order");
    CHECK(rs.std[0].direction == MFW_DIR_INGRESS && rs.ext[0].dport.min == 22,
          "eth0: fields");
    mfw_policy_compile(&p, 1, &rs);
    CHECK(rs.std_acl == 0 && rs.n_std == 0 && rs.ext_acl == 101 && rs.n_ext == 0,
          "eth1: an empty bound extended list stays bound");
    mfw_policy_compile(&p, 2, &rs);
    CHECK(rs.n_ext == 3 && rs.ext[0].reply_idle == MFW_REPLY_IDLE_TCP &&
          rs.ext[1].reply_idle == 60 && rs.ext[2].reply_idle == 0,
          "eth2: each reply ACE carries its protocol's idle limit: %u %u %u",
          rs.ext[0].reply_idle, rs.ext[1].reply_idle, rs.ext[2].reply_idle);
    mfw_policy_free(&p);
}

int main(void)
{
    test_parse_and_format();
    test_rejections();
    test_limits();
    test_compile();
    if (failures) {
        printf("%d failure(s)\n", failures);
        return 1;
    }
    printf("test_policy: all tests passed\n");
    return 0;
}
