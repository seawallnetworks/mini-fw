// SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
/* mfw — command-line client for mfwd. Sends policies, prints what mfwd
 * enforces. Needs no privileges beyond access to mfwd's socket. */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "mfw_client.h"
#include "mfw_policy.h"

#define MFW_VERSION "0.4.0"

/* exit status, as sw_authctl */
#define EXIT_OK       0
#define EXIT_REFUSED  1   /* mfwd said no */
#define EXIT_ERROR    2   /* usage, file or connection error */

static void usage(FILE *f)
{
    fprintf(f,
        "usage: mfw [-s socket] <command>\n"
        "\n"
        "  apply [file]       replace the whole policy (stdin if no file or '-')\n"
        "  check [file]       check a policy here, without sending it\n"
        "  show               the policy mfwd enforces\n"
        "  status             generation, attached, missing and degraded\n"
        "                     (at TC: another program holds XDP) interfaces\n"
        "  stats [--json]     packet counters\n"
        "  ping\n"
        "  version\n"
        "\n"
        "A policy has one item per line:\n"
        "  acl <list> <seq> permit|deny ...   an ACE, Cisco syntax\n"
        "  bind <ifname> in <list>            one standard + one extended list per interface\n"
        "  set drop-ipv4-fragments 0|1\n"
        "\n"
        "  standard ACE (1-99):    permit|deny <addr>\n"
        "  extended ACE (100-199): permit|deny <proto> <addr> [<port>] <addr> [<port>] [established]\n"
        "    <addr>:  any | host A.B.C.D | A.B.C.D <wildcard> | A.B.C.D/len\n"
        "    <proto>: ip | tcp | udp | icmp | 0-255\n"
        "    <port>:  eq N | range LO HI | gt N | lt N   (tcp/udp only)\n"
        "\n"
        "mfwd attaches every bound interface and detaches the others. Only\n"
        "inbound traffic is filtered. Socket: -s, else $MFW_SOCKET, else "
        MFW_SOCKET ".\n"
        "Exit status: 0 ok, 1 refused by mfwd, 2 usage or connection error.\n"
        "\n"
        "In the Seawall stack sw_configd owns the policy and sends its own back\n"
        "within 5 s of any other apply: change it there (telnet 127.0.0.1 2323,\n"
        "access-list / ip access-group), and use mfw for show, status and stats.\n");
}

static char *read_all(FILE *f)
{
    size_t size = 4096, off = 0;
    char *buf = malloc(size + 1), *p;

    while (buf) {
        size_t n = fread(buf + off, 1, size - off, f);

        off += n;
        if (n == 0)
            break;
        if (off == size) {
            if (size > MFW_REQUEST_MAX) {
                errno = EFBIG;
                free(buf);
                return NULL;
            }
            size *= 2;
            p = realloc(buf, size + 1);
            if (!p) {
                free(buf);
                return NULL;
            }
            buf = p;
        }
    }
    if (!buf || ferror(f)) {
        free(buf);
        return NULL;
    }
    buf[off] = '\0';
    return buf;
}

/* The policy text from argv[0] (a file, or '-' / nothing for stdin). */
static char *read_policy(int argc, char **argv)
{
    const char *path = argc ? argv[0] : "-";
    FILE *f = strcmp(path, "-") ? fopen(path, "r") : stdin;
    char *text;

    if (!f) {
        fprintf(stderr, "mfw: %s: %s\n", path, strerror(errno));
        return NULL;
    }
    text = read_all(f);
    if (!text)
        fprintf(stderr, "mfw: read %s: %s\n", path, strerror(errno));
    if (f != stdin)
        fclose(f);
    return text;
}

/* Reports a failed call; returns the exit status. */
static int failed(int rc, const char *err)
{
    if (rc == mfw_err_io)
        fprintf(stderr, "mfw: %s: %s\n", mfw_strerror(rc), strerror(errno));
    else if (err && *err)
        fprintf(stderr, "mfw: %s\n", err);
    else
        fprintf(stderr, "mfw: %s\n", mfw_strerror(rc));
    return rc == mfw_err_io || rc == mfw_err_reply ? EXIT_ERROR : EXIT_REFUSED;
}

static int cmd_check(int argc, char **argv)
{
    struct mfw_policy p;
    char err[MFW_ERR_LEN], *text = read_policy(argc, argv);

    if (!text)
        return EXIT_ERROR;
    if (mfw_policy_parse(text, &p, err, sizeof(err))) {
        fprintf(stderr, "mfw: %s\n", err);
        free(text);
        return EXIT_REFUSED;
    }
    printf("ok: %d ACEs, %d interfaces\n", p.n_rules, p.n_binds);
    mfw_policy_free(&p);
    free(text);
    return EXIT_OK;
}

static int cmd_apply(const mfw_client_t *c, int argc, char **argv)
{
    char err[MFW_ERR_LEN], missing[1024], *text = read_policy(argc, argv);
    __u32 gen;
    int rc;

    if (!text)
        return EXIT_ERROR;
    rc = mfw_apply(c, text, &gen, missing, sizeof(missing), err, sizeof(err));
    free(text);
    if (rc)
        return failed(rc, err);
    printf("applied, generation %u\n", gen);
    if (*missing)
        printf("not present, so not attached: %s\n", missing);
    return EXIT_OK;
}

static int cmd_show(const mfw_client_t *c)
{
    char *policy;
    int rc = mfw_show(c, &policy);

    if (rc)
        return failed(rc, NULL);
    fputs(policy, stdout);
    free(policy);
    return EXIT_OK;
}

static int cmd_status(const mfw_client_t *c)
{
    struct mfw_status st;
    int rc = mfw_status(c, &st);

    if (rc)
        return failed(rc, NULL);
    if (st.generation)
        printf("generation           %u\n", st.generation);
    else
        printf("generation           none (no policy applied since boot)\n");
    printf("attached             %s\n", *st.attached ? st.attached : "-");
    printf("missing              %s\n", *st.missing ? st.missing : "-");
    printf("degraded             %s\n", *st.degraded ? st.degraded : "-");
    printf("drop-ipv4-fragments  %d\n", st.drop_ipv4_fragments);
    return EXIT_OK;
}

static int cmd_stats(const mfw_client_t *c, int argc, char **argv)
{
    int json = argc == 1 && !strcmp(argv[0], "--json");
    __u64 v[MFW_STAT_MAX];
    int rc;

    if (argc > 1 || (argc == 1 && !json)) {
        usage(stderr);
        return EXIT_ERROR;
    }
    rc = mfw_stats(c, v);
    if (rc)
        return failed(rc, NULL);
    for (int i = 0; i < MFW_STAT_MAX; i++) {
        if (json)
            printf("%s\"%s\":%llu", i ? "," : "{", mfw_stat_name(i),
                   (unsigned long long)v[i]);
        else
            printf("%-18s %llu\n", mfw_stat_name(i), (unsigned long long)v[i]);
    }
    if (json)
        printf("}\n");
    return EXIT_OK;
}

int main(int argc, char **argv)
{
    mfw_client_t c = { .socket_path = getenv("MFW_SOCKET") };
    int opt, rc;

    if (c.socket_path && !*c.socket_path)
        c.socket_path = NULL;
    while ((opt = getopt(argc, argv, "+s:h")) != -1) {
        switch (opt) {
        case 's': c.socket_path = optarg; break;
        case 'h': usage(stdout); return EXIT_OK;
        default:  usage(stderr); return EXIT_ERROR;
        }
    }
    argc -= optind;
    argv += optind;
    if (argc < 1) {
        usage(stderr);
        return EXIT_ERROR;
    }

    const char *cmd = argv[0];
    int n = argc - 1;
    char **rest = argv + 1;

    if (!strcmp(cmd, "apply") && n <= 1)
        return cmd_apply(&c, n, rest);
    if (!strcmp(cmd, "check") && n <= 1)
        return cmd_check(n, rest);
    if (!strcmp(cmd, "show") && n == 0)
        return cmd_show(&c);
    if (!strcmp(cmd, "status") && n == 0)
        return cmd_status(&c);
    if (!strcmp(cmd, "stats"))
        return cmd_stats(&c, n, rest);
    if (!strcmp(cmd, "ping") && n == 0) {
        rc = mfw_ping(&c);
        if (rc)
            return failed(rc, NULL);
        printf("mfwd is running\n");
        return EXIT_OK;
    }
    if (!strcmp(cmd, "version") && n == 0) {
        printf("mfw %s, ABI %d\n", MFW_VERSION, MFW_ABI_VERSION);
        return EXIT_OK;
    }
    if (!strcmp(cmd, "help")) {
        usage(stdout);
        return EXIT_OK;
    }
    usage(stderr);
    return EXIT_ERROR;
}
