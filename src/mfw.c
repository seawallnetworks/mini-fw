
/* SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause */

/*
 * mfw — command-line client for mfwd. Sends policies, prints what mfwd
 * enforces. Needs no privileges beyond access to mfwd's socket.
 */


#include "mfw_client.h"
#include "mfw_policy.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>


#define MFW_VERSION  "0.4.0"

/* exit status, as sw_authctl */
#define MFW_EXIT_OK       0
#define MFW_EXIT_REFUSED  1   /* mfwd said no */
#define MFW_EXIT_ERROR    2   /* usage, file or connection error */


static void usage(FILE *f);
static char *read_all(FILE *f);
static char *read_policy(int argc, char **argv);
static int failed(int rc, const char *err);
static int cmd_check(int argc, char **argv);
static int cmd_apply(const mfw_client_t *c, int argc, char **argv);
static int cmd_show(const mfw_client_t *c);
static int cmd_status(const mfw_client_t *c);
static int cmd_stats(const mfw_client_t *c, int argc, char **argv);


static void
usage(FILE *f)
{
    fprintf(f,
        "usage: mfw [-s socket] <command>\n"
        "\n"
        "  apply [file]       replace the whole policy, from stdin if no\n"
        "                     file or '-'\n"
        "  check [file]       check a policy here, without sending it\n"
        "  show               the policy mfwd enforces\n"
        "  status             generation, attached, missing and degraded\n"
        "                     (at TC: another program holds XDP) interfaces;\n"
        "                     flows: sw_flowd, when reply ACEs read its table\n"
        "  stats [--json]     packet counters\n"
        "  ping\n"
        "  version\n"
        "\n"
        "A policy has one item per line:\n"
        "  acl <list> <seq> permit|deny ...   an ACE, Cisco syntax\n"
        "  bind <ifname> in <list>            at most one standard and one\n"
        "                                     extended list per interface\n"
        "  set drop-ipv4-fragments 0|1\n"
        "  set reply-idle-tcp|reply-idle-udp <seconds>   default 86400, 180\n"
        "\n"
        "  standard ACE (1-99):    permit|deny <addr>\n"
        "  extended ACE (100-199): permit|deny <proto> <addr> [<port>]\n"
        "                          <addr> [<port>] [established|reply]\n"
        "    <addr>:  any | host A.B.C.D | A.B.C.D <wildcard> | A.B.C.D/len\n"
        "    <proto>: ip | tcp | udp | icmp | 0-255\n"
        "    <port>:  eq N | range LO HI | gt N | lt N   (tcp/udp only)\n"
        "\n"
        "mfwd attaches every bound interface and detaches the others. Only\n"
        "inbound traffic is filtered. Socket: -s, else $MFW_SOCKET, else "
        MFW_SOCKET ".\n"
        "Exit status: 0 ok, 1 refused by mfwd, 2 usage, file or connection\n"
        "error.\n"
        "\n"
        "In the Seawall stack sw_configd owns the policy and sends its own\n"
        "back within 5 s of any other apply: change it there (telnet\n"
        "127.0.0.1 2323, access-list / ip access-group), and use mfw for\n"
        "show, status and stats.\n");
}


static char *
read_all(FILE *f)
{
    char    *buf, *p;
    size_t   n, off, size;

    size = 4096;
    off = 0;

    buf = malloc(size + 1);
    if (buf == NULL) {
        return NULL;
    }

    for ( ;; ) {
        n = fread(buf + off, 1, size - off, f);
        off += n;

        if (n == 0) {
            break;
        }

        if (off == size) {
            if (size > MFW_REQUEST_MAX) {
                errno = EFBIG;
                free(buf);
                return NULL;
            }

            size *= 2;

            p = realloc(buf, size + 1);
            if (p == NULL) {
                free(buf);
                return NULL;
            }

            buf = p;
        }
    }

    if (ferror(f)) {
        free(buf);
        return NULL;
    }

    buf[off] = '\0';

    return buf;
}


/* The policy text from argv[0] (a file, or '-' / nothing for stdin). */
static char *
read_policy(int argc, char **argv)
{
    FILE        *f;
    char        *text;
    const char  *path;

    path = argc > 0 ? argv[0] : "-";
    f = strcmp(path, "-") != 0 ? fopen(path, "r") : stdin;

    if (f == NULL) {
        fprintf(stderr, "mfw: %s: %s\n", path, strerror(errno));
        return NULL;
    }

    text = read_all(f);

    if (text == NULL) {
        fprintf(stderr, "mfw: read %s: %s\n", path, strerror(errno));
    }

    if (f != stdin) {
        fclose(f);
    }

    return text;
}


/* Reports a failed call; returns the exit status. */
static int
failed(int rc, const char *err)
{
    if (rc == mfw_err_io) {
        fprintf(stderr, "mfw: %s: %s\n", mfw_strerror(rc), strerror(errno));

    } else if (err != NULL && *err != '\0') {
        fprintf(stderr, "mfw: %s\n", err);

    } else {
        fprintf(stderr, "mfw: %s\n", mfw_strerror(rc));
    }

    return rc == mfw_err_io || rc == mfw_err_reply ? MFW_EXIT_ERROR
                                                   : MFW_EXIT_REFUSED;
}


static int
cmd_check(int argc, char **argv)
{
    char               *text;
    struct mfw_policy   p;
    char                err[MFW_ERR_LEN];

    text = read_policy(argc, argv);
    if (text == NULL) {
        return MFW_EXIT_ERROR;
    }

    if (mfw_policy_parse(text, &p, err, sizeof(err)) != 0) {
        fprintf(stderr, "mfw: %s\n", err);
        free(text);
        return MFW_EXIT_REFUSED;
    }

    printf("ok: %d ACEs, %d interfaces\n", p.n_rules, p.n_binds);

    mfw_policy_free(&p);
    free(text);

    return MFW_EXIT_OK;
}


static int
cmd_apply(const mfw_client_t *c, int argc, char **argv)
{
    int     rc;
    char   *text;
    __u32   gen;
    char    err[MFW_ERR_LEN], missing[1024];

    text = read_policy(argc, argv);
    if (text == NULL) {
        return MFW_EXIT_ERROR;
    }

    rc = mfw_apply(c, text, &gen, missing, sizeof(missing), err, sizeof(err));
    free(text);

    if (rc != 0) {
        return failed(rc, err);
    }

    printf("applied, generation %u\n", gen);

    if (missing[0] != '\0') {
        printf("not present, so not attached: %s\n", missing);
    }

    return MFW_EXIT_OK;
}


static int
cmd_show(const mfw_client_t *c)
{
    int    rc;
    char  *policy;

    rc = mfw_show(c, &policy);
    if (rc != 0) {
        return failed(rc, NULL);
    }

    fputs(policy, stdout);
    free(policy);

    return MFW_EXIT_OK;
}


static int
cmd_status(const mfw_client_t *c)
{
    int                 rc;
    struct mfw_status   st;

    rc = mfw_status(c, &st);
    if (rc != 0) {
        return failed(rc, NULL);
    }

    if (st.generation != 0) {
        printf("generation           %u\n", st.generation);

    } else {
        printf("generation           none (none applied since mfwd "
               "started)\n");
    }

    printf("attached             %s\n",
           st.attached[0] != '\0' ? st.attached : "-");
    printf("missing              %s\n",
           st.missing[0] != '\0' ? st.missing : "-");
    printf("degraded             %s\n",
           st.degraded[0] != '\0' ? st.degraded : "-");
    printf("drop-ipv4-fragments  %d\n", st.drop_ipv4_fragments);
    printf("flows                %s\n", st.flows);

    return MFW_EXIT_OK;
}


static int
cmd_stats(const mfw_client_t *c, int argc, char **argv)
{
    int    i, json, rc;
    __u64  v[MFW_STAT_MAX];

    json = argc == 1 && strcmp(argv[0], "--json") == 0;

    if (argc > 1 || (argc == 1 && !json)) {
        usage(stderr);
        return MFW_EXIT_ERROR;
    }

    rc = mfw_stats(c, v);
    if (rc != 0) {
        return failed(rc, NULL);
    }

    for (i = 0; i < MFW_STAT_MAX; i++) {
        if (json) {
            printf("%s\"%s\":%llu", i > 0 ? "," : "{", mfw_stat_name(i),
                   (unsigned long long) v[i]);

        } else {
            printf("%-18s %llu\n", mfw_stat_name(i),
                   (unsigned long long) v[i]);
        }
    }

    if (json) {
        printf("}\n");
    }

    return MFW_EXIT_OK;
}


int
main(int argc, char **argv)
{
    int            n, opt, rc;
    char         **rest;
    const char    *cmd;
    mfw_client_t   c = {};

    c.socket_path = getenv("MFW_SOCKET");

    if (c.socket_path != NULL && *c.socket_path == '\0') {
        c.socket_path = NULL;
    }

    while ((opt = getopt(argc, argv, "+s:h")) != -1) {
        switch (opt) {
        case 's':
            c.socket_path = optarg;
            break;

        case 'h':
            usage(stdout);
            return MFW_EXIT_OK;

        default:
            usage(stderr);
            return MFW_EXIT_ERROR;
        }
    }

    argc -= optind;
    argv += optind;

    if (argc < 1) {
        usage(stderr);
        return MFW_EXIT_ERROR;
    }

    cmd = argv[0];
    n = argc - 1;
    rest = argv + 1;

    if (strcmp(cmd, "apply") == 0 && n <= 1) {
        return cmd_apply(&c, n, rest);
    }

    if (strcmp(cmd, "check") == 0 && n <= 1) {
        return cmd_check(n, rest);
    }

    if (strcmp(cmd, "show") == 0 && n == 0) {
        return cmd_show(&c);
    }

    if (strcmp(cmd, "status") == 0 && n == 0) {
        return cmd_status(&c);
    }

    if (strcmp(cmd, "stats") == 0) {
        return cmd_stats(&c, n, rest);
    }

    if (strcmp(cmd, "ping") == 0 && n == 0) {
        rc = mfw_ping(&c);
        if (rc != 0) {
            return failed(rc, NULL);
        }

        printf("mfwd is running\n");
        return MFW_EXIT_OK;
    }

    if (strcmp(cmd, "version") == 0 && n == 0) {
        printf("mfw %s, ABI %d\n", MFW_VERSION, MFW_ABI_VERSION);
        return MFW_EXIT_OK;
    }

    if (strcmp(cmd, "help") == 0) {
        usage(stdout);
        return MFW_EXIT_OK;
    }

    usage(stderr);

    return MFW_EXIT_ERROR;
}
