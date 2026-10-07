// SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
/* mfw — mini-fw CLI. Cisco IOS-style ACL syntax over pinned BPF maps. */
#include <stdio.h>
#include <string.h>

#include "mfw_cli.h"

#define MFW_VERSION "0.1.0 (stateless ACL)"

static void usage(FILE *f)
{
    fprintf(f,
        "usage: mfw <command>\n"
        "\n"
        "  attach -i <ifname> [--xdp-mode native|generic|auto]\n"
        "  detach -i <ifname> [--purge-maps]\n"
        "\n"
        "  ip access-list <1-99>    [seq] permit|deny <src>\n"
        "  ip access-list <100-199> [seq] permit|deny <proto> <src> [<port>] <dst> [<port>] [established]\n"
        "      <src>/<dst>: any | host A.B.C.D | A.B.C.D <wildcard> | A.B.C.D/len\n"
        "      <proto>: ip | tcp | udp | icmp | 0-255\n"
        "      <port>:  eq N | range LO HI | gt N | lt N   (tcp/udp only)\n"
        "  no ip access-list <list> [<seq>]\n"
        "  ip access-group <list> in <ifname>\n"
        "  no ip access-group [<list>] in <ifname>\n"
        "  show ip access-lists [<list>]\n"
        "  show ip access-group [<ifname>]\n"
        "\n"
        "  stats [--json]\n"
        "  set drop-ipv4-fragments 0|1\n"
        "  set-default deny|allow   (v1: deny is a no-op, allow is rejected)\n"
        "  version\n"
        "\n"
        "Only inbound traffic is filtered; egress always passes.\n"
        "The 'ip' prefix is optional: 'mfw access-list 10 deny host 1.2.3.4' also works.\n");
}

/* Strip optional leading "ip". */
static int skip_ip(int *argc, char ***argv)
{
    if (*argc > 0 && !strcmp((*argv)[0], "ip")) {
        (*argc)--;
        (*argv)++;
    }
    return *argc;
}

static int dispatch_ip(int argc, char **argv, int negate)
{
    skip_ip(&argc, &argv);
    if (argc < 1)
        return -1;
    if (!strcmp(argv[0], "access-list"))
        return negate ? cmd_no_access_list(argc - 1, argv + 1)
                      : cmd_access_list(argc - 1, argv + 1);
    if (!strcmp(argv[0], "access-group"))
        return cmd_access_group(argc - 1, argv + 1, negate);
    return -1;
}

int main(int argc, char **argv)
{
    int rc = -1;

    if (argc < 2) {
        usage(stderr);
        return EXIT_USAGE;
    }
    const char *cmd = argv[1];

    if (!strcmp(cmd, "attach"))
        rc = cmd_attach(argc - 1, argv + 1);
    else if (!strcmp(cmd, "detach"))
        rc = cmd_detach(argc - 1, argv + 1);
    else if (!strcmp(cmd, "no"))
        rc = dispatch_ip(argc - 2, argv + 2, 1);
    else if (!strcmp(cmd, "ip") || !strcmp(cmd, "access-list") ||
             !strcmp(cmd, "access-group"))
        rc = dispatch_ip(argc - 1, argv + 1, 0);
    else if (!strcmp(cmd, "show")) {
        int n = argc - 2;
        char **v = argv + 2;

        skip_ip(&n, &v);
        if (n >= 1 && !strcmp(v[0], "access-lists"))
            rc = cmd_show_access_lists(n - 1, v + 1);
        else if (n >= 1 && !strcmp(v[0], "access-group"))
            rc = cmd_show_access_group(n - 1, v + 1);
    } else if (!strcmp(cmd, "stats"))
        rc = cmd_stats(argc - 2, argv + 2);
    else if (!strcmp(cmd, "set"))
        rc = cmd_set(argc - 2, argv + 2);
    else if (!strcmp(cmd, "set-default") && argc == 3) {
        if (!strcmp(argv[2], "deny"))
            rc = EXIT_OK;  /* K10: ABI-only field, always deny */
        else {
            fprintf(stderr, "mfw: set-default %s is not supported in v1\n", argv[2]);
            rc = EXIT_VALIDATION;
        }
    } else if (!strcmp(cmd, "version")) {
        printf("mfw %s, ABI %d\n", MFW_VERSION, MFW_ABI_VERSION);
        rc = EXIT_OK;
    } else if (!strcmp(cmd, "help") || !strcmp(cmd, "-h") || !strcmp(cmd, "--help")) {
        usage(stdout);
        rc = EXIT_OK;
    }

    if (rc < 0) {
        usage(stderr);
        return EXIT_USAGE;
    }
    return rc;
}
