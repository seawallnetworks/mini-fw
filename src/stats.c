// SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
/* mfw stats / mfw set */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "mfw_cli.h"

static const char *stat_names[MFW_STAT_MAX] = {
    [MFW_STAT_XDP_PASS]          = "xdp_pass",
    [MFW_STAT_XDP_DROP]          = "xdp_drop",
    [MFW_STAT_STD_DENY]          = "std_deny",
    [MFW_STAT_STD_PERMIT]        = "std_permit",
    [MFW_STAT_EXT_PERMIT]        = "ext_permit",
    [MFW_STAT_EXT_DENY]          = "ext_deny",
    [MFW_STAT_EXT_IMPLICIT_DENY] = "ext_implicit_deny",
    [MFW_STAT_PARSE_ERR]         = "parse_err",
    [MFW_STAT_FRAG_DROP]         = "frag_drop",
    [MFW_STAT_NON_IPV4]          = "non_ipv4",
};

int cmd_stats(int argc, char **argv)
{
    int json = argc == 1 && !strcmp(argv[0], "--json");
    int ncpu = libbpf_num_possible_cpus();
    struct mfw_stat_value *vals;
    int fd, first = 1;

    if (argc > 1 || (argc == 1 && !json)) {
        fprintf(stderr, "usage: mfw stats [--json]\n");
        return EXIT_USAGE;
    }
    fd = mfw_open_pinned(MFW_MAPS_DIR "/stats");
    if (fd < 0) {
        fprintf(stderr, "mfw: not attached (no %s/stats)\n", MFW_MAPS_DIR);
        return EXIT_NOT_ATTACHED;
    }
    vals = calloc(ncpu > 0 ? ncpu : 1, sizeof(*vals));
    if (!vals) {
        close(fd);
        return EXIT_KERNEL;
    }
    if (json)
        printf("{");
    for (__u32 id = 0; id < MFW_STAT_MAX; id++) {
        __u64 sum = 0;

        if (!stat_names[id])
            continue;
        if (bpf_map_lookup_elem(fd, &id, vals) == 0)
            for (int c = 0; c < ncpu; c++)
                sum += vals[c].count;
        if (json)
            printf("%s\"%s\":%llu", first ? "" : ",", stat_names[id],
                   (unsigned long long)sum);
        else
            printf("%-18s %llu\n", stat_names[id], (unsigned long long)sum);
        first = 0;
    }
    if (json)
        printf("}\n");
    free(vals);
    close(fd);
    return EXIT_OK;
}

/* mfw set drop-ipv4-fragments 0|1   |   mfw set-default deny|allow */
int cmd_set(int argc, char **argv)
{
    struct mfw_config cfg;
    __u32 k = 0;
    int fd, rc = EXIT_OK;

    if (argc != 2 || strcmp(argv[0], "drop-ipv4-fragments") ||
        (strcmp(argv[1], "0") && strcmp(argv[1], "1"))) {
        fprintf(stderr, "usage: mfw set drop-ipv4-fragments 0|1\n");
        return EXIT_USAGE;
    }
    fd = mfw_open_pinned(MFW_MAPS_DIR "/config");
    if (fd < 0) {
        fprintf(stderr, "mfw: not attached\n");
        return EXIT_NOT_ATTACHED;
    }
    if (bpf_map_lookup_elem(fd, &k, &cfg)) {
        rc = EXIT_KERNEL;
        goto out;
    }
    cfg.drop_ipv4_fragments = argv[1][0] == '1';
    if (bpf_map_update_elem(fd, &k, &cfg, BPF_ANY))
        rc = EXIT_KERNEL;
out:
    if (rc)
        fprintf(stderr, "mfw: config update: %s\n", strerror(errno));
    close(fd);
    return rc;
}
