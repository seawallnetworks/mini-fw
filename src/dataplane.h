/* SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause */
/* The BPF side of mfwd: pinned maps, XDP and TC attachments, rulesets,
 * counters. */
#ifndef MFW_DATAPLANE_H
#define MFW_DATAPLANE_H

#include <limits.h>
#include <net/if.h>
#include <stddef.h>
#include "mfw.h"

struct mfw_bpf;

struct mfw_dp {
    const char     *root;                 /* pin root: MFW_PIN_PATH */
    struct mfw_bpf *skel;                 /* loaded program, maps from pins */
    int             prog_fd;
    int             rulesets_fd;
    int             config_fd;
    int             stats_fd;
    int             flows_fd;     /* sw_flowd's table, bound at load; -1: none */
    int             tcx;      /* attach with tcx links (6.6+), not classic TC */
    int             no_xdp;   /* MFW_NO_XDP: TC only, for tests */
};

/*
 * Detach every interface and remove the pins an earlier mfwd left under
 * MFW_PIN_PATH, as mfw_dp_purge() does, then load the program and pin new
 * maps there. Returns 0, or -1 with a message in err.
 */
int mfw_dp_open(struct mfw_dp *dp, char *err, size_t errlen);
void mfw_dp_close(struct mfw_dp *dp);

/* Is ifname attached, by a program, link or filter still alive on that
 * interface? */
int mfw_dp_attached(const struct mfw_dp *dp, const char *ifname);
/* Is ifname at TC because a program that is not libxdp's dispatcher holds
 * its XDP hook? */
int mfw_dp_degraded(const struct mfw_dp *dp, const char *ifname);
/* Names of the attached interfaces, sorted; returns how many (≤ max). */
int mfw_dp_list_attached(const struct mfw_dp *dp, char names[][IF_NAMESIZE], int max);
/* In libxdp's dispatcher; at TC ingress if a program that is not one holds
 * the XDP hook. */
int mfw_dp_attach(struct mfw_dp *dp, const char *ifname, char *err, size_t errlen);
/* Drop the interface's ruleset and detach it. */
void mfw_dp_detach(struct mfw_dp *dp, const char *ifname);

/* Swap in rs as the ruleset of ifindex (one map update). */
int mfw_dp_install(struct mfw_dp *dp, __u32 ifindex, const struct mfw_ruleset *rs,
                   char *err, size_t errlen);
/* Remove every ruleset whose ifindex is not in keep[0..n). */
void mfw_dp_prune(struct mfw_dp *dp, const __u32 *keep, int n);

int mfw_dp_get_config(const struct mfw_dp *dp, struct mfw_config *cfg);
/* Set the fragment policy and bump the generation; returns the new one. */
int mfw_dp_set_config(struct mfw_dp *dp, int drop_ipv4_fragments, __u32 *generation);
int mfw_dp_stats(const struct mfw_dp *dp, __u64 out[MFW_STAT_MAX]);

/*
 * Detach every interface and remove all pins under MFW_PIN_PATH. Returns
 * 0, or -1 with a message in err; an interface that can't be looked up
 * stops it before any pin is removed.
 */
int mfw_dp_purge(char *err, size_t errlen);

#endif /* MFW_DATAPLANE_H */
