
/* SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause */

/*
 * The BPF side of mfwd: pinned maps, XDP and TC attachments, rulesets,
 * counters.
 */


#ifndef _MFW_DATAPLANE_H_INCLUDED_
#define _MFW_DATAPLANE_H_INCLUDED_


#include "mfw.h"

#include <limits.h>
#include <net/if.h>
#include <stddef.h>


struct mfw_bpf;


typedef struct {
    const char      *root;          /* pin root: MFW_PIN_PATH */
    struct mfw_bpf  *skel;          /* the TC program, its maps pinned */
    int              prog_fd;
    int              rulesets_fd;
    int              config_fd;
    int              stats_fd;
    int              flows_fd;      /* sw_flowd's table, bound at load, or -1 */
    int              tcx;           /* attach with tcx links (6.6+), not
                                     * classic TC */
    int              no_xdp;        /* MFW_NO_XDP: TC only, for tests */
} mfw_dp_t;


/*
 * Load the TC program and pin its maps under MFW_PIN_PATH, attaching
 * nothing. mfwd purges first, so the maps are new. Returns 0, or -1 with
 * a message in err.
 */
int mfw_dp_open(mfw_dp_t *dp, char *err, size_t errlen);
void mfw_dp_close(mfw_dp_t *dp);

/*
 * Is ifname attached, by a program, link or filter still alive on that
 * interface?
 */
int mfw_dp_attached(const mfw_dp_t *dp, const char *ifname);
/*
 * Is ifname at TC because a program that is not libxdp's dispatcher holds
 * its XDP hook?
 */
int mfw_dp_degraded(const mfw_dp_t *dp, const char *ifname);
/* Names of the attached interfaces, sorted; returns how many (≤ max). */
int mfw_dp_list_attached(const mfw_dp_t *dp, char names[][IF_NAMESIZE],
    int max);
/*
 * In libxdp's dispatcher; at TC ingress if a program that is not one holds
 * the XDP hook.
 */
int mfw_dp_attach(mfw_dp_t *dp, const char *ifname, char *err,
    size_t errlen);
/* Drop the interface's ruleset and detach it. */
void mfw_dp_detach(mfw_dp_t *dp, const char *ifname);

/* Swap in rs as the ruleset of ifindex (one map update). */
int mfw_dp_install(mfw_dp_t *dp, __u32 ifindex, const struct mfw_ruleset *rs,
    char *err, size_t errlen);
/* Remove every ruleset whose ifindex is not in keep[0..n). */
void mfw_dp_prune(mfw_dp_t *dp, const __u32 *keep, int n);

int mfw_dp_get_config(const mfw_dp_t *dp, struct mfw_config *cfg);
/*
 * Set the fragment policy and bump the generation, putting the new one in
 * *generation. Returns 0, or -1 with errno.
 */
int mfw_dp_set_config(mfw_dp_t *dp, int drop_ipv4_fragments,
    __u32 *generation);
int mfw_dp_stats(const mfw_dp_t *dp, __u64 out[MFW_STAT_MAX]);

/*
 * Detach every interface and remove all pins under MFW_PIN_PATH. Returns
 * 0, or -1 with a message in err; an interface that can't be looked up
 * stops it before any pin is removed.
 */
int mfw_dp_purge(char *err, size_t errlen);


#endif /* _MFW_DATAPLANE_H_INCLUDED_ */
