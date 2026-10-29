
/* SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause */

/*
 * The BPF side of mfwd: loads the program, keeps its maps, attaches it
 * to interfaces. Everything lives in pins under <root>
 * (/sys/fs/bpf/seawall/mfw, beside sw_flowd's /sys/fs/bpf/seawall/flows):
 *
 *   maps/rulesets   hash of maps: ifindex → an inner map holding that
 *                   interface's mfw_ruleset
 *   maps/config     array: flags, generation
 *   maps/stats      per-CPU counters
 *
 * "reply" ACEs look up sw_flowd's table, /sys/fs/bpf/seawall/flows/outbound
 * (Seawall proposal 0009), which every program mfwd loads binds at load:
 * sw_flowd starts first. Without it, a program gets an empty map of its
 * own, and keeps it until an mfwd started with the table replaces it.
 *
 * Each attached interface has one pin in attach/, by how it is attached:
 *
 *   attach/xdp_<if>  the normal case: mini-fw's XDP program in the
 *                    interface's libxdp dispatcher, at priority 20 (after
 *                    voidgate's 10). A program pin: the dispatcher's own
 *                    pins keep it there, this one says which copy is ours
 *   attach/tcx_<if>  degraded: a program that is not a dispatcher holds
 *                    the XDP hook, and mini-fw never replaces it, so the
 *                    TC ingress program is attached with a tcx link. The
 *                    one bpf_link: the pin keeps it attached
 *   attach/tc_<if>   degraded, on a kernel without tcx (before 6.6): the
 *                    TC ingress program is a classic TC filter (cls_bpf
 *                    on the clsact qdisc). A program pin that marks that
 *                    mini-fw put it there
 *
 * Because everything is pinned, filtering goes on while mfwd is stopped.
 * There is no live update: a starting mfwd detaches what an earlier one
 * attached and removes its pins, so the interfaces pass everything
 * (fail-open) until mfwd applies the saved policy again.
 *
 * A ruleset is never changed in place: a new one goes into a new inner
 * map, which one update of the outer map swaps in. A packet sees either
 * the old ruleset or the new one, never a mix.
 */


#include "dataplane.h"
#include "dp_attach.h"
#include "mfw.skel.h"

#include <sw_flowd/sw_flowd.h>

#include <sw/bpf.h>
#include <sw/bpffs.h>
#include <sw/fail.h>
#include <sw/file.h>
#include <sw/log.h>
#include <sw/netif.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <xdp/libxdp.h>


/* The kinds of pin in attach/ (see above), in pin_ifname()'s order. */
typedef enum {
    mfw_pin_xdp = 0,     /* attach/xdp_<if> */
    mfw_pin_tcx,         /* attach/tcx_<if> */
    mfw_pin_tc           /* attach/tc_<if> */
} mfw_pin_e;


static const char *pin_ifname(const char *pin, mfw_pin_e *kind);
static int name_cmp(const void *a, const void *b);
static int init_config(struct mfw_dp *dp, char *err, size_t len);
static int detach_pinned(const char *root, char *err, size_t errlen);
static void flows_open(struct mfw_dp *dp);


int
mfw_dp_attached(const struct mfw_dp *dp, const char *ifname)
{
    return mfw_xdp_attached(dp->root, ifname)
           || mfw_tcx_attached(dp->root, ifname)
           || mfw_tc_attached(dp->root, ifname);
}


int
mfw_dp_degraded(const struct mfw_dp *dp, const char *ifname)
{
    int                   ifindex;
    enum xdp_attach_mode  mode;
    char                  holder[BPF_OBJ_NAME_LEN];

    ifindex = sw_netif_index(ifname, NULL, 0);

    return ifindex > 0
           && !mfw_xdp_attached(dp->root, ifname)
           && mfw_dp_attached(dp, ifname)
           && mfw_xdp_state(ifindex, &mode, holder, sizeof(holder))
              == mfw_xdp_held;
}


/*
 * The interface an attach/ pin is for: its name after the kind's prefix,
 * with the kind in *kind. NULL if the name is not one of mini-fw's pins,
 * or what follows the prefix is not an interface name.
 */
static const char *
pin_ifname(const char *pin, mfw_pin_e *kind)
{
    size_t              len;
    mfw_pin_e           k;
    static const char  *prefix[] = { "xdp_", "tcx_", "tc_" };

    for (k = mfw_pin_xdp; k <= mfw_pin_tc; k++) {
        len = strlen(prefix[k]);

        if (strncmp(pin, prefix[k], len) == 0) {
            pin += len;
            len = strlen(pin);

            if (len == 0 || len >= IF_NAMESIZE) {
                return NULL;
            }

            *kind = k;

            return pin;
        }
    }

    return NULL;
}


/* names are char[IF_NAMESIZE], so a and b are the strings */
static int
name_cmp(const void *a, const void *b)
{
    return strcmp(a, b);
}


int
mfw_dp_list_attached(const struct mfw_dp *dp, char names[][IF_NAMESIZE],
    int max)
{
    int              n;
    DIR             *d;
    mfw_pin_e        kind;
    const char      *ifname;
    struct dirent   *de;
    char             dir[PATH_MAX];

    snprintf(dir, sizeof(dir), "%s/attach", dp->root);

    d = opendir(dir);
    if (d == NULL) {
        return 0;
    }

    n = 0;

    while (n < max && (de = readdir(d)) != NULL) {
        ifname = pin_ifname(de->d_name, &kind);

        if (ifname != NULL && mfw_dp_attached(dp, ifname)) {
            snprintf(names[n++], IF_NAMESIZE, "%s", ifname);
        }
    }

    closedir(d);
    qsort(names, n, IF_NAMESIZE, name_cmp);

    return n;
}


/* The config map is new (all zeros): give it the defaults. */
static int
init_config(struct mfw_dp *dp, char *err, size_t len)
{
    __u32              k;
    struct mfw_config  cfg;

    k = 0;

    memset(&cfg, 0, sizeof(cfg));
    cfg.default_action = MFW_ACTION_DENY;
    cfg.abi_version = MFW_ABI_VERSION;

    if (bpf_map_update_elem(dp->config_fd, &k, &cfg, BPF_ANY) != 0) {
        return sw_fail(err, len, "init config: %s", strerror(errno));
    }

    return 0;
}


int
mfw_dp_open(struct mfw_dp *dp, char *err, size_t errlen)
{
    char  maps[PATH_MAX], attach[PATH_MAX];
    LIBBPF_OPTS(bpf_object_open_opts, opts, .pin_root_path = maps);

    memset(dp, 0, sizeof(*dp));
    dp->prog_fd = -1;
    dp->rulesets_fd = -1;
    dp->config_fd = -1;
    dp->stats_fd = -1;
    dp->flows_fd = -1;

    dp->root = MFW_PIN_PATH;

    /*
     * Before anything is made: otherwise mkdir in sysfs, or pinning
     * outside bpffs, fails later, and less clearly.
     */
    if (sw_bpffs_check(dp->root, err, errlen) != 0) {
        return -1;
    }

    /* no live update: start afresh, fail-open until the policy is applied */
    if (mfw_dp_purge(err, errlen) != 0) {
        return -1;
    }

    snprintf(maps, sizeof(maps), "%s/maps", dp->root);
    snprintf(attach, sizeof(attach), "%s/attach", dp->root);

    if (sw_file_mkdir_p(maps, 0700) != 0
        || sw_file_mkdir_p(attach, 0700) != 0)
    {
        return sw_fail(err, errlen, "create %s: %s", dp->root,
                       strerror(errno));
    }

    dp->skel = mfw_bpf__open_opts(&opts);
    if (dp->skel == NULL) {
        return sw_fail(err, errlen, "open BPF object: %s", strerror(errno));
    }

    flows_open(dp);

    if (dp->flows_fd >= 0
        && bpf_map__reuse_fd(dp->skel->maps.flows, dp->flows_fd) != 0)
    {
        sw_fail(err, errlen, "bind sw_flowd's flow table: %s",
                strerror(errno));
        goto failed;
    }

    /*
     * Load only the TC entry here, for the interfaces at TC. libxdp loads
     * the XDP entry itself, from a copy of the object, for each interface
     * in a dispatcher (see mfw_xdp_attach()).
     */
    bpf_program__set_autoload(dp->skel->progs.mfw_xdp, false);

    /* pins the maps, under maps/ */
    if (mfw_bpf__load(dp->skel) != 0) {
        sw_fail(err, errlen, "load BPF object: %s (kernel 6.1+ with BTF, "
                "CAP_BPF and CAP_NET_ADMIN needed; mfwd -v with "
                "SW_BPF_DEBUG=1 for the verifier log)", strerror(errno));
        goto failed;
    }

    dp->prog_fd = bpf_program__fd(dp->skel->progs.mfw_tc);
    dp->rulesets_fd = bpf_map__fd(dp->skel->maps.rulesets);
    dp->config_fd = bpf_map__fd(dp->skel->maps.config);
    dp->stats_fd = bpf_map__fd(dp->skel->maps.stats);
    dp->tcx = sw_bpf_have_tcx();
    dp->no_xdp = getenv("MFW_NO_XDP") != NULL;

    if (init_config(dp, err, errlen) != 0) {
        goto failed;
    }

    return 0;

failed:

    mfw_dp_close(dp);

    return -1;
}


void
mfw_dp_close(struct mfw_dp *dp)
{
    mfw_bpf__destroy(dp->skel);  /* the pins keep maps and attachments */
    dp->skel = NULL;

    if (dp->flows_fd >= 0) {
        close(dp->flows_fd);
        dp->flows_fd = -1;
    }
}


int
mfw_dp_attach(struct mfw_dp *dp, const char *ifname, char *err,
    size_t errlen)
{
    int   e, ifindex;
    char  holder[BPF_OBJ_NAME_LEN];

    ifindex = sw_netif_index(ifname, err, errlen);
    if (ifindex < 0) {
        return -1;
    }

    if (ifindex == 0) {
        return sw_fail(err, errlen, "%s: no such interface", ifname);
    }

    if (mfw_dp_attached(dp, ifname)) {
        return 0;
    }

    if (!dp->no_xdp) {
        e = mfw_xdp_attach(dp->root, ifname, ifindex, dp->flows_fd, holder,
                           sizeof(holder));

        if (e == 0) {
            return 0;

        } else if (e == -ENOTSUP) {
            return sw_fail(err, errlen, "%s: attach XDP: libxdp needs bpffs "
                           "at %s", ifname, sw_bpffs_libxdp_dir());

        } else if (e < 0) {
            return sw_fail(err, errlen, "%s: attach XDP: %s", ifname,
                           strerror(-e));
        }

        sw_log_warn("%s: %s holds the XDP hook without libxdp's dispatcher: "
                    "filtering at TC ingress (degraded)", ifname, holder);
    }

    if (!dp->tcx) {
        e = -mfw_tc_attach(ifindex, dp->prog_fd);
        if (e != 0) {
            return sw_fail(err, errlen, "%s: attach TC ingress: %s", ifname,
                           strerror(e));
        }

        if (mfw_tc_pin(dp->root, ifname, dp->prog_fd) != 0) {
            e = errno;
            mfw_tc_detach(ifindex);
            return sw_fail(err, errlen, "%s: pin: %s", ifname, strerror(e));
        }

        return 0;
    }

    return mfw_tcx_attach(dp->root, ifname, ifindex, dp->prog_fd, err,
                          errlen);
}


void
mfw_dp_detach(struct mfw_dp *dp, const char *ifname)
{
    int    idx;
    __u32  ifindex;
    char   err[256];

    /* can't tell: unpinning would leave mini-fw there, unknown to mfwd */
    idx = sw_netif_index(ifname, err, sizeof(err));
    if (idx < 0) {
        mfw_netif_unknown(err);
        return;
    }

    if (idx > 0) {
        ifindex = (__u32) idx;
        bpf_map_delete_elem(dp->rulesets_fd, &ifindex);
    }

    mfw_xdp_detach(dp->root, ifname);
    mfw_tc_off(dp->root, ifname);
}


int
mfw_dp_install(struct mfw_dp *dp, __u32 ifindex, const struct mfw_ruleset *rs,
    char *err, size_t errlen)
{
    int    e, fd;
    __u32  zero;

    fd = bpf_map_create(BPF_MAP_TYPE_ARRAY, "mfw_ruleset", sizeof(__u32),
                        sizeof(*rs), 1, NULL);
    if (fd < 0) {
        return sw_fail(err, errlen, "create ruleset map: %s", strerror(errno));
    }

    e = 0;
    zero = 0;

    if (bpf_map_update_elem(fd, &zero, rs, BPF_ANY) != 0
        || bpf_map_update_elem(dp->rulesets_fd, &ifindex, &fd, BPF_ANY) != 0)
    {
        e = errno;
    }

    close(fd);  /* the outer map holds the inner map now */

    if (e != 0) {
        return sw_fail(err, errlen, "install ruleset: %s", strerror(e));
    }

    return 0;
}


void
mfw_dp_prune(struct mfw_dp *dp, const __u32 *keep, int n)
{
    int    i, kept, wanted;
    __u32  last, next;

    kept = 0;

    while (bpf_map_get_next_key(dp->rulesets_fd, kept ? &last : NULL, &next)
           == 0)
    {
        wanted = 0;

        for (i = 0; i < n; i++) {
            wanted |= keep[i] == next;
        }

        if (!wanted && bpf_map_delete_elem(dp->rulesets_fd, &next) == 0) {
            continue;  /* next is gone: go on from the last key kept */
        }

        last = next;
        kept = 1;
    }
}


int
mfw_dp_get_config(const struct mfw_dp *dp, struct mfw_config *cfg)
{
    __u32  k;

    k = 0;

    return bpf_map_lookup_elem(dp->config_fd, &k, cfg) != 0 ? -1 : 0;
}


int
mfw_dp_set_config(struct mfw_dp *dp, int drop_ipv4_fragments,
    __u32 *generation)
{
    __u32              k;
    struct mfw_config  cfg;

    k = 0;

    if (bpf_map_lookup_elem(dp->config_fd, &k, &cfg) != 0) {
        return -1;
    }

    cfg.drop_ipv4_fragments = !!drop_ipv4_fragments;
    *generation = ++cfg.generation;

    return bpf_map_update_elem(dp->config_fd, &k, &cfg, BPF_ANY) != 0 ? -1 : 0;
}


/*
 * sw_flowd's table, for every program this mfwd loads to bind.
 * sf_outbound_open() refuses one of another layout, a sw_flowd built from
 * another sw_flowd.h than mini-fw was. Without it, "reply" ACEs match
 * nothing until mfwd restarts with the right one.
 */
static void
flows_open(struct mfw_dp *dp)
{
    int    fd;
    __u32  size;

    size = 0;
    fd = sf_outbound_open(&size);

    if (fd == -ENOENT) {
        sw_log_warn("no sw_flowd flow table under %s: \"reply\" ACEs match "
                    "nothing until mfwd restarts with it (start sw_flowd "
                    "first)", SF_PIN_ROOT);
        return;
    }

    if (fd == -EPROTO) {
        sw_log_warn("sw_flowd's flow table under %s is not the layout this "
                    "mfwd reads: \"reply\" ACEs match nothing", SF_PIN_ROOT);
        return;
    }

    if (fd < 0) {
        sw_log_warn("sw_flowd's flow table under %s: %s: \"reply\" ACEs "
                    "match nothing", SF_PIN_ROOT, strerror(-fd));
        return;
    }

    dp->flows_fd = fd;
    sw_log_info("reading sw_flowd's flow table (%u flows): \"reply\" ACEs "
                "match replies to the host's own flows", size);
}


int
mfw_dp_stats(const struct mfw_dp *dp, __u64 out[MFW_STAT_MAX])
{
    int                     c, ncpu;
    __u32                   id;
    struct mfw_stat_value  *vals;

    ncpu = libbpf_num_possible_cpus();
    if (ncpu < 1) {
        return -1;
    }

    vals = calloc(ncpu, sizeof(*vals));
    if (vals == NULL) {
        return -1;
    }

    for (id = 0; id < MFW_STAT_MAX; id++) {
        out[id] = 0;

        if (bpf_map_lookup_elem(dp->stats_fd, &id, vals) != 0) {
            continue;
        }

        for (c = 0; c < ncpu; c++) {
            out[id] += vals[c].count;
        }
    }

    free(vals);

    return 0;
}


/*
 * Detach what the pins under <root>/attach attached. Deleting a tcx link
 * pin detaches the program, but a classic TC filter and a program in a
 * dispatcher stay until removed, so remove those; the pins stay. An
 * interface that can't be looked up stops it, with -1 and the reason in
 * err: its pins must stay, or mini-fw would run on there, unknown.
 */
static int
detach_pinned(const char *root, char *err, size_t errlen)
{
    int              ifindex, rc;
    DIR             *d;
    mfw_pin_e        kind;
    const char      *ifname;
    struct dirent   *de;
    char             path[PATH_MAX];

    snprintf(path, sizeof(path), "%s/attach", root);

    d = opendir(path);
    if (d == NULL) {
        return 0;
    }

    rc = 0;

    while (rc == 0 && (de = readdir(d)) != NULL) {
        ifname = pin_ifname(de->d_name, &kind);

        /* a tcx link detaches when its pin is deleted */
        if (ifname == NULL || kind == mfw_pin_tcx) {
            continue;
        }

        ifindex = sw_netif_index(ifname, err, errlen);

        if (ifindex < 0) {
            rc = -1;

        } else if (ifindex > 0 && kind == mfw_pin_tc) {
            mfw_tc_detach(ifindex);

        } else if (ifindex > 0) {
            mfw_xdp_path(root, ifname, path, sizeof(path));
            mfw_xdp_unload(ifindex, mfw_xdp_pinned_id(path));
        }
    }

    closedir(d);

    return rc;
}


int
mfw_dp_purge(char *err, size_t errlen)
{
    size_t       i;
    char         dir[PATH_MAX];

    static const char  *dirs[] = { "attach", "maps" };

    /* detach first, so no interface is left running on deleted maps */
    if (detach_pinned(MFW_PIN_PATH, err, errlen) != 0) {
        return -1;
    }

    for (i = 0; i < sizeof(dirs) / sizeof(dirs[0]); i++) {
        snprintf(dir, sizeof(dir), "%s/%s", MFW_PIN_PATH, dirs[i]);

        if (sw_bpffs_unpin_dir(dir, err, errlen) != 0) {
            return -1;
        }
    }

    if (rmdir(MFW_PIN_PATH) != 0 && errno != ENOENT) {
        return sw_fail(err, errlen, "rmdir %s: %s", MFW_PIN_PATH,
                       strerror(errno));
    }

    return 0;
}


void
mfw_netif_unknown(const char *err)
{
    static int  said;

    if (!said) {
        sw_log_warn("%s: no interface is attached or detached until it can",
                    err);
        said = 1;
    }
}
