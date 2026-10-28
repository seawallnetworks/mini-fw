
/* SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause */

/*
 * The BPF side of mfwd: loads the program, keeps its maps, attaches it
 * to interfaces. Everything lives in pins under <root> (by default
 * /sys/fs/bpf/seawall/mfw, beside sw_flowd's /sys/fs/bpf/seawall/flows):
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
 * Each attached interface has one of three link pins:
 *
 *   link/xdp_<if>   the normal case: mini-fw's XDP program in the
 *                   interface's libxdp dispatcher, at priority 20 (after
 *                   voidgate's 10)
 *   link/tcx_<if>   degraded: a program that is not a dispatcher holds
 *                   the XDP hook, and mini-fw never replaces it, so the
 *                   TC ingress program is attached with a tcx link
 *   link/tc_<if>    degraded, on a kernel without tcx (before 6.6): the
 *                   TC ingress program is a classic TC filter (cls_bpf on
 *                   the clsact qdisc); the pin marks that mini-fw put it
 *                   there
 *
 * Because everything is pinned, filtering goes on while mfwd is stopped
 * or restarting.
 *
 * A ruleset is never changed in place: a new one goes into a new inner
 * map, which one update of the outer map swaps in. A packet sees either
 * the old ruleset or the new one, never a mix.
 */


#include "dataplane.h"
#include "dp_link.h"
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
#include <sys/stat.h>
#include <unistd.h>
#include <xdp/libxdp.h>


static int name_cmp(const void *a, const void *b);
static int init_config(struct mfw_dp *dp, char *err, size_t len);
static void upgrade_links(struct mfw_dp *dp);
static int upgrade_link(struct mfw_dp *dp, const char *ifname);
static void drop_old_stats(const char *root);
static int links_detach(const char *root, char *err, size_t errlen);
static void flows_open(struct mfw_dp *dp);


int
mfw_dp_attached(const struct mfw_dp *dp, const char *ifname)
{
    int  fd;

    if (mfw_xdp_attached(dp->root, ifname)) {
        return 1;
    }

    fd = mfw_tcx_open(dp->root, ifname);
    if (fd < 0) {
        return mfw_tc_attached(dp->root, ifname);
    }

    close(fd);

    return 1;
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


static int
name_cmp(const void *a, const void *b)
{
    return strcmp(a, b);
}


int
mfw_dp_list(const struct mfw_dp *dp, char names[][IF_NAMESIZE], int max)
{
    int              n;
    DIR             *d;
    const char      *ifname;
    struct dirent   *de;
    char             dir[PATH_MAX];

    snprintf(dir, sizeof(dir), "%s/link", dp->root);

    d = opendir(dir);
    if (d == NULL) {
        return 0;
    }

    n = 0;

    while (n < max && (de = readdir(d)) != NULL) {
        ifname = strchr(de->d_name, '_');

        if (ifname == NULL || strlen(++ifname) >= IF_NAMESIZE
            || (strncmp(de->d_name, "tcx_", 4) != 0
                && strncmp(de->d_name, "tc_", 3) != 0
                && strncmp(de->d_name, "xdp_", 4) != 0))
        {
            continue;
        }

        if (mfw_dp_attached(dp, ifname)) {
            snprintf(names[n++], IF_NAMESIZE, "%s", ifname);
        }
    }

    closedir(d);
    qsort(names, n, IF_NAMESIZE, name_cmp);

    return n;
}


/*
 * Check the config map. A new one (all zeros) gets the defaults; one from
 * another ABI version is refused.
 */
static int
init_config(struct mfw_dp *dp, char *err, size_t len)
{
    __u32              k;
    struct mfw_config  cfg;

    k = 0;

    if (bpf_map_lookup_elem(dp->config_fd, &k, &cfg) != 0) {
        return sw_fail(err, len, "read config: %s", strerror(errno));
    }

    if (cfg.abi_version == MFW_ABI_VERSION) {
        return 0;
    }

    if (cfg.abi_version != 0) {
        return sw_fail(err, len, "pinned maps under %s have ABI %u, "
                       "expected %u (mfwd -P to remove them)", dp->root,
                       cfg.abi_version, MFW_ABI_VERSION);
    }

    memset(&cfg, 0, sizeof(cfg));
    cfg.default_action = MFW_ACTION_DENY;
    cfg.abi_version = MFW_ABI_VERSION;

    if (bpf_map_update_elem(dp->config_fd, &k, &cfg, BPF_ANY) != 0) {
        return sw_fail(err, len, "init config: %s", strerror(errno));
    }

    return 0;
}


/*
 * Move the interfaces an earlier mfwd attached to the program loaded now:
 *
 * - In a dispatcher: load the new program, then take the old one out.
 *   libxdp can't swap them in one step, so both run for a moment, on the
 *   same maps, and no packet goes unfiltered.
 * - At TC, with the XDP hook free now: move to XDP, again XDP first,
 *   then off TC.
 * - At TC otherwise: point the tcx link, or the classic TC filter, at
 *   the new program.
 */
static void
upgrade_links(struct mfw_dp *dp)
{
    int   e, i, n;
    char  names[MFW_MAX_IFACES][IF_NAMESIZE];

    n = mfw_dp_list(dp, names, MFW_MAX_IFACES);

    for (i = 0; i < n; i++) {
        e = upgrade_link(dp, names[i]);
        if (e != 0) {
            sw_log_warn("%s: update program: %s", names[i], strerror(e));
        }
    }
}


/* One interface of upgrade_links(). Returns 0 or an errno. */
static int
upgrade_link(struct mfw_dp *dp, const char *ifname)
{
    int                   e, fd, ifindex;
    __u32                 old;
    enum xdp_attach_mode  mode;
    char                  holder[BPF_OBJ_NAME_LEN];
    char                  path[PATH_MAX];

    /* can't tell: left on the old program, which goes on filtering */
    ifindex = sw_netif_index(ifname, NULL, 0);
    if (ifindex < 0) {
        return errno;
    }

    if (mfw_xdp_attached(dp->root, ifname)) {
        mfw_xdp_path(dp->root, ifname, path, sizeof(path));
        old = mfw_xdp_pinned_id(path);

        mode = XDP_MODE_NATIVE;

        if (mfw_xdp_state(ifindex, &mode, holder, sizeof(holder))
            != mfw_xdp_shared)
        {
            return ENOENT;
        }

        e = -mfw_xdp_load(dp->root, ifname, ifindex, mode, dp->flows_fd);
        if (e != 0) {
            return e;
        }

        mfw_xdp_unload(ifindex, old);

        return 0;
    }

    if (!dp->no_xdp
        && mfw_xdp_attach(dp->root, ifname, ifindex, dp->flows_fd, holder,
                          sizeof(holder))
           == 0)
    {
        mfw_tc_off(dp->root, ifname);
        sw_log_notice("%s: the XDP hook is free: moved from TC to XDP",
                      ifname);
        return 0;
    }

    fd = mfw_tcx_open(dp->root, ifname);
    if (fd >= 0) {
        e = 0;

        if (bpf_link_update(fd, dp->prog_fd, NULL) != 0) {
            e = errno;
        }

        close(fd);

        return e;
    }

    if (!mfw_tc_attached(dp->root, ifname)) {
        return 0;
    }

    e = -mfw_tc_attach(ifindex, dp->prog_fd);
    if (e != 0) {
        return e;
    }

    if (mfw_tc_pin(dp->root, ifname, dp->prog_fd) != 0) {
        return errno;
    }

    return 0;
}


/*
 * The stats map has MFW_STAT_MAX entries. A pinned one from a build with
 * a different number can't be reused (libbpf refuses another
 * max_entries), so its pin is deleted and the load pins a new map. The
 * counters restart; the rules and links stay. The old program keeps the
 * old map until upgrade_links() replaces the program.
 */
static void
drop_old_stats(const char *root)
{
    int                   fd;
    __u32                 len;
    struct bpf_map_info   info = {};
    char                  path[PATH_MAX];

    snprintf(path, sizeof(path), "%s/maps/stats", root);

    fd = bpf_obj_get(path);
    if (fd < 0) {
        return;
    }

    len = sizeof(info);

    if (bpf_map_get_info_by_fd(fd, &info, &len) == 0
        && info.max_entries != MFW_STAT_MAX)
    {
        unlink(path);
    }

    close(fd);
}


int
mfw_dp_open(struct mfw_dp *dp, const char *root, char *err, size_t errlen)
{
    char  maps[PATH_MAX], links[PATH_MAX];
    LIBBPF_OPTS(bpf_object_open_opts, opts, .pin_root_path = maps);

    memset(dp, 0, sizeof(*dp));
    dp->prog_fd = -1;
    dp->rulesets_fd = -1;
    dp->config_fd = -1;
    dp->stats_fd = -1;
    dp->flows_fd = -1;

    if (strlen(root) >= sizeof(dp->root)) {
        return sw_fail(err, errlen, "pin root too long");
    }

    snprintf(dp->root, sizeof(dp->root), "%s", root);

    /* the pin root may not exist yet: the nearest ancestor that does */
    if (sw_bpffs_check(root, err, errlen) != 0) {
        return -1;
    }

    snprintf(maps, sizeof(maps), "%s/maps", root);
    snprintf(links, sizeof(links), "%s/link", root);

    if (sw_file_mkdir_p(maps, 0700) != 0 || sw_file_mkdir_p(links, 0700) != 0) {
        return sw_fail(err, errlen, "create %s: %s", root, strerror(errno));
    }

    drop_old_stats(dp->root);

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
     * in a dispatcher (see mfw_xdp_load()).
     */
    bpf_program__set_autoload(dp->skel->progs.mfw_xdp, false);

    /* reuses the pinned maps, and pins any that don't exist yet */
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

    upgrade_links(dp);

    return 0;

failed:

    mfw_dp_close(dp);

    return -1;
}


void
mfw_dp_close(struct mfw_dp *dp)
{
    mfw_bpf__destroy(dp->skel);  /* the pins keep maps and links alive */
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
 * sw_flowd's table, for every program this mfwd loads to bind. The table
 * is not versioned: one of another layout is a sw_flowd built from
 * another sw_flowd.h than mini-fw was, and is not bound. Either way "reply"
 * ACEs match nothing until mfwd restarts with the right one.
 */
static void
flows_open(struct mfw_dp *dp)
{
    int                  fd;
    __u32                len;
    struct bpf_map_info  info;

    fd = bpf_obj_get(SF_PIN_ROOT "/" SF_PIN_OUTBOUND);

    if (fd < 0) {
        sw_log_warn("no sw_flowd flow table under %s: \"reply\" ACEs match "
                    "nothing until mfwd restarts with it (start sw_flowd "
                    "first)", SF_PIN_ROOT);
        return;
    }

    memset(&info, 0, sizeof(info));
    len = sizeof(info);

    if (bpf_map_get_info_by_fd(fd, &info, &len) != 0
        || info.type != BPF_MAP_TYPE_LRU_HASH
        || info.key_size != sizeof(struct sf_flow_key)
        || info.value_size != sizeof(struct sf_flow))
    {
        sw_log_warn("sw_flowd's flow table under %s is not the layout this "
                    "mfwd reads: \"reply\" ACEs match nothing", SF_PIN_ROOT);
        close(fd);
        return;
    }

    dp->flows_fd = fd;
    sw_log_info("reading sw_flowd's flow table (%u flows): \"reply\" ACEs "
                "match replies to the host's own flows", info.max_entries);
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
 * Detach what the pins under <root>/link attached. Deleting a tcx link
 * pin detaches the program, but a classic TC filter and a program in a
 * dispatcher stay until removed, so remove those; the pins stay. An
 * interface that can't be looked up stops it, with -1 and the reason in
 * err: its pins must stay, or mini-fw would run on there, unknown.
 */
static int
links_detach(const char *root, char *err, size_t errlen)
{
    int              ifindex, rc, tc;
    DIR             *d;
    const char      *ifname;
    struct dirent   *de;
    char             path[PATH_MAX];

    snprintf(path, sizeof(path), "%s/link", root);

    d = opendir(path);
    if (d == NULL) {
        return 0;
    }

    rc = 0;

    while (rc == 0 && (de = readdir(d)) != NULL) {
        if (strncmp(de->d_name, "tc_", 3) == 0) {
            ifname = de->d_name + 3;
            tc = 1;

        } else if (strncmp(de->d_name, "xdp_", 4) == 0) {
            ifname = de->d_name + 4;
            tc = 0;

        } else {
            continue;
        }

        ifindex = sw_netif_index(ifname, err, errlen);

        if (ifindex < 0) {
            rc = -1;

        } else if (ifindex > 0 && tc) {
            mfw_tc_detach(ifindex);

        } else if (ifindex > 0) {
            mfw_xdp_path(root, ifname, path, sizeof(path));
            mfw_xdp_unload(ifindex, mfw_xdp_pinned_id(path));
        }
    }

    closedir(d);

    return rc;
}


/*
 * rename(2) on bpffs moves a directory with everything pinned in it:
 * the links stay attached, the maps keep their contents, and the next
 * mfw_dp_open() takes them over in place. Both are on the one bpffs, or
 * the rename fails.
 */
int
mfw_dp_move_root(const char *old, const char *root, char *err,
    size_t errlen)
{
    char         *slash;
    struct stat   st;
    char          parent[PATH_MAX];

    if (stat(old, &st) != 0) {
        return 0;
    }

    /* a second set of links would attach mini-fw twice */
    if (stat(root, &st) == 0) {
        return sw_fail(err, errlen, "pins under both %s and %s: "
                       "mfwd -P -p %s removes the old ones", old, root, old);
    }

    snprintf(parent, sizeof(parent), "%s", root);

    slash = strrchr(parent, '/');
    if (slash != NULL && slash != parent) {
        *slash = '\0';

        if (sw_file_mkdir_p(parent, 0700) != 0) {
            return sw_fail(err, errlen, "create %s: %s", parent,
                           strerror(errno));
        }
    }

    if (rename(old, root) != 0) {
        return sw_fail(err, errlen, "move %s to %s: %s", old, root,
                       strerror(errno));
    }

    return 1;
}


int
mfw_dp_purge(const char *root, char *err, size_t errlen)
{
    int          i;
    char         dir[PATH_MAX];

    /* state/ was left by mfw 0.2 */
    static const char  *dirs[] = { "link", "maps", "state" };

    /* links first, so no interface is left running on deleted maps */
    if (links_detach(root, err, errlen) != 0) {
        return -1;
    }

    for (i = 0; i < 3; i++) {
        snprintf(dir, sizeof(dir), "%s/%s", root, dirs[i]);

        if (sw_bpffs_unpin_dir(dir, err, errlen) != 0) {
            return -1;
        }
    }

    if (rmdir(root) != 0 && errno != ENOENT) {
        return sw_fail(err, errlen, "rmdir %s: %s", root, strerror(errno));
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
