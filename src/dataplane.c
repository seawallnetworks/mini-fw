
/* SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause */

/*
 * The BPF side of mfwd: loads the program, keeps its maps, attaches it
 * to interfaces. Everything lives in pins under <root> (by default
 * /sys/fs/bpf/mfw):
 *
 *   maps/rulesets   hash of maps: ifindex → an inner map holding that
 *                   interface's mfw_ruleset
 *   maps/config     array: flags, generation
 *   maps/stats      per-CPU counters
 *
 * Each attached interface has one of three link pins:
 *
 *   link/xdp_<if>   the normal case: mini-fw's XDP program in the
 *                   interface's libxdp dispatcher, at priority 20 (after
 *                   voidGate's 10)
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
#include "mfw.skel.h"

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <dirent.h>
#include <errno.h>
#include <linux/magic.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <unistd.h>
#include <xdp/libxdp.h>


/*
 * tcx came with Linux 6.6. When building with older UAPI headers (Amazon
 * Linux 2023 has 6.1's), define its values here, so mfwd still uses tcx
 * on a kernel that has it.
 */
#ifndef BPF_F_BEFORE
#define BPF_TCX_INGRESS    46
#define BPF_LINK_TYPE_TCX  11
/* in bpf_link_info's union, tcx.ifindex is where xdp.ifindex is */
#define TCX_IFINDEX(info)  ((info).xdp.ifindex)
#else /* BPF_F_BEFORE */
#define TCX_IFINDEX(info)  ((info).tcx.ifindex)
#endif /* BPF_F_BEFORE */

/*
 * mini-fw's classic TC filter. The handle identifies it; the priority is
 * a late one, so tc programs attached before mini-fw run first, as they
 * do with tcx.
 */
#define MFW_TC_HANDLE    0x4d46  /* "MF" */
#define MFW_TC_PRIORITY  0xc000

#define MFW_XDP_PROG  "mfw_xdp"


/* What holds an interface's XDP hook. */
typedef enum {
    mfw_xdp_free = 0,    /* nothing */
    mfw_xdp_shared,      /* libxdp's dispatcher */
    mfw_xdp_held         /* a program that is not a dispatcher */
} mfw_xdp_hook_e;


static int fail(char *err, size_t len, const char *fmt, ...);
static int ensure_dir(const char *path);
static void tcx_path(const char *root, const char *ifname, char *buf,
    size_t len);
static void tc_path(const char *root, const char *ifname, char *buf,
    size_t len);
static void xdp_path(const char *root, const char *ifname, char *buf,
    size_t len);
static int libxdp_bpffs(void);
static int xdp_state(int ifindex, enum xdp_attach_mode *mode, char *holder,
    size_t len);
static int xdp_remove(int ifindex, __u32 id);
static __u32 pinned_id(const char *path);
static int xdp_attached(const char *root, const char *ifname);
static int xdp_load(const char *root, const char *ifname, int ifindex,
    enum xdp_attach_mode mode);
static int xdp_attach(const char *root, const char *ifname, int ifindex,
    char *holder, size_t len);
static void xdp_detach(const char *root, const char *ifname);
static int have_tcx(void);
static int tc_attach(int ifindex, int prog_fd);
static void tc_detach(int ifindex);
static int tc_attached(const char *root, const char *ifname);
static int tc_pin(const char *root, const char *ifname, int prog_fd);
static __u32 tcx_link_ifindex(int fd);
static int tcx_open(const char *root, const char *ifname);
static int name_cmp(const void *a, const void *b);
static int check_bpffs(const char *root, char *err, size_t len);
static int init_config(struct mfw_dp *dp, char *err, size_t len);
static void tc_off(const char *root, const char *ifname);
static void upgrade_links(struct mfw_dp *dp);
static int libbpf_print(enum libbpf_print_level level, const char *fmt,
    va_list ap);
static int libxdp_print(enum libxdp_print_level level, const char *fmt,
    va_list ap);
static void drop_old_stats(const char *root);
static void rm_dir(const char *dir);


static int
fail(char *err, size_t len, const char *fmt, ...)
{
    va_list  ap;

    va_start(ap, fmt);
    vsnprintf(err, len, fmt, ap);
    va_end(ap);

    return -1;
}


static int
ensure_dir(const char *path)
{
    char  *p;
    char   tmp[PATH_MAX];

    snprintf(tmp, sizeof(tmp), "%s", path);

    for (p = tmp + 1; *p != '\0'; p++) {
        if (*p != '/') {
            continue;
        }

        *p = '\0';

        if (mkdir(tmp, 0700) != 0 && errno != EEXIST) {
            return -1;
        }

        *p = '/';
    }

    if (mkdir(tmp, 0700) != 0 && errno != EEXIST) {
        return -1;
    }

    return 0;
}


static void
tcx_path(const char *root, const char *ifname, char *buf, size_t len)
{
    snprintf(buf, len, "%s/link/tcx_%.*s", root, IF_NAMESIZE, ifname);
}


static void
tc_path(const char *root, const char *ifname, char *buf, size_t len)
{
    snprintf(buf, len, "%s/link/tc_%.*s", root, IF_NAMESIZE, ifname);
}


static void
xdp_path(const char *root, const char *ifname, char *buf, size_t len)
{
    snprintf(buf, len, "%s/link/xdp_%.*s", root, IF_NAMESIZE, ifname);
}


/*
 * Is bpffs mounted where libxdp looks for it? libxdp keeps its
 * dispatchers' state there. Without it, libxdp attaches a program alone,
 * without a dispatcher, and no other program can join the hook after it.
 */
static int
libxdp_bpffs(void)
{
    const char     *dir;
    struct statfs   st;

    dir = getenv("LIBXDP_BPFFS");
    if (dir == NULL) {
        dir = "/sys/fs/bpf";
    }

    return statfs(dir, &st) == 0 && st.f_type == BPF_FS_MAGIC;
}


/*
 * What holds ifindex's XDP hook:
 *
 *   mfw_xdp_free     nothing
 *   mfw_xdp_shared   a libxdp dispatcher; its mode is put in *mode
 *   mfw_xdp_held     a program on its own; its name is put in holder
 *
 * Returns one of those, or -errno if the hook can't be read.
 */
static int
xdp_state(int ifindex, enum xdp_attach_mode *mode, char *holder, size_t len)
{
    int                    state;
    long                   e;
    struct xdp_program    *main;
    struct xdp_multiprog  *mp;

    mp = xdp_multiprog__get_from_ifindex(ifindex);

    e = libxdp_get_error(mp);
    if (e == -ENOENT) {
        return mfw_xdp_free;
    }

    if (e != 0) {
        return e;
    }

    main = xdp_multiprog__main_prog(mp);

    if (!xdp_multiprog__is_legacy(mp)) {
        *mode = xdp_multiprog__attach_mode(mp);
        state = mfw_xdp_shared;

    } else if (main != NULL) {
        snprintf(holder, len, "%s", xdp_program__name(main));
        state = mfw_xdp_held;

    } else {
        /* only a hardware-offloaded program: the driver hook is free */
        state = mfw_xdp_free;
    }

    xdp_multiprog__close(mp);

    return state;
}


/*
 * Take one mini-fw program out of ifindex's libxdp dispatcher.
 *
 * - id != 0: the program with that id.
 * - id == 0: the first program named mfw_xdp, whatever its id (used to
 *   clean up copies no pin points to any more).
 *
 * Returns 1 if a program was taken out, 0 if there is no dispatcher or
 * no such program in it, or -errno if libxdp fails to detach it.
 */
static int
xdp_remove(int ifindex, __u32 id)
{
    int                    e;
    struct xdp_program    *p;
    struct xdp_multiprog  *mp;

    mp = xdp_multiprog__get_from_ifindex(ifindex);
    if (libxdp_get_error(mp) != 0) {
        return 0;
    }

    p = NULL;

    if (!xdp_multiprog__is_legacy(mp)) {
        while ((p = xdp_multiprog__next_prog(p, mp)) != NULL) {
            if (id != 0 ? xdp_program__id(p) == id
                        : strcmp(xdp_program__name(p), MFW_XDP_PROG) == 0)
            {
                break;
            }
        }
    }

    e = 0;

    if (p != NULL) {
        e = xdp_program__detach(p, ifindex, xdp_multiprog__attach_mode(mp),
                                0);
    }

    xdp_multiprog__close(mp);

    if (e != 0) {
        return e;
    }

    return p != NULL;
}


/* The id of the program pinned at path; 0 if none. */
static __u32
pinned_id(const char *path)
{
    int                    fd;
    __u32                  len;
    struct bpf_prog_info   info = {};

    fd = bpf_obj_get(path);
    if (fd < 0) {
        return 0;
    }

    len = sizeof(info);

    if (bpf_prog_get_info_by_fd(fd, &info, &len) != 0) {
        info.id = 0;
    }

    close(fd);

    return info.id;
}


/*
 * Is the program pinned at link/xdp_<ifname> still in ifname's
 * dispatcher? If not (the interface was deleted or re-created, or the
 * program was taken out), the stale pin is deleted and 0 returned.
 */
static int
xdp_attached(const char *root, const char *ifname)
{
    int                    ifindex;
    __u32                  id;
    struct xdp_program    *p;
    struct xdp_multiprog  *mp;
    char                   path[PATH_MAX];

    xdp_path(root, ifname, path, sizeof(path));

    id = pinned_id(path);
    if (id == 0) {
        return 0;
    }

    p = NULL;
    ifindex = if_nametoindex(ifname);
    mp = ifindex != 0 ? xdp_multiprog__get_from_ifindex(ifindex) : NULL;

    if (mp != NULL && libxdp_get_error(mp) == 0) {
        while ((p = xdp_multiprog__next_prog(p, mp)) != NULL) {
            if (xdp_program__id(p) == id) {
                break;
            }
        }

        xdp_multiprog__close(mp);
    }

    if (p != NULL) {
        return 1;
    }

    unlink(path);

    return 0;
}


/*
 * Load a new copy of mini-fw's XDP program into ifindex's dispatcher, in
 * this mode, and pin it as link/xdp_<ifname>. libxdp joins the dispatcher
 * there, or makes one. The copy is a new BPF object that shares the
 * pinned maps; libxdp loads it as an extension of the dispatcher.
 * Returns 0 or -errno.
 */
static int
xdp_load(const char *root, const char *ifname, int ifindex,
    enum xdp_attach_mode mode)
{
    char                 maps[PATH_MAX], path[PATH_MAX];
    LIBBPF_OPTS(bpf_object_open_opts, oopts, .pin_root_path = maps);
    DECLARE_LIBXDP_OPTS(xdp_program_opts, xopts, .prog_name = MFW_XDP_PROG);
    int                  e;
    struct mfw_bpf      *skel;
    struct xdp_program  *xp;

    snprintf(maps, sizeof(maps), "%s/maps", root);

    skel = mfw_bpf__open_opts(&oopts);
    if (skel == NULL) {
        return -errno;
    }

    bpf_program__set_autoload(skel->progs.mfw_tc, false);
    xopts.obj = skel->obj;

    xp = xdp_program__create(&xopts);

    e = libxdp_get_error(xp);
    if (e != 0) {
        mfw_bpf__destroy(skel);
        return e;
    }

    /*
     * The program's xdp.frags section is not enough: libxdp has to be
     * told too, or it makes a dispatcher without frags support, which an
     * interface with a jumbo MTU refuses.
     */
    xdp_program__set_xdp_frags_support(xp, true);

    e = xdp_program__attach(xp, ifindex, mode, 0);
    if (e == 0) {
        xdp_path(root, ifname, path, sizeof(path));
        unlink(path);

        if (bpf_obj_pin(xdp_program__fd(xp), path) != 0) {
            e = -errno;
            xdp_program__detach(xp, ifindex, mode, 0);
        }
    }

    xdp_program__close(xp);
    /* the program stays attached: the dispatcher's pins hold it */
    mfw_bpf__destroy(skel);

    return e;
}


/*
 * Attach mini-fw's XDP program to ifname through libxdp's dispatcher.
 *
 * - If the interface already has a dispatcher, join it, in the mode it
 *   runs in (native or skb).
 * - If the XDP hook is free, make a dispatcher: native mode first, skb
 *   mode if the driver refuses native (some do even when they support
 *   it, such as ENA with an MTU over 3498).
 * - If some other program holds the hook on its own, without a
 *   dispatcher, leave it alone: copy its name into holder and return 1,
 *   so the caller can fall back to TC.
 *
 * Returns 0 when attached, 1 when the hook is held, or -errno
 * (-ENOTSUP if bpffs is not mounted, which libxdp needs).
 */
static int
xdp_attach(const char *root, const char *ifname, int ifindex, char *holder,
    size_t len)
{
    int                   e, i, state;
    enum xdp_attach_mode  mode;

    if (!libxdp_bpffs()) {
        return -ENOTSUP;
    }

    mode = XDP_MODE_NATIVE;

    state = xdp_state(ifindex, &mode, holder, len);
    if (state < 0) {
        return state;
    }

    if (state == mfw_xdp_held) {
        return 1;
    }

    /*
     * Take out copies of mfw_xdp left by a crash or a lost pin, which
     * would otherwise run along with the new one.
     */
    for (i = 0; i < 10 && xdp_remove(ifindex, 0) > 0; i++) { /* void */ }

    e = xdp_load(root, ifname, ifindex, mode);

    /*
     * A new dispatcher was tried in native mode: if the driver refused,
     * try skb mode. A dispatcher that was there keeps its own mode.
     */
    if (e != 0
        && state == mfw_xdp_free
        && e != -EBUSY
        && e != -EEXIST)
    {
        e = xdp_load(root, ifname, ifindex, XDP_MODE_SKB);
    }

    /* another program took the hook after xdp_state() looked */
    if (e == -EBUSY || e == -EEXIST) {
        snprintf(holder, len, "another program");
        return 1;
    }

    return e;
}


/* Leave ifname's dispatcher, if mini-fw is in it. */
static void
xdp_detach(const char *root, const char *ifname)
{
    int    ifindex;
    __u32  id;
    char   path[PATH_MAX];

    xdp_path(root, ifname, path, sizeof(path));
    id = pinned_id(path);
    ifindex = if_nametoindex(ifname);

    if (id != 0 && ifindex != 0) {
        xdp_remove(ifindex, id);
    }

    unlink(path);
}


/*
 * Does the kernel have tcx (6.6+)? One without it refuses a tcx query, so
 * query lo's. MFW_NO_TCX=1 says no anyway, to test classic TC on a newer
 * kernel.
 */
static int
have_tcx(void)
{
    LIBBPF_OPTS(bpf_prog_query_opts, q);

    if (getenv("MFW_NO_TCX") != NULL) {
        return 0;
    }

    return bpf_prog_query_opts(1 /* lo */, BPF_TCX_INGRESS, &q) == 0;
}


/*
 * Attach prog_fd as mini-fw's classic TC filter on ifindex's ingress,
 * adding the clsact qdisc if there is none. A mini-fw filter already
 * there is replaced in one netlink request, so the interface is never
 * left without one. Returns 0 or -errno.
 */
static int
tc_attach(int ifindex, int prog_fd)
{
    LIBBPF_OPTS(bpf_tc_hook, hook, .ifindex = ifindex,
                .attach_point = BPF_TC_INGRESS);
    LIBBPF_OPTS(bpf_tc_opts, opts, .handle = MFW_TC_HANDLE,
                .priority = MFW_TC_PRIORITY, .prog_fd = prog_fd,
                .flags = BPF_TC_F_REPLACE);
    int  e;

    e = bpf_tc_hook_create(&hook);
    if (e != 0 && e != -EEXIST) {
        return e;
    }

    return bpf_tc_attach(&hook, &opts);
}


/*
 * Remove mini-fw's classic TC filter from ifindex. The clsact qdisc
 * stays: other filters may use it.
 */
static void
tc_detach(int ifindex)
{
    LIBBPF_OPTS(bpf_tc_hook, hook, .ifindex = ifindex,
                .attach_point = BPF_TC_INGRESS);
    LIBBPF_OPTS(bpf_tc_opts, opts, .handle = MFW_TC_HANDLE,
                .priority = MFW_TC_PRIORITY);

    bpf_tc_detach(&hook, &opts);
}


/*
 * Is ifname attached with classic TC? If link/tc_<ifname> is pinned but
 * the filter is gone (the interface was deleted or re-created, or the
 * filter removed), the stale pin is deleted and 0 returned.
 */
static int
tc_attached(const char *root, const char *ifname)
{
    LIBBPF_OPTS(bpf_tc_hook, hook, .attach_point = BPF_TC_INGRESS);
    LIBBPF_OPTS(bpf_tc_opts, opts, .handle = MFW_TC_HANDLE,
                .priority = MFW_TC_PRIORITY);
    char  path[PATH_MAX];

    tc_path(root, ifname, path, sizeof(path));

    if (access(path, F_OK) != 0) {
        return 0;
    }

    hook.ifindex = if_nametoindex(ifname);

    if (hook.ifindex != 0 && bpf_tc_query(&hook, &opts) == 0) {
        return 1;
    }

    unlink(path);

    return 0;
}


/*
 * Pin prog_fd as link/tc_<ifname>, replacing any pin there. The pin only
 * marks that mini-fw attached ifname with classic TC: the filter itself
 * stays in the qdisc whether pinned or not.
 */
static int
tc_pin(const char *root, const char *ifname, int prog_fd)
{
    char  path[PATH_MAX];

    tc_path(root, ifname, path, sizeof(path));
    unlink(path);

    return bpf_obj_pin(prog_fd, path);
}


/*
 * The ifindex a tcx link is attached to; 0 if it is not a tcx link or its
 * interface is gone.
 */
static __u32
tcx_link_ifindex(int fd)
{
    __u32                  len;
    struct bpf_link_info   info = {};

    len = sizeof(info);

    if (bpf_link_get_info_by_fd(fd, &info, &len) != 0
        || info.type != BPF_LINK_TYPE_TCX)
    {
        return 0;
    }

    return TCX_IFINDEX(info);
}


/*
 * Open the tcx link pinned at link/tcx_<ifname>. Returns its fd if the
 * link is still attached to ifname, else -1; a stale pin (the interface
 * was deleted or re-created) is deleted.
 */
static int
tcx_open(const char *root, const char *ifname)
{
    int    fd;
    __u32  now;
    char   path[PATH_MAX];

    tcx_path(root, ifname, path, sizeof(path));

    fd = bpf_obj_get(path);
    if (fd < 0) {
        return -1;
    }

    now = if_nametoindex(ifname);

    if (now == 0 || tcx_link_ifindex(fd) != now) {
        close(fd);
        unlink(path);
        return -1;
    }

    return fd;
}


int
mfw_dp_attached(const struct mfw_dp *dp, const char *ifname)
{
    int  fd;

    if (xdp_attached(dp->root, ifname)) {
        return 1;
    }

    fd = tcx_open(dp->root, ifname);
    if (fd < 0) {
        return tc_attached(dp->root, ifname);
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

    ifindex = if_nametoindex(ifname);

    return ifindex != 0
           && !xdp_attached(dp->root, ifname)
           && mfw_dp_attached(dp, ifname)
           && xdp_state(ifindex, &mode, holder, sizeof(holder))
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


static int
check_bpffs(const char *root, char *err, size_t len)
{
    char           *slash;
    struct statfs   st;
    char            parent[PATH_MAX];

    /* the pin root itself may not exist yet: check its parent */
    snprintf(parent, sizeof(parent), "%s", root);

    slash = strrchr(parent, '/');
    if (slash != NULL && slash != parent) {
        *slash = '\0';
    }

    if (statfs(parent, &st) != 0 || st.f_type != BPF_FS_MAGIC) {
        return fail(err, len,
                    "%s is not on bpffs (mount -t bpf bpf /sys/fs/bpf)",
                    parent);
    }

    return 0;
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
        return fail(err, len, "read config: %s", strerror(errno));
    }

    if (cfg.abi_version == MFW_ABI_VERSION) {
        return 0;
    }

    if (cfg.abi_version != 0) {
        return fail(err, len, "pinned maps under %s have ABI %u, expected %u "
                    "(mfwd -P to remove them)", dp->root, cfg.abi_version,
                    MFW_ABI_VERSION);
    }

    memset(&cfg, 0, sizeof(cfg));
    cfg.default_action = MFW_ACTION_DENY;
    cfg.abi_version = MFW_ABI_VERSION;

    if (bpf_map_update_elem(dp->config_fd, &k, &cfg, BPF_ANY) != 0) {
        return fail(err, len, "init config: %s", strerror(errno));
    }

    return 0;
}


/*
 * Take ifname off TC: delete its tcx link pin, or remove its classic TC
 * filter and pin, whichever it has.
 */
static void
tc_off(const char *root, const char *ifname)
{
    int   ifindex;
    char  path[PATH_MAX];

    tcx_path(root, ifname, path, sizeof(path));
    /* the pin is the link's last reference: the kernel detaches it */
    unlink(path);

    tc_path(root, ifname, path, sizeof(path));
    ifindex = if_nametoindex(ifname);

    if (unlink(path) == 0 && ifindex != 0) {
        tc_detach(ifindex);
    }
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
    int                   e, fd, i, ifindex, n;
    __u32                 old;
    enum xdp_attach_mode  mode;
    char                  holder[BPF_OBJ_NAME_LEN];
    char                  path[PATH_MAX];
    char                  names[MFW_MAX_IFACES][IF_NAMESIZE];

    n = mfw_dp_list(dp, names, MFW_MAX_IFACES);

    for (i = 0; i < n; i++) {
        e = 0;
        mode = XDP_MODE_NATIVE;
        ifindex = if_nametoindex(names[i]);

        if (xdp_attached(dp->root, names[i])) {
            xdp_path(dp->root, names[i], path, sizeof(path));
            old = pinned_id(path);

            if (xdp_state(ifindex, &mode, holder, sizeof(holder))
                != mfw_xdp_shared)
            {
                e = ENOENT;

            } else {
                e = -xdp_load(dp->root, names[i], ifindex, mode);
                if (e == 0) {
                    xdp_remove(ifindex, old);
                }
            }

        } else if (!dp->no_xdp
                   && xdp_attach(dp->root, names[i], ifindex, holder,
                                 sizeof(holder)) == 0)
        {
            tc_off(dp->root, names[i]);
            fprintf(stderr, "mfwd: %s: the XDP hook is free: "
                    "moved from TC to XDP\n", names[i]);

        } else if ((fd = tcx_open(dp->root, names[i])) >= 0) {
            if (bpf_link_update(fd, dp->prog_fd, NULL) != 0) {
                e = errno;
            }

            close(fd);

        } else if (tc_attached(dp->root, names[i])) {
            e = -tc_attach(ifindex, dp->prog_fd);
            if (e == 0 && tc_pin(dp->root, names[i], dp->prog_fd) != 0) {
                e = errno;
            }
        }

        if (e != 0) {
            fprintf(stderr, "mfwd: %s: update program: %s\n", names[i],
                    strerror(e));
        }
    }
}


static int
libbpf_print(enum libbpf_print_level level, const char *fmt, va_list ap)
{
    if (level == LIBBPF_DEBUG && getenv("MFW_DEBUG") == NULL) {
        return 0;
    }

    /*
     * libxdp's own sections, such as .xdp_run_config: libxdp reads them
     * itself, so libbpf's warning about them is noise
     */
    if (strstr(fmt, "skipping unrecognized data section") != NULL) {
        return 0;
    }

    return vfprintf(stderr, fmt, ap);
}


static int
libxdp_print(enum libxdp_print_level level, const char *fmt, va_list ap)
{
    if (level == LIBXDP_DEBUG && getenv("MFW_DEBUG") == NULL) {
        return 0;
    }

    return vfprintf(stderr, fmt, ap);
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

    if (strlen(root) >= sizeof(dp->root)) {
        return fail(err, errlen, "pin root too long");
    }

    snprintf(dp->root, sizeof(dp->root), "%s", root);

    if (check_bpffs(root, err, errlen) != 0) {
        return -1;
    }

    snprintf(maps, sizeof(maps), "%s/maps", root);
    snprintf(links, sizeof(links), "%s/link", root);

    if (ensure_dir(maps) != 0 || ensure_dir(links) != 0) {
        return fail(err, errlen, "create %s: %s", root, strerror(errno));
    }

    drop_old_stats(dp->root);
    libbpf_set_print(libbpf_print);

    dp->skel = mfw_bpf__open_opts(&opts);
    if (dp->skel == NULL) {
        return fail(err, errlen, "open BPF object: %s", strerror(errno));
    }

    /*
     * Load only the TC entry here, for the interfaces at TC. libxdp loads
     * the XDP entry itself, from a copy of the object, for each interface
     * in a dispatcher (see xdp_load()).
     */
    bpf_program__set_autoload(dp->skel->progs.mfw_xdp, false);

    /* reuses the pinned maps, and pins any that don't exist yet */
    if (mfw_bpf__load(dp->skel) != 0) {
        mfw_dp_close(dp);
        return fail(err, errlen, "load BPF object: %s (kernel 6.1+ with BTF, "
                    "CAP_BPF and CAP_NET_ADMIN needed; MFW_DEBUG=1 for the "
                    "verifier log)", strerror(errno));
    }

    dp->prog_fd = bpf_program__fd(dp->skel->progs.mfw_tc);
    dp->rulesets_fd = bpf_map__fd(dp->skel->maps.rulesets);
    dp->config_fd = bpf_map__fd(dp->skel->maps.config);
    dp->stats_fd = bpf_map__fd(dp->skel->maps.stats);
    dp->tcx = have_tcx();
    dp->no_xdp = getenv("MFW_NO_XDP") != NULL;
    libxdp_set_print(libxdp_print);

    if (init_config(dp, err, errlen) != 0) {
        mfw_dp_close(dp);
        return -1;
    }

    upgrade_links(dp);

    return 0;
}


void
mfw_dp_close(struct mfw_dp *dp)
{
    mfw_bpf__destroy(dp->skel);  /* the pins keep maps and links alive */
    dp->skel = NULL;
}


int
mfw_dp_attach(struct mfw_dp *dp, const char *ifname, char *err,
    size_t errlen)
{
    int   e, fd, ifindex;
    char  holder[BPF_OBJ_NAME_LEN];
    char  path[PATH_MAX];

    ifindex = if_nametoindex(ifname);
    if (ifindex == 0) {
        return fail(err, errlen, "%s: no such interface", ifname);
    }

    if (mfw_dp_attached(dp, ifname)) {
        return 0;
    }

    if (!dp->no_xdp) {
        e = xdp_attach(dp->root, ifname, ifindex, holder, sizeof(holder));

        if (e == 0) {
            return 0;

        } else if (e == -ENOTSUP) {
            return fail(err, errlen, "%s: attach XDP: libxdp needs bpffs "
                        "at /sys/fs/bpf", ifname);

        } else if (e < 0) {
            return fail(err, errlen, "%s: attach XDP: %s", ifname,
                        strerror(-e));
        }

        fprintf(stderr, "mfwd: %s: %s holds the XDP hook without libxdp's "
                "dispatcher: filtering at TC ingress (degraded)\n", ifname,
                holder);
    }

    if (!dp->tcx) {
        e = -tc_attach(ifindex, dp->prog_fd);
        if (e != 0) {
            return fail(err, errlen, "%s: attach TC ingress: %s", ifname,
                        strerror(e));
        }

        if (tc_pin(dp->root, ifname, dp->prog_fd) != 0) {
            e = errno;
            tc_detach(ifindex);
            return fail(err, errlen, "%s: pin: %s", ifname, strerror(e));
        }

        return 0;
    }

    /*
     * the link goes after the interface's other tcx programs, so those
     * run first
     */
    fd = bpf_link_create(dp->prog_fd, ifindex, BPF_TCX_INGRESS, NULL);
    if (fd < 0) {
        return fail(err, errlen, "%s: attach TC ingress: %s", ifname,
                    strerror(errno));
    }

    tcx_path(dp->root, ifname, path, sizeof(path));

    if (bpf_obj_pin(fd, path) != 0) {
        e = errno;
        close(fd);  /* the last reference: the link detaches */
        return fail(err, errlen, "%s: pin %s: %s", ifname, path, strerror(e));
    }

    close(fd);  /* the pin keeps the link alive */

    return 0;
}


void
mfw_dp_detach(struct mfw_dp *dp, const char *ifname)
{
    __u32  ifindex;

    ifindex = if_nametoindex(ifname);

    if (ifindex != 0) {
        bpf_map_delete_elem(dp->rulesets_fd, &ifindex);
    }

    xdp_detach(dp->root, ifname);
    tc_off(dp->root, ifname);
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
        return fail(err, errlen, "create ruleset map: %s", strerror(errno));
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
        return fail(err, errlen, "install ruleset: %s", strerror(e));
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


static void
rm_dir(const char *dir)
{
    int              ifindex;
    DIR             *d;
    struct dirent   *de;
    char             path[PATH_MAX];

    d = opendir(dir);
    if (d == NULL) {
        return;
    }

    while ((de = readdir(d)) != NULL) {
        if (de->d_name[0] == '.') {
            continue;
        }

        snprintf(path, sizeof(path), "%s/%s", dir, de->d_name);

        /*
         * Deleting a tcx link pin detaches the program. A classic TC
         * filter and a program in a dispatcher stay until removed, so
         * remove those first.
         */
        if (strncmp(de->d_name, "tc_", 3) == 0) {
            ifindex = if_nametoindex(de->d_name + 3);
            if (ifindex != 0) {
                tc_detach(ifindex);
            }

        } else if (strncmp(de->d_name, "xdp_", 4) == 0) {
            ifindex = if_nametoindex(de->d_name + 4);
            if (ifindex != 0) {
                xdp_remove(ifindex, pinned_id(path));
            }
        }

        unlink(path);
    }

    closedir(d);
    rmdir(dir);
}


void
mfw_dp_purge(const char *root)
{
    char  dir[PATH_MAX];

    /* links first, so no interface is left running on deleted maps */
    snprintf(dir, sizeof(dir), "%s/link", root);
    rm_dir(dir);

    snprintf(dir, sizeof(dir), "%s/maps", root);
    rm_dir(dir);

    snprintf(dir, sizeof(dir), "%s/state", root);  /* left by mfw 0.2 */
    rm_dir(dir);

    rmdir(root);
}
