// SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
/* The BPF side of mfwd.
 *
 *   <root>/maps/rulesets   HASH_OF_MAPS ifindex → inner map (one mfw_ruleset)
 *   <root>/maps/config     ARRAY  flags, generation
 *   <root>/maps/stats      PERCPU counters
 *   <root>/link/xdp_<if>   the XDP program mini-fw put in the interface's
 *                          libxdp dispatcher (priority 20, after voidGate's
 *                          10), whose own pins keep it there without mfwd
 *   <root>/link/tcx_<if>   or, when a program that is not a dispatcher
 *                          holds the XDP hook (degraded: mini-fw never
 *                          replaces it), a pinned bpf_link that keeps the
 *                          TC ingress program attached without mfwd
 *   <root>/link/tc_<if>    or, on a kernel without tcx (before 6.6), the
 *                          program, pinned to say mini-fw attached it with
 *                          classic TC: a cls_bpf filter on the interface's
 *                          clsact qdisc, which stays without mfwd
 *
 * Everything is pinned, so filtering goes on while mfwd is stopped or
 * restarting. An installed inner map is never written again: a new
 * ruleset gets a new inner map, swapped in with one update of the outer
 * map, so a packet sees one whole ruleset. */
#include <dirent.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <unistd.h>
#include <linux/magic.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <xdp/libxdp.h>

/* tcx is Linux 6.6's UAPI: with older headers, such as Amazon Linux 2023's
 * 6.1, mfwd still attaches with tcx on a kernel that has it */
#ifndef BPF_F_BEFORE
#define BPF_TCX_INGRESS   46
#define BPF_LINK_TYPE_TCX 11
/* tcx.ifindex starts bpf_link_info's union, where xdp.ifindex is */
#define TCX_IFINDEX(info) ((info).xdp.ifindex)
#else
#define TCX_IFINDEX(info) ((info).tcx.ifindex)
#endif

#include "dataplane.h"
#include "mfw.skel.h"

static int fail(char *err, size_t len, const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    vsnprintf(err, len, fmt, ap);
    va_end(ap);
    return -1;
}

static int ensure_dir(const char *path)
{
    char tmp[PATH_MAX];

    snprintf(tmp, sizeof(tmp), "%s", path);
    for (char *p = tmp + 1; *p; p++) {
        if (*p != '/')
            continue;
        *p = '\0';
        if (mkdir(tmp, 0700) && errno != EEXIST)
            return -1;
        *p = '/';
    }
    return mkdir(tmp, 0700) && errno != EEXIST ? -1 : 0;
}

/* mini-fw's classic TC filter: its handle, and a priority after most
 * others, so a tc program attached before mini-fw runs first, as with tcx */
#define MFW_TC_HANDLE    0x4d46  /* "MF" */
#define MFW_TC_PRIORITY  0xc000

static void link_path(const char *root, const char *ifname, char *buf, size_t len)
{
    snprintf(buf, len, "%s/link/tcx_%.*s", root, IF_NAMESIZE, ifname);
}

static void tc_path(const char *root, const char *ifname, char *buf, size_t len)
{
    snprintf(buf, len, "%s/link/tc_%.*s", root, IF_NAMESIZE, ifname);
}

static void xdp_path(const char *root, const char *ifname, char *buf, size_t len)
{
    snprintf(buf, len, "%s/link/xdp_%.*s", root, IF_NAMESIZE, ifname);
}

#define MFW_XDP_PROG  "mfw_xdp"

/* What holds an interface's XDP hook. */
enum {
    XDP_FREE,      /* nothing */
    XDP_SHARED,    /* libxdp's dispatcher */
    XDP_HELD,      /* a program that is not a dispatcher */
};

/* libxdp keeps its dispatchers' state on bpffs: without it, it attaches a
 * program alone, which takes the hook from every program after it. */
static int libxdp_bpffs(void)
{
    const char *dir = getenv("LIBXDP_BPFFS");
    struct statfs st;

    return statfs(dir ? dir : "/sys/fs/bpf", &st) == 0 && st.f_type == BPF_FS_MAGIC;
}

/* The state of ifindex's XDP hook; for XDP_SHARED its mode, for XDP_HELD
 * the holder's name. -errno if it can't be read. */
static int xdp_state(int ifindex, enum xdp_attach_mode *mode, char *holder, size_t len)
{
    struct xdp_multiprog *mp = xdp_multiprog__get_from_ifindex(ifindex);
    long e = libxdp_get_error(mp);
    struct xdp_program *main;
    int state;

    if (e == -ENOENT)
        return XDP_FREE;
    if (e)
        return e;
    main = xdp_multiprog__main_prog(mp);
    if (!xdp_multiprog__is_legacy(mp)) {
        *mode = xdp_multiprog__attach_mode(mp);
        state = XDP_SHARED;
    } else if (main) {
        snprintf(holder, len, "%s", xdp_program__name(main));
        state = XDP_HELD;
    } else {
        state = XDP_FREE;  /* only a hardware-offloaded program */
    }
    xdp_multiprog__close(mp);
    return state;
}

/* Take mini-fw's program with id (any, if id is 0) out of ifindex's
 * dispatcher. Returns 1 if one was, 0 if none, -errno. */
static int xdp_remove(int ifindex, __u32 id)
{
    struct xdp_multiprog *mp = xdp_multiprog__get_from_ifindex(ifindex);
    struct xdp_program *p = NULL;
    int e;

    if (libxdp_get_error(mp))
        return 0;
    if (!xdp_multiprog__is_legacy(mp))
        while ((p = xdp_multiprog__next_prog(p, mp)))
            if (id ? xdp_program__id(p) == id
                   : !strcmp(xdp_program__name(p), MFW_XDP_PROG))
                break;
    e = p ? xdp_program__detach(p, ifindex, xdp_multiprog__attach_mode(mp), 0) : 0;
    xdp_multiprog__close(mp);
    return e ? e : p != NULL;
}

/* The id of the program pinned at path; 0 if none. */
static __u32 pinned_id(const char *path)
{
    struct bpf_prog_info info = {};
    __u32 len = sizeof(info);
    int fd = bpf_obj_get(path);

    if (fd < 0)
        return 0;
    if (bpf_prog_get_info_by_fd(fd, &info, &len))
        info.id = 0;
    close(fd);
    return info.id;
}

/* Is mini-fw's pinned program in ifname's dispatcher? A pin whose program
 * is not (the device was deleted or re-created, or the program removed)
 * is removed. */
static int xdp_attached(const char *root, const char *ifname)
{
    struct xdp_multiprog *mp;
    struct xdp_program *p = NULL;
    char path[PATH_MAX];
    int ifindex = if_nametoindex(ifname);
    __u32 id;

    xdp_path(root, ifname, path, sizeof(path));
    id = pinned_id(path);
    if (!id)
        return 0;
    mp = ifindex ? xdp_multiprog__get_from_ifindex(ifindex) : NULL;
    if (mp && !libxdp_get_error(mp)) {
        while ((p = xdp_multiprog__next_prog(p, mp)))
            if (xdp_program__id(p) == id)
                break;
        xdp_multiprog__close(mp);
    }
    if (p)
        return 1;
    unlink(path);
    return 0;
}

/* Load the XDP entry into ifindex's dispatcher, made or joined, and pin it
 * as ifname's xdp_ pin. The object is a new one on the pinned maps: libxdp
 * loads it, as an extension of that dispatcher. Returns 0 or -errno. */
static int xdp_load(const char *root, const char *ifname, int ifindex,
                    enum xdp_attach_mode mode)
{
    char maps[PATH_MAX], path[PATH_MAX];
    LIBBPF_OPTS(bpf_object_open_opts, oopts, .pin_root_path = maps);
    DECLARE_LIBXDP_OPTS(xdp_program_opts, xopts, .prog_name = MFW_XDP_PROG);
    struct xdp_program *xp;
    struct mfw_bpf *skel;
    int e;

    snprintf(maps, sizeof(maps), "%s/maps", root);
    skel = mfw_bpf__open_opts(&oopts);
    if (!skel)
        return -errno;
    bpf_program__set_autoload(skel->progs.mfw_tc, false);
    xopts.obj = skel->obj;
    xp = xdp_program__create(&xopts);
    e = libxdp_get_error(xp);
    if (e) {
        mfw_bpf__destroy(skel);
        return e;
    }
    /* xdp.frags is not enough for libxdp, which then makes a dispatcher
     * without frags: one a jumbo-MTU interface refuses */
    xdp_program__set_xdp_frags_support(xp, true);
    e = xdp_program__attach(xp, ifindex, mode, 0);
    if (!e) {
        xdp_path(root, ifname, path, sizeof(path));
        unlink(path);
        if (bpf_obj_pin(xdp_program__fd(xp), path)) {
            e = -errno;
            xdp_program__detach(xp, ifindex, mode, 0);
        }
    }
    xdp_program__close(xp);
    mfw_bpf__destroy(skel);  /* the dispatcher's pins keep the program */
    return e;
}

/* Put mini-fw in ifname's dispatcher, unless a program that is not one
 * holds the hook: then 1, with its name in holder. A dispatcher has one
 * mode, which joining keeps; making one takes native XDP, else skb (a
 * driver may have native XDP and still refuse it: ENA, say, at an MTU
 * over 3498). Returns 0, 1 or -errno. */
static int xdp_attach(const char *root, const char *ifname, int ifindex,
                      char *holder, size_t len)
{
    enum xdp_attach_mode mode = XDP_MODE_NATIVE;
    int state, e;

    if (!libxdp_bpffs())
        return -ENOTSUP;
    state = xdp_state(ifindex, &mode, holder, len);
    if (state < 0)
        return state;
    if (state == XDP_HELD)
        return 1;
    /* one a crash or a lost pin left would run twice */
    for (int i = 0; i < 10 && xdp_remove(ifindex, 0) > 0; i++)
        ;
    e = xdp_load(root, ifname, ifindex, mode);
    if (e && state == XDP_FREE && e != -EBUSY && e != -EEXIST)
        e = xdp_load(root, ifname, ifindex, XDP_MODE_SKB);
    if (e == -EBUSY || e == -EEXIST) {  /* attached after xdp_state() */
        snprintf(holder, len, "another program");
        return 1;
    }
    return e;
}

/* Leave ifname's dispatcher, if mini-fw is in it. */
static void xdp_detach(const char *root, const char *ifname)
{
    char path[PATH_MAX];
    int ifindex = if_nametoindex(ifname);
    __u32 id;

    xdp_path(root, ifname, path, sizeof(path));
    id = pinned_id(path);
    if (id && ifindex)
        xdp_remove(ifindex, id);
    unlink(path);
}

/* tcx (6.6+): a kernel without it refuses to query it. MFW_NO_TCX=1 takes
 * classic TC anyway, to test it on a newer kernel. */
static int have_tcx(void)
{
    LIBBPF_OPTS(bpf_prog_query_opts, q);

    if (getenv("MFW_NO_TCX"))
        return 0;
    return bpf_prog_query_opts(1 /* lo */, BPF_TCX_INGRESS, &q) == 0;
}

/* Put prog_fd in mini-fw's filter on ifindex's ingress, adding a clsact
 * qdisc if there is none: one netlink request, so a filter already there
 * is replaced atomically. Returns 0 or -errno. */
static int tc_attach(int ifindex, int prog_fd)
{
    LIBBPF_OPTS(bpf_tc_hook, hook, .ifindex = ifindex,
                .attach_point = BPF_TC_INGRESS);
    LIBBPF_OPTS(bpf_tc_opts, opts, .handle = MFW_TC_HANDLE,
                .priority = MFW_TC_PRIORITY, .prog_fd = prog_fd,
                .flags = BPF_TC_F_REPLACE);
    int e = bpf_tc_hook_create(&hook);

    if (e && e != -EEXIST)
        return e;
    return bpf_tc_attach(&hook, &opts);
}

/* The clsact qdisc is left: something else may use it. */
static void tc_detach(int ifindex)
{
    LIBBPF_OPTS(bpf_tc_hook, hook, .ifindex = ifindex,
                .attach_point = BPF_TC_INGRESS);
    LIBBPF_OPTS(bpf_tc_opts, opts, .handle = MFW_TC_HANDLE,
                .priority = MFW_TC_PRIORITY);

    bpf_tc_detach(&hook, &opts);
}

/* Is ifname attached with classic TC? A pin whose filter is gone (the
 * device was deleted or re-created, or the filter removed) is removed. */
static int tc_attached(const char *root, const char *ifname)
{
    LIBBPF_OPTS(bpf_tc_hook, hook, .attach_point = BPF_TC_INGRESS);
    LIBBPF_OPTS(bpf_tc_opts, opts, .handle = MFW_TC_HANDLE,
                .priority = MFW_TC_PRIORITY);
    char path[PATH_MAX];

    tc_path(root, ifname, path, sizeof(path));
    if (access(path, F_OK))
        return 0;
    hook.ifindex = if_nametoindex(ifname);
    if (hook.ifindex && bpf_tc_query(&hook, &opts) == 0)
        return 1;
    unlink(path);
    return 0;
}

/* Pin prog_fd as ifname's tc_ pin, in place of the one there. */
static int tc_pin(const char *root, const char *ifname, int prog_fd)
{
    char path[PATH_MAX];

    tc_path(root, ifname, path, sizeof(path));
    unlink(path);
    return bpf_obj_pin(prog_fd, path);
}

/* The ifindex a TC ingress link is attached to; 0 if its device is gone. */
static __u32 link_ifindex(int fd)
{
    struct bpf_link_info info = {};
    __u32 len = sizeof(info);

    if (bpf_link_get_info_by_fd(fd, &info, &len) || info.type != BPF_LINK_TYPE_TCX)
        return 0;
    return TCX_IFINDEX(info);
}

/* An fd for ifname's link pin if it is alive on that interface, else -1.
 * A dead pin (the device was deleted or re-created) is removed. */
static int open_link(const char *root, const char *ifname)
{
    char path[PATH_MAX];
    __u32 now = if_nametoindex(ifname);
    int fd;

    link_path(root, ifname, path, sizeof(path));
    fd = bpf_obj_get(path);
    if (fd < 0)
        return -1;
    if (!now || link_ifindex(fd) != now) {
        close(fd);
        unlink(path);
        return -1;
    }
    return fd;
}

int mfw_dp_attached(const struct mfw_dp *dp, const char *ifname)
{
    int fd;

    if (xdp_attached(dp->root, ifname))
        return 1;
    fd = open_link(dp->root, ifname);
    if (fd < 0)
        return tc_attached(dp->root, ifname);
    close(fd);
    return 1;
}

int mfw_dp_degraded(const struct mfw_dp *dp, const char *ifname)
{
    enum xdp_attach_mode mode;
    char holder[BPF_OBJ_NAME_LEN];
    int ifindex = if_nametoindex(ifname);

    return ifindex && !xdp_attached(dp->root, ifname) &&
           mfw_dp_attached(dp, ifname) &&
           xdp_state(ifindex, &mode, holder, sizeof(holder)) == XDP_HELD;
}

static int name_cmp(const void *a, const void *b)
{
    return strcmp(a, b);
}

int mfw_dp_list(const struct mfw_dp *dp, char names[][IF_NAMESIZE], int max)
{
    char dir[PATH_MAX];
    struct dirent *de;
    DIR *d;
    int n = 0;

    snprintf(dir, sizeof(dir), "%s/link", dp->root);
    d = opendir(dir);
    if (!d)
        return 0;
    while ((de = readdir(d)) && n < max) {
        const char *ifname = strchr(de->d_name, '_');

        if (!ifname || strlen(++ifname) >= IF_NAMESIZE ||
            (strncmp(de->d_name, "tcx_", 4) && strncmp(de->d_name, "tc_", 3) &&
             strncmp(de->d_name, "xdp_", 4)))
            continue;
        if (mfw_dp_attached(dp, ifname))
            snprintf(names[n++], IF_NAMESIZE, "%s", ifname);
    }
    closedir(d);
    qsort(names, n, IF_NAMESIZE, name_cmp);
    return n;
}

static int check_bpffs(const char *root, char *err, size_t len)
{
    char parent[PATH_MAX], *slash;
    struct statfs st;

    /* the pin root itself may not exist yet: check its parent */
    snprintf(parent, sizeof(parent), "%s", root);
    slash = strrchr(parent, '/');
    if (slash && slash != parent)
        *slash = '\0';
    if (statfs(parent, &st) || st.f_type != BPF_FS_MAGIC)
        return fail(err, len, "%s is not on bpffs (mount -t bpf bpf /sys/fs/bpf)",
                    parent);
    return 0;
}

/* A fresh config gets the defaults; another ABI is refused. */
static int init_config(struct mfw_dp *dp, char *err, size_t len)
{
    struct mfw_config cfg;
    __u32 k = 0;

    if (bpf_map_lookup_elem(dp->config_fd, &k, &cfg))
        return fail(err, len, "read config: %s", strerror(errno));
    if (cfg.abi_version == MFW_ABI_VERSION)
        return 0;
    if (cfg.abi_version != 0)
        return fail(err, len, "pinned maps under %s have ABI %u, expected %u "
                    "(mfwd -P to remove them)", dp->root, cfg.abi_version,
                    MFW_ABI_VERSION);
    memset(&cfg, 0, sizeof(cfg));
    cfg.default_action = MFW_ACTION_DENY;
    cfg.abi_version = MFW_ABI_VERSION;
    if (bpf_map_update_elem(dp->config_fd, &k, &cfg, BPF_ANY))
        return fail(err, len, "init config: %s", strerror(errno));
    return 0;
}

/* Take ifname off TC, where it was attached before. */
static void tc_off(const char *root, const char *ifname)
{
    char path[PATH_MAX];

    link_path(root, ifname, path, sizeof(path));
    unlink(path);  /* last reference: the kernel detaches the program */
    tc_path(root, ifname, path, sizeof(path));
    if (unlink(path) == 0 && if_nametoindex(ifname))
        tc_detach(if_nametoindex(ifname));
}

/* Interfaces attached by an earlier mfwd run the program loaded now. In a
 * dispatcher the new program goes in before the old one comes out, which
 * libxdp can't do in one step: for a moment both run, on the same maps,
 * and nothing passes unfiltered. One at TC moves to XDP if the hook has
 * come free, the same way: XDP first. */
static void upgrade_links(struct mfw_dp *dp)
{
    char names[MFW_MAX_IFACES][IF_NAMESIZE], path[PATH_MAX];
    int n = mfw_dp_list(dp, names, MFW_MAX_IFACES);

    for (int i = 0; i < n; i++) {
        int ifindex = if_nametoindex(names[i]), fd, e = 0;
        enum xdp_attach_mode mode = XDP_MODE_NATIVE;
        char holder[BPF_OBJ_NAME_LEN];
        __u32 old;

        if (xdp_attached(dp->root, names[i])) {
            xdp_path(dp->root, names[i], path, sizeof(path));
            old = pinned_id(path);
            if (xdp_state(ifindex, &mode, holder, sizeof(holder)) != XDP_SHARED)
                e = ENOENT;
            else if ((e = -xdp_load(dp->root, names[i], ifindex, mode)) == 0)
                xdp_remove(ifindex, old);
        } else if (!dp->no_xdp &&
                   xdp_attach(dp->root, names[i], ifindex, holder, sizeof(holder)) == 0) {
            tc_off(dp->root, names[i]);
            fprintf(stderr, "mfwd: %s: the XDP hook is free: moved from TC to XDP\n",
                    names[i]);
        } else if ((fd = open_link(dp->root, names[i])) >= 0) {
            if (bpf_link_update(fd, dp->prog_fd, NULL))
                e = errno;
            close(fd);
        } else if (tc_attached(dp->root, names[i])) {
            e = -tc_attach(ifindex, dp->prog_fd);
            if (!e && tc_pin(dp->root, names[i], dp->prog_fd))
                e = errno;
        }
        if (e)
            fprintf(stderr, "mfwd: %s: update program: %s\n", names[i],
                    strerror(e));
    }
}

static int libbpf_print(enum libbpf_print_level level, const char *fmt, va_list ap)
{
    if (level == LIBBPF_DEBUG && !getenv("MFW_DEBUG"))
        return 0;
    /* sections of libxdp's, which libxdp reads itself */
    if (strstr(fmt, "skipping unrecognized data section"))
        return 0;
    return vfprintf(stderr, fmt, ap);
}

static int libxdp_print(enum libxdp_print_level level, const char *fmt, va_list ap)
{
    if (level == LIBXDP_DEBUG && !getenv("MFW_DEBUG"))
        return 0;
    return vfprintf(stderr, fmt, ap);
}

/* A pinned stats map from a build with fewer stats ids cannot be reused
 * (libbpf refuses another max_entries), so it is removed and the load
 * pins a new one: the counters restart, the rules and links stay. The old
 * program keeps its own map until upgrade_links() replaces it. */
static void drop_old_stats(const char *root)
{
    struct bpf_map_info info = {};
    __u32 len = sizeof(info);
    char path[PATH_MAX];
    int fd;

    snprintf(path, sizeof(path), "%s/maps/stats", root);
    fd = bpf_obj_get(path);
    if (fd < 0)
        return;
    if (!bpf_map_get_info_by_fd(fd, &info, &len) && info.max_entries != MFW_STAT_MAX)
        unlink(path);
    close(fd);
}

int mfw_dp_open(struct mfw_dp *dp, const char *root, char *err, size_t errlen)
{
    char maps[PATH_MAX], links[PATH_MAX];

    memset(dp, 0, sizeof(*dp));
    dp->prog_fd = dp->rulesets_fd = dp->config_fd = dp->stats_fd = -1;
    if (strlen(root) >= sizeof(dp->root))
        return fail(err, errlen, "pin root too long");
    snprintf(dp->root, sizeof(dp->root), "%s", root);
    if (check_bpffs(root, err, errlen))
        return -1;

    snprintf(maps, sizeof(maps), "%s/maps", root);
    snprintf(links, sizeof(links), "%s/link", root);
    if (ensure_dir(maps) || ensure_dir(links))
        return fail(err, errlen, "create %s: %s", root, strerror(errno));

    drop_old_stats(dp->root);
    libbpf_set_print(libbpf_print);
    LIBBPF_OPTS(bpf_object_open_opts, opts, .pin_root_path = maps);
    dp->skel = mfw_bpf__open_opts(&opts);
    if (!dp->skel)
        return fail(err, errlen, "open BPF object: %s", strerror(errno));
    /* the TC entry, for the interfaces at TC; libxdp loads the XDP entry,
     * from an object of its own, for each interface in a dispatcher */
    bpf_program__set_autoload(dp->skel->progs.mfw_xdp, false);
    if (mfw_bpf__load(dp->skel)) {  /* reuses pinned maps, pins new ones */
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
    if (init_config(dp, err, errlen)) {
        mfw_dp_close(dp);
        return -1;
    }
    upgrade_links(dp);
    return 0;
}

void mfw_dp_close(struct mfw_dp *dp)
{
    mfw_bpf__destroy(dp->skel);  /* the pins keep maps and links alive */
    dp->skel = NULL;
}

int mfw_dp_attach(struct mfw_dp *dp, const char *ifname, char *err, size_t errlen)
{
    char path[PATH_MAX];
    int ifindex = if_nametoindex(ifname), fd, e;

    if (!ifindex)
        return fail(err, errlen, "%s: no such interface", ifname);
    if (mfw_dp_attached(dp, ifname))
        return 0;
    if (!dp->no_xdp) {
        char holder[BPF_OBJ_NAME_LEN];

        e = xdp_attach(dp->root, ifname, ifindex, holder, sizeof(holder));
        if (e == 0)
            return 0;
        if (e < 0)
            return fail(err, errlen, "%s: attach XDP: %s%s", ifname, strerror(-e),
                        e == -ENOTSUP ? " (libxdp needs bpffs at /sys/fs/bpf)" : "");
        fprintf(stderr, "mfwd: %s: %s holds the XDP hook without libxdp's "
                "dispatcher: filtering at TC ingress (degraded)\n", ifname, holder);
    }
    if (!dp->tcx) {
        e = -tc_attach(ifindex, dp->prog_fd);
        if (e)
            return fail(err, errlen, "%s: attach TC ingress: %s", ifname,
                        strerror(e));
        if (tc_pin(dp->root, ifname, dp->prog_fd)) {
            e = errno;
            tc_detach(ifindex);
            return fail(err, errlen, "%s: pin: %s", ifname, strerror(e));
        }
        return 0;
    }
    /* appended: a tc program attached before mini-fw runs first */
    fd = bpf_link_create(dp->prog_fd, ifindex, BPF_TCX_INGRESS, NULL);
    if (fd < 0)
        return fail(err, errlen, "%s: attach TC ingress: %s", ifname,
                    strerror(errno));
    link_path(dp->root, ifname, path, sizeof(path));
    if (bpf_obj_pin(fd, path)) {
        e = errno;
        close(fd);  /* last reference: detaches again */
        return fail(err, errlen, "%s: pin %s: %s", ifname, path, strerror(e));
    }
    close(fd);  /* the pin keeps the link alive */
    return 0;
}

void mfw_dp_detach(struct mfw_dp *dp, const char *ifname)
{
    __u32 ifindex = if_nametoindex(ifname);

    if (ifindex)
        bpf_map_delete_elem(dp->rulesets_fd, &ifindex);
    xdp_detach(dp->root, ifname);
    tc_off(dp->root, ifname);
}

int mfw_dp_install(struct mfw_dp *dp, __u32 ifindex, const struct mfw_ruleset *rs,
                   char *err, size_t errlen)
{
    __u32 zero = 0;
    int fd, e = 0;

    fd = bpf_map_create(BPF_MAP_TYPE_ARRAY, "mfw_ruleset", sizeof(__u32),
                        sizeof(*rs), 1, NULL);
    if (fd < 0)
        return fail(err, errlen, "create ruleset map: %s", strerror(errno));
    if (bpf_map_update_elem(fd, &zero, rs, BPF_ANY) ||
        bpf_map_update_elem(dp->rulesets_fd, &ifindex, &fd, BPF_ANY))
        e = errno;
    close(fd);  /* the outer map holds the inner map now */
    if (e)
        return fail(err, errlen, "install ruleset: %s", strerror(e));
    return 0;
}

void mfw_dp_prune(struct mfw_dp *dp, const __u32 *keep, int n)
{
    __u32 last, next;
    int kept = 0;

    while (bpf_map_get_next_key(dp->rulesets_fd, kept ? &last : NULL, &next) == 0) {
        int wanted = 0;

        for (int i = 0; i < n; i++)
            wanted |= keep[i] == next;
        if (!wanted && bpf_map_delete_elem(dp->rulesets_fd, &next) == 0)
            continue;  /* deleted: carry on after the last key kept */
        last = next;
        kept = 1;
    }
}

int mfw_dp_get_config(const struct mfw_dp *dp, struct mfw_config *cfg)
{
    __u32 k = 0;

    return bpf_map_lookup_elem(dp->config_fd, &k, cfg) ? -1 : 0;
}

int mfw_dp_set_config(struct mfw_dp *dp, int drop_ipv4_fragments, __u32 *generation)
{
    struct mfw_config cfg;
    __u32 k = 0;

    if (bpf_map_lookup_elem(dp->config_fd, &k, &cfg))
        return -1;
    cfg.drop_ipv4_fragments = !!drop_ipv4_fragments;
    *generation = ++cfg.generation;
    return bpf_map_update_elem(dp->config_fd, &k, &cfg, BPF_ANY) ? -1 : 0;
}

int mfw_dp_stats(const struct mfw_dp *dp, __u64 out[MFW_STAT_MAX])
{
    int ncpu = libbpf_num_possible_cpus();
    struct mfw_stat_value *vals;

    if (ncpu < 1)
        return -1;
    vals = calloc(ncpu, sizeof(*vals));
    if (!vals)
        return -1;
    for (__u32 id = 0; id < MFW_STAT_MAX; id++) {
        out[id] = 0;
        if (bpf_map_lookup_elem(dp->stats_fd, &id, vals) == 0)
            for (int c = 0; c < ncpu; c++)
                out[id] += vals[c].count;
    }
    free(vals);
    return 0;
}

static void rm_dir(const char *dir)
{
    char path[PATH_MAX];
    struct dirent *de;
    DIR *d = opendir(dir);

    if (!d)
        return;
    while ((de = readdir(d))) {
        if (de->d_name[0] == '.')
            continue;
        snprintf(path, sizeof(path), "%s/%s", dir, de->d_name);
        /* a link pin: the kernel detaches the program; a classic TC
         * filter stays until it is removed, a program in a dispatcher
         * until it is taken out */
        if (!strncmp(de->d_name, "tc_", 3) && if_nametoindex(de->d_name + 3))
            tc_detach(if_nametoindex(de->d_name + 3));
        if (!strncmp(de->d_name, "xdp_", 4) && if_nametoindex(de->d_name + 4))
            xdp_remove(if_nametoindex(de->d_name + 4), pinned_id(path));
        unlink(path);
    }
    closedir(d);
    rmdir(dir);
}

void mfw_dp_purge(const char *root)
{
    char dir[PATH_MAX];

    /* links first, so no interface is left running on deleted maps */
    snprintf(dir, sizeof(dir), "%s/link", root);
    rm_dir(dir);
    snprintf(dir, sizeof(dir), "%s/maps", root);
    rm_dir(dir);
    snprintf(dir, sizeof(dir), "%s/state", root);  /* left by mfw 0.2 */
    rm_dir(dir);
    rmdir(root);
}
