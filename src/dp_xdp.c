
/* SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause */

/*
 * mini-fw in libxdp's dispatcher: the normal case, link/xdp_<if>. Each
 * interface gets its own copy of the XDP program, on the pinned maps.
 */


#include "dp_link.h"
#include "mfw.skel.h"

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <limits.h>
#include <linux/magic.h>
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/vfs.h>
#include <unistd.h>
#include <xdp/libxdp.h>


#define MFW_XDP_PROG  "mfw_xdp"


static int mfw_xdp_bpffs_mounted(void);


void
mfw_xdp_path(const char *root, const char *ifname, char *buf, size_t len)
{
    snprintf(buf, len, "%s/link/xdp_%.*s", root, IF_NAMESIZE, ifname);
}


/*
 * Is bpffs mounted where libxdp looks for it? libxdp keeps its
 * dispatchers' state there. Without it, libxdp attaches a program alone,
 * without a dispatcher, and no other program can join the hook after it.
 */
static int
mfw_xdp_bpffs_mounted(void)
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
int
mfw_xdp_state(int ifindex, enum xdp_attach_mode *mode, char *holder, size_t len)
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

    /* what the hook holds: the dispatcher, or a program on its own */
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
int
mfw_xdp_remove(int ifindex, __u32 id)
{
    int                    e;
    struct xdp_program    *p;
    struct xdp_multiprog  *mp;

    mp = xdp_multiprog__get_from_ifindex(ifindex);
    if (libxdp_get_error(mp) != 0) {
        return 0;
    }

    p = NULL;

    /* NULL at once for a program attached without a dispatcher */
    while ((p = xdp_multiprog__next_prog(p, mp)) != NULL) {
        if (id != 0 ? xdp_program__id(p) == id
                    : strcmp(xdp_program__name(p), MFW_XDP_PROG) == 0)
        {
            break;
        }
    }

    e = 0;

    if (p != NULL) {
        e = xdp_program__detach(p, ifindex, xdp_multiprog__attach_mode(mp), 0);
    }

    xdp_multiprog__close(mp);

    if (e != 0) {
        return e;
    }

    return p != NULL;
}


/* The id of the program pinned at path; 0 if none. */
__u32
mfw_xdp_pinned_id(const char *path)
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
int
mfw_xdp_attached(const char *root, const char *ifname)
{
    int                    ifindex;
    __u32                  id;
    struct xdp_program    *p;
    struct xdp_multiprog  *mp;
    char                   path[PATH_MAX];

    mfw_xdp_path(root, ifname, path, sizeof(path));

    id = mfw_xdp_pinned_id(path);
    if (id == 0) {
        return 0;
    }

    ifindex = if_nametoindex(ifname);
    if (ifindex == 0) {
        goto not_found;  /* the interface is gone */
    }

    mp = xdp_multiprog__get_from_ifindex(ifindex);
    if (libxdp_get_error(mp) != 0) {
        goto not_found;  /* nothing on its XDP hook */
    }

    p = NULL;

    while ((p = xdp_multiprog__next_prog(p, mp)) != NULL) {
        if (xdp_program__id(p) == id) {
            break;
        }
    }

    xdp_multiprog__close(mp);

    if (p != NULL) {
        return 1;
    }

not_found:

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
int
mfw_xdp_load(const char *root, const char *ifname, int ifindex,
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
        mfw_xdp_path(root, ifname, path, sizeof(path));
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
int
mfw_xdp_attach(const char *root, const char *ifname, int ifindex,
    char *holder, size_t len)
{
    int                   e, i, state;
    enum xdp_attach_mode  mode;

    if (!mfw_xdp_bpffs_mounted()) {
        return -ENOTSUP;
    }

    mode = XDP_MODE_NATIVE;

    state = mfw_xdp_state(ifindex, &mode, holder, len);
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
    for (i = 0; i < 10 && mfw_xdp_remove(ifindex, 0) > 0; i++) { /* void */ }

    e = mfw_xdp_load(root, ifname, ifindex, mode);

    /*
     * A new dispatcher was tried in native mode: if the driver refused,
     * try skb mode. A dispatcher that was there keeps its own mode.
     */
    if (e != 0
        && state == mfw_xdp_free
        && e != -EBUSY
        && e != -EEXIST)
    {
        e = mfw_xdp_load(root, ifname, ifindex, XDP_MODE_SKB);
    }

    /* another program took the hook after mfw_xdp_state() looked */
    if (e == -EBUSY || e == -EEXIST) {
        snprintf(holder, len, "another program");
        return 1;
    }

    return e;
}


/* Leave ifname's dispatcher, if mini-fw is in it. */
void
mfw_xdp_detach(const char *root, const char *ifname)
{
    int    ifindex;
    __u32  id;
    char   path[PATH_MAX];

    mfw_xdp_path(root, ifname, path, sizeof(path));
    id = mfw_xdp_pinned_id(path);
    ifindex = if_nametoindex(ifname);

    if (id != 0 && ifindex != 0) {
        mfw_xdp_remove(ifindex, id);
    }

    unlink(path);
}
