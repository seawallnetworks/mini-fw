
/* SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause */

/*
 * mini-fw in libxdp's dispatcher: the normal case, attach/xdp_<if>. Each
 * interface gets its own copy of the XDP program, on the pinned maps.
 */


#include "dp_attach.h"
#include "mfw.skel.h"

#include <sw/bpffs.h>
#include <sw/netif.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <limits.h>
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <xdp/libxdp.h>


#define MFW_XDP_PROG  "mfw_xdp"


static int xdp_load(const char *root, const char *ifname, int ifindex,
    enum xdp_attach_mode mode, int flows_fd);


void
mfw_xdp_path(const char *root, const char *ifname, char *buf, size_t len)
{
    snprintf(buf, len, "%s/attach/xdp_%.*s", root, IF_NAMESIZE, ifname);
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

    if (!xdp_multiprog__is_legacy(mp)) {
        *mode = xdp_multiprog__attach_mode(mp);
        state = mfw_xdp_shared;

    } else {
        /*
         * A program on its own, or none: only a hardware-offloaded one,
         * and the driver hook is free.
         */
        main = xdp_multiprog__main_prog(mp);

        if (main != NULL) {
            snprintf(holder, len, "%s", xdp_program__name(main));
            state = mfw_xdp_held;

        } else {
            state = mfw_xdp_free;
        }
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
mfw_xdp_unload(int ifindex, __u32 id)
{
    int                    rc;
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

    rc = 0;

    if (p != NULL) {
        rc = xdp_program__detach(p, ifindex, xdp_multiprog__attach_mode(mp), 0);
        if (rc == 0) {
            rc = 1;     /* taken out */
        }
    }

    xdp_multiprog__close(mp);

    return rc;
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
 * Is the program pinned at attach/xdp_<ifname> still in ifname's
 * dispatcher? If not (the interface was deleted or re-created, or the
 * program was taken out), the stale pin is deleted and 0 returned. If
 * the interface can't be looked up, the pin stays, and counts.
 */
int
mfw_xdp_attached(const char *root, const char *ifname)
{
    int                    ifindex;
    __u32                  id;
    struct xdp_program    *p;
    struct xdp_multiprog  *mp;
    char                   path[PATH_MAX], err[256];

    mfw_xdp_path(root, ifname, path, sizeof(path));

    id = mfw_xdp_pinned_id(path);
    if (id == 0) {
        return 0;
    }

    ifindex = sw_netif_index(ifname, err, sizeof(err));
    if (ifindex < 0) {
        mfw_netif_unknown(err);
        return 1;
    }

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
 * this mode, and pin it as attach/xdp_<ifname>. libxdp joins the dispatcher
 * there, or makes one. The copy is a new BPF object that shares the
 * pinned maps, and binds sw_flowd's table, flows_fd, unless that is -1;
 * libxdp loads it as an extension of the dispatcher. Returns 0 or -errno.
 */
static int
xdp_load(const char *root, const char *ifname, int ifindex,
    enum xdp_attach_mode mode, int flows_fd)
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

    if (flows_fd >= 0 && bpf_map__reuse_fd(skel->maps.flows, flows_fd) != 0) {
        e = -errno;
        mfw_bpf__destroy(skel);
        return e;
    }

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
    if (e != 0) {
        goto done;
    }

    mfw_xdp_path(root, ifname, path, sizeof(path));
    unlink(path);

    if (bpf_obj_pin(xdp_program__fd(xp), path) != 0) {
        e = -errno;
        xdp_program__detach(xp, ifindex, mode, 0);
    }

done:

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
 * (-ENOTSUP if bpffs is not mounted, which libxdp needs). flows_fd is
 * xdp_load()'s.
 */
int
mfw_xdp_attach(const char *root, const char *ifname, int ifindex,
    int flows_fd, char *holder, size_t len)
{
    int                   e, i, state;
    enum xdp_attach_mode  mode;

    /*
     * libxdp keeps its dispatchers' state there: without it, it attaches
     * a program alone, and nothing can join the hook after it
     */
    if (!sw_bpffs_mounted(sw_bpffs_libxdp_dir())) {
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
    for (i = 0; i < 10 && mfw_xdp_unload(ifindex, 0) > 0; i++) { /* void */ }

    e = xdp_load(root, ifname, ifindex, mode, flows_fd);

    /*
     * A new dispatcher was tried in native mode: if the driver refused,
     * try skb mode. A dispatcher that was there keeps its own mode.
     */
    if (e != 0
        && state == mfw_xdp_free
        && e != -EBUSY
        && e != -EEXIST)
    {
        e = xdp_load(root, ifname, ifindex, XDP_MODE_SKB, flows_fd);
    }

    /* another program took the hook after mfw_xdp_state() looked */
    if (e == -EBUSY || e == -EEXIST) {
        snprintf(holder, len, "another program");
        return 1;
    }

    return e;
}


/*
 * Leave ifname's dispatcher, if mini-fw is in it. If ifname can't be
 * looked up, nothing changes: unpinning without the unload would leave
 * the program in the dispatcher, unknown to mfwd.
 */
void
mfw_xdp_detach(const char *root, const char *ifname)
{
    int    ifindex;
    __u32  id;
    char   path[PATH_MAX], err[256];

    ifindex = sw_netif_index(ifname, err, sizeof(err));
    if (ifindex < 0) {
        mfw_netif_unknown(err);
        return;
    }

    mfw_xdp_path(root, ifname, path, sizeof(path));
    id = mfw_xdp_pinned_id(path);

    if (id != 0 && ifindex != 0) {
        mfw_xdp_unload(ifindex, id);
    }

    unlink(path);
}
