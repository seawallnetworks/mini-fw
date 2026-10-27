
/* SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause */

/*
 * mini-fw at TC ingress, when a program that is not a dispatcher holds
 * the XDP hook (degraded): a tcx link, link/tcx_<if>, or on a kernel
 * before 6.6 a classic TC filter, marked by link/tc_<if>.
 */


#include "dp_link.h"
#include "util.h"

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


static void tcx_path(const char *root, const char *ifname, char *buf,
    size_t len);
static void tc_path(const char *root, const char *ifname, char *buf,
    size_t len);
static __u32 tcx_link_ifindex(int fd);


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


/*
 * Attach prog_fd as mini-fw's classic TC filter on ifindex's ingress,
 * adding the clsact qdisc if there is none. A mini-fw filter already
 * there is replaced in one netlink request, so the interface is never
 * left without one. Returns 0 or -errno.
 */
int
mfw_tc_attach(int ifindex, int prog_fd)
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
void
mfw_tc_detach(int ifindex)
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
int
mfw_tc_attached(const char *root, const char *ifname)
{
    LIBBPF_OPTS(bpf_tc_hook, hook, .attach_point = BPF_TC_INGRESS);
    LIBBPF_OPTS(bpf_tc_opts, opts, .handle = MFW_TC_HANDLE,
                .priority = MFW_TC_PRIORITY);
    int   ifindex;
    char  path[PATH_MAX], err[256];

    tc_path(root, ifname, path, sizeof(path));

    if (access(path, F_OK) != 0) {
        return 0;
    }

    /* can't tell: the pin stays, and counts */
    ifindex = sw_netif_index(ifname, err, sizeof(err));
    if (ifindex < 0) {
        mfw_netif_unknown(err);
        return 1;
    }

    hook.ifindex = ifindex;

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
int
mfw_tc_pin(const char *root, const char *ifname, int prog_fd)
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
 * was deleted or re-created) is deleted. If ifname can't be looked up,
 * the link is taken as still its.
 */
int
mfw_tcx_open(const char *root, const char *ifname)
{
    int    fd, now;
    char   path[PATH_MAX], err[256];

    tcx_path(root, ifname, path, sizeof(path));

    fd = bpf_obj_get(path);
    if (fd < 0) {
        return -1;
    }

    now = sw_netif_index(ifname, err, sizeof(err));
    if (now < 0) {
        mfw_netif_unknown(err);
        return fd;
    }

    if (now == 0 || tcx_link_ifindex(fd) != (__u32) now) {
        close(fd);
        unlink(path);
        return -1;
    }

    return fd;
}


/*
 * Attach prog_fd to ifindex's TC ingress with a tcx link, pinned as
 * link/tcx_<ifname>. The link goes after the interface's other tcx
 * programs, so those run first. Returns 0, or -1 with a message in err.
 */
int
mfw_tcx_attach(const char *root, const char *ifname, int ifindex,
    int prog_fd, char *err, size_t errlen)
{
    int   e, fd;
    char  path[PATH_MAX];

    fd = bpf_link_create(prog_fd, ifindex, BPF_TCX_INGRESS, NULL);
    if (fd < 0) {
        return mfw_fail(err, errlen, "%s: attach TC ingress: %s", ifname,
                        strerror(errno));
    }

    tcx_path(root, ifname, path, sizeof(path));

    if (bpf_obj_pin(fd, path) != 0) {
        e = errno;
        close(fd);  /* the last reference: the link detaches */
        return mfw_fail(err, errlen, "%s: pin %s: %s", ifname, path,
                        strerror(e));
    }

    close(fd);  /* the pin keeps the link alive */

    return 0;
}


/*
 * Take ifname off TC: delete its tcx link pin, or remove its classic TC
 * filter and pin, whichever it has. A classic filter on an interface that
 * can't be looked up keeps its pin: without it, mfwd wouldn't know the
 * filter is there.
 */
void
mfw_tc_off(const char *root, const char *ifname)
{
    int   ifindex;
    char  path[PATH_MAX], err[256];

    tcx_path(root, ifname, path, sizeof(path));
    /* the pin is the link's last reference: the kernel detaches it */
    unlink(path);

    ifindex = sw_netif_index(ifname, err, sizeof(err));
    if (ifindex < 0) {
        mfw_netif_unknown(err);
        return;
    }

    tc_path(root, ifname, path, sizeof(path));

    if (unlink(path) == 0 && ifindex != 0) {
        mfw_tc_detach(ifindex);
    }
}
