
/* SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause */

/*
 * Between dataplane.c and its two ways of attaching: dp_xdp.c (libxdp's
 * dispatcher) and dp_tc.c (tcx or classic TC). Pins are under root.
 */


#ifndef _MFW_DP_ATTACH_H_INCLUDED_
#define _MFW_DP_ATTACH_H_INCLUDED_


#include <linux/types.h>
#include <stddef.h>
#include <xdp/libxdp.h>


/* What holds an interface's XDP hook. */
typedef enum {
    mfw_xdp_free = 0,    /* nothing */
    mfw_xdp_shared,      /* libxdp's dispatcher */
    mfw_xdp_held         /* a program that is not a dispatcher */
} mfw_xdp_hook_e;


void mfw_xdp_path(const char *root, const char *ifname, char *buf, size_t len);
int mfw_xdp_state(int ifindex, enum xdp_attach_mode *mode, char *holder,
    size_t len);
int mfw_xdp_unload(int ifindex, __u32 id);
__u32 mfw_xdp_pinned_id(const char *path);
int mfw_xdp_attached(const char *root, const char *ifname);
int mfw_xdp_attach(const char *root, const char *ifname, int ifindex,
    int flows_fd, char *holder, size_t len);
void mfw_xdp_detach(const char *root, const char *ifname);

int mfw_tc_attach(int ifindex, int prog_fd);
void mfw_tc_detach(int ifindex);
int mfw_tc_attached(const char *root, const char *ifname);
int mfw_tc_pin(const char *root, const char *ifname, int prog_fd);
int mfw_tcx_open(const char *root, const char *ifname);
int mfw_tcx_attach(const char *root, const char *ifname, int ifindex,
    int prog_fd, char *err, size_t errlen);
void mfw_tc_off(const char *root, const char *ifname);

/*
 * Logs, once, that an interface couldn't be looked up (sw_netif_index()
 * returned -1, with err): glibc's if_nametoindex() needs AF_UNIX, and
 * every interface fails alike until the unit allows it.
 */
void mfw_netif_unknown(const char *err);


#endif /* _MFW_DP_ATTACH_H_INCLUDED_ */
