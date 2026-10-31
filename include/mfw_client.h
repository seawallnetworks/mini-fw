
/* SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause */

/*
 * mfw_client.h — talk to mfwd over its Unix socket. Part of libmfw.a, no
 * privileges needed beyond access to the socket.
 *
 * Each call opens one connection, sends one request and reads the reply.
 * There is no global state, so calls may come from several threads. The
 * library never raises SIGPIPE.
 */


#ifndef _MFW_CLIENT_H_INCLUDED_
#define _MFW_CLIENT_H_INCLUDED_


#include "mfw.h"

#include <stddef.h>


#define MFW_SOCKET       "/run/mfwd.sock"
#define MFW_TIMEOUT_MS   5000
#define MFW_REQUEST_MAX  (1024 * 1024)   /* bytes, APPLY block included */


/* Every call returns mfw_ok or one of these; mfw_strerror() names it. */
enum mfw_rc {
    mfw_ok           = 0,
    mfw_err_io       = -1,   /* can't reach mfwd, or no reply in time; errno */
    mfw_err_reply    = -2,   /* a reply mfwd should never send */
    mfw_err_badreq   = -3,   /* ERR badreq: mfwd couldn't parse the request */
    mfw_err_invalid  = -4,   /* ERR invalid: the policy was refused */
    mfw_err_kernel   = -5,   /* ERR kernel: a BPF or XDP operation failed */
    mfw_err_internal = -6,   /* ERR internal */
};


/*
 * NULL means the defaults: MFW_SOCKET, MFW_TIMEOUT_MS. timeout_ms bounds
 * each of connect, send and receive; 0 is the default.
 */
typedef struct {
    const char       *socket_path;
    int               timeout_ms;
} mfw_client_t;


/*
 * STATUS. generation is the last APPLY's, 0 if none since mfwd started.
 * degraded lists interfaces attached at TC ingress, not XDP, because
 * another program holds their XDP hook. flows is "sw_flowd" when "reply"
 * ACEs read its table, "none" without it.
 */
struct mfw_status {
    __u32             generation;
    int               drop_ipv4_fragments;
    char              attached[1024];   /* "eth0,eth1"; "" if none */
    char              missing[1024];    /* bound interfaces not there */
    char              degraded[1024];
    char              flows[16];
};


const char *mfw_strerror(int rc);

int mfw_ping(const mfw_client_t *c);

/*
 * Replace the whole policy (see mfw_policy.h). On mfw_ok, *generation is
 * the new generation and missing (if not NULL) lists bound interfaces that
 * do not exist, comma-separated. On a refusal, err holds mfwd's message,
 * e.g. "line 3: ...".
 */
int mfw_apply(const mfw_client_t *c, const char *policy, __u32 *generation,
    char *missing, size_t missing_len, char *err, size_t errlen);

int mfw_status(const mfw_client_t *c, struct mfw_status *st);

/* Counters summed over CPUs, indexed by enum mfw_stat_id. */
int mfw_stats(const mfw_client_t *c, __u64 counters[MFW_STAT_MAX]);
/* The name of a counter ("xdp_pass", ...), or NULL. */
const char *mfw_stat_name(int id);

/* The applied policy in canonical form; malloc'd, free() it. */
int mfw_show(const mfw_client_t *c, char **policy);

/*
 * Low level: send request (one line, or a block ending in "END\n") and
 * return the whole reply, malloc'd. err gets the message of an ERR reply.
 */
int mfw_request(const mfw_client_t *c, const char *request, char **reply,
    char *err, size_t errlen);


#endif /* _MFW_CLIENT_H_INCLUDED_ */
