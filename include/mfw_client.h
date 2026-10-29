/* SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause */
/*
 * mfw_client.h — talk to mfwd over its Unix socket. Part of libmfw.a, no
 * privileges needed beyond access to the socket.
 *
 * Each call opens one connection, sends one request and reads the reply.
 * There is no global state, so calls may come from several threads. The
 * library never raises SIGPIPE.
 */
#ifndef MFW_CLIENT_H
#define MFW_CLIENT_H

#include <stddef.h>
#include "mfw.h"

#define MFW_SOCKET          "/run/mfwd.sock"
#define MFW_TIMEOUT_MS      5000
#define MFW_REQUEST_MAX     (1024 * 1024)   /* bytes, APPLY block included */

/* Every call returns mfw_ok or one of these; mfw_strerror() names it. */
enum mfw_rc {
    mfw_ok           = 0,
    mfw_err_io       = -1,   /* cannot reach mfwd, or no answer in time; see errno */
    mfw_err_reply    = -2,   /* a reply mfwd should never send */
    mfw_err_badreq   = -3,   /* ERR badreq: mfwd did not understand the request */
    mfw_err_invalid  = -4,   /* ERR invalid: the policy was refused */
    mfw_err_kernel   = -5,   /* ERR kernel: a BPF or XDP operation failed */
    mfw_err_internal = -6,   /* ERR internal */
};

/* NULL means the defaults: MFW_SOCKET, MFW_TIMEOUT_MS. */
typedef struct {
    const char *socket_path;
    int         timeout_ms;    /* each of connect, send, receive; 0 = default */
} mfw_client_t;

struct mfw_status {
    __u32 generation;           /* of the last APPLY; 0 = none since boot */
    int   drop_ipv4_fragments;
    char  attached[1024];       /* "eth0,eth1"; "" if none */
    char  missing[1024];        /* bound interfaces that do not exist */
    char  degraded[1024];       /* attached at TC ingress, not XDP: another
                                 * program holds the XDP hook */
    char  flows[16];            /* "sw_flowd": "reply" ACEs read its table;
                                 * "none" without it */
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

#endif /* MFW_CLIENT_H */
