
/* SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause */

/*
 * Client side of the mfwd protocol. Part of libmfw.a.
 *
 * One request per connection. mfwd sends its whole reply and closes, so a
 * reply is read up to EOF: "OK [fields]\n", "ERR <code> <message>\n", or
 * for SHOW "OK <n>\n" followed by n lines.
 *
 * The connection and the sends are libsw's (Seawall proposal 0011): what
 * links libmfw.a links libsw.a after it.
 */


#include "mfw_client.h"

#include <sw/sock.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>


#define MFW_REPLY_MAX  (MFW_REQUEST_MAX + 4096)


/* An ERR reply's code, and the rc it maps to. */
typedef struct {
    const char  *code;
    int          rc;
} mfw_err_code_t;


static int recv_all(int fd, char **out);
static int parse_err(const char *reply, char *err, size_t errlen);
static int simple(const mfw_client_t *c, const char *req, char **reply,
    char **fields);
static int field(const char *fields, const char *key, char *out,
    size_t len);


static const char *const  mfw_stat_names[MFW_STAT_MAX] = {
    [MFW_STAT_PASS]              = "xdp_pass",
    [MFW_STAT_DROP]              = "xdp_drop",
    [MFW_STAT_STD_DENY]          = "std_deny",
    [MFW_STAT_STD_PERMIT]        = "std_permit",
    [MFW_STAT_EXT_PERMIT]        = "ext_permit",
    [MFW_STAT_EXT_DENY]          = "ext_deny",
    [MFW_STAT_EXT_IMPLICIT_DENY] = "ext_implicit_deny",
    [MFW_STAT_PARSE_ERR]         = "parse_err",
    [MFW_STAT_FRAG_DROP]         = "frag_drop",
    [MFW_STAT_NON_IPV4]          = "non_ipv4",
    [MFW_STAT_TCP_FRAG_OFF1]     = "tcp_frag_off1",
};

static const mfw_err_code_t  mfw_err_codes[] = {
    { "badreq",   mfw_err_badreq },
    { "invalid",  mfw_err_invalid },
    { "kernel",   mfw_err_kernel },
    { "internal", mfw_err_internal },
};


const char *
mfw_stat_name(int id)
{
    return id >= 0 && id < MFW_STAT_MAX ? mfw_stat_names[id] : NULL;
}


const char *
mfw_strerror(int rc)
{
    switch (rc) {
    case mfw_ok:
        return "ok";

    case mfw_err_io:
        return "cannot reach mfwd";

    case mfw_err_reply:
        return "bad reply from mfwd";

    case mfw_err_badreq:
        return "mfwd did not understand the request";

    case mfw_err_invalid:
        return "invalid policy";

    case mfw_err_kernel:
        return "kernel error";

    case mfw_err_internal:
        return "mfwd internal error";

    default:
        return "unknown error";
    }
}


/* Reads to EOF into a malloc'd, NUL-terminated buffer. */
static int
recv_all(int fd, char **out)
{
    char     *buf, *p;
    size_t    off, size;
    ssize_t   n;

    size = 4096;
    off = 0;

    buf = malloc(size);
    if (buf == NULL) {
        return -1;
    }

    for ( ;; ) {
        if (off + 1 == size) {
            if (size >= MFW_REPLY_MAX) {
                errno = EMSGSIZE;
                goto failed;
            }

            size *= 2;

            p = realloc(buf, size);
            if (p == NULL) {
                goto failed;
            }

            buf = p;
        }

        n = recv(fd, buf + off, size - 1 - off, 0);

        if (n < 0 && errno == EINTR) {
            continue;
        }

        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                errno = ETIMEDOUT;
            }

            goto failed;
        }

        if (n == 0) {
            break;
        }

        off += n;
    }

    buf[off] = '\0';
    *out = buf;

    return 0;

failed:

    free(buf);

    return -1;
}


/* "ERR <code> <message>" → rc, message into err. */
static int
parse_err(const char *reply, char *err, size_t errlen)
{
    size_t       i, n;
    const char  *code, *msg;

    code = reply + 4;
    msg = strchr(code, ' ');
    n = msg != NULL ? (size_t) (msg - code) : strcspn(code, "\n");

    if (err != NULL && errlen > 0) {
        snprintf(err, errlen, "%s", msg != NULL ? msg + 1 : "");
        err[strcspn(err, "\n")] = '\0';
    }

    for (i = 0; i < sizeof(mfw_err_codes) / sizeof(mfw_err_codes[0]); i++) {
        if (strlen(mfw_err_codes[i].code) == n
            && strncmp(code, mfw_err_codes[i].code, n) == 0)
        {
            return mfw_err_codes[i].rc;
        }
    }

    return mfw_err_reply;
}


int
mfw_request(const mfw_client_t *c, const char *request, char **reply,
    char *err, size_t errlen)
{
    int          fd, rc, saved, timeout;
    char        *buf;
    size_t       len;
    const char  *path;

    *reply = NULL;

    if (err != NULL && errlen > 0) {
        err[0] = '\0';
    }

    len = strlen(request);

    if (len == 0 || len > MFW_REQUEST_MAX || request[len - 1] != '\n') {
        return mfw_err_badreq;
    }

    path = c != NULL && c->socket_path != NULL ? c->socket_path : MFW_SOCKET;
    timeout = c != NULL && c->timeout_ms > 0 ? c->timeout_ms : MFW_TIMEOUT_MS;

    /* the timeout bounds connect() too: an mfwd that never accepts */
    fd = sw_sock_connect(path, timeout, NULL, 0);
    if (fd < 0) {
        return mfw_err_io;
    }

    buf = NULL;

    if (sw_sock_send_all(fd, request, len) != 0
        || shutdown(fd, SHUT_WR) != 0
        || recv_all(fd, &buf) != 0)
    {
        saved = errno;
        close(fd);
        errno = saved;
        return mfw_err_io;
    }

    close(fd);

    if (strncmp(buf, "OK", 2) == 0 && (buf[2] == '\n' || buf[2] == ' ')) {
        *reply = buf;
        return mfw_ok;
    }

    if (strncmp(buf, "ERR ", 4) == 0) {
        rc = parse_err(buf, err, errlen);
        free(buf);
        return rc;
    }

    free(buf);

    return mfw_err_reply;
}


/*
 * A one-line request whose reply is a single line; *fields points just
 * after "OK" (at "" or at the fields), inside *reply.
 */
static int
simple(const mfw_client_t *c, const char *req, char **reply, char **fields)
{
    int    rc;
    char  *nl;

    rc = mfw_request(c, req, reply, NULL, 0);
    if (rc != 0) {
        return rc;
    }

    nl = strchr(*reply, '\n');

    if (nl == NULL || nl[1] != '\0') {
        free(*reply);
        *reply = NULL;
        return mfw_err_reply;
    }

    *nl = '\0';
    *fields = *reply + 2 + ((*reply)[2] == ' ');

    return mfw_ok;
}


int
mfw_ping(const mfw_client_t *c)
{
    int    rc;
    char  *fields, *reply;

    rc = simple(c, "PING\n", &reply, &fields);

    if (rc == mfw_ok && *fields != '\0') {
        rc = mfw_err_reply;
    }

    free(reply);

    return rc;
}


int
mfw_apply(const mfw_client_t *c, const char *policy, __u32 *generation,
    char *missing, size_t missing_len, char *err, size_t errlen)
{
    int             rc;
    char           *end, *m, *nl, *reply, *req;
    size_t          len;
    const char     *p;
    unsigned long   gen;

    if (missing != NULL && missing_len > 0) {
        missing[0] = '\0';
    }

    /* "END" alone on a line would end the block early */
    for (p = policy; (p = strstr(p, "END")) != NULL; p += 3) {
        if ((p == policy || p[-1] == '\n')
            && (p[3] == '\n' || p[3] == '\0'))
        {
            if (err != NULL && errlen > 0) {
                snprintf(err, errlen, "the policy contains a line \"END\"");
            }

            return mfw_err_badreq;
        }
    }

    len = strlen(policy);

    req = malloc(len + 16);
    if (req == NULL) {
        return mfw_err_io;
    }

    snprintf(req, len + 16, "APPLY\n%s%sEND\n", policy,
             len > 0 && policy[len - 1] != '\n' ? "\n" : "");

    rc = mfw_request(c, req, &reply, err, errlen);
    free(req);

    if (rc != 0) {
        return rc;
    }

    /* OK <generation>[ missing=a,b] */
    nl = strchr(reply, '\n');
    if (nl != NULL) {
        *nl = '\0';
    }

    errno = 0;
    gen = strtoul(reply + 3, &end, 10);

    if (nl == NULL || reply[2] != ' ' || end == reply + 3 || errno != 0
        || gen > 0xffffffffUL
        || (*end != '\0' && strncmp(end, " missing=", 9) != 0))
    {
        free(reply);
        return mfw_err_reply;
    }

    if (generation != NULL) {
        *generation = gen;
    }

    m = *end != '\0' ? end + 9 : "";

    if (missing != NULL && missing_len > 0) {
        snprintf(missing, missing_len, "%s", m);
    }

    free(reply);

    return mfw_ok;
}


/* "key=value key=value" → the value for key, copied into out. */
static int
field(const char *fields, const char *key, char *out, size_t len)
{
    size_t       klen, n;
    const char  *p;

    klen = strlen(key);
    p = fields;

    while (p != NULL && *p != '\0') {
        if (strncmp(p, key, klen) == 0 && p[klen] == '=') {
            n = strcspn(p + klen + 1, " ");

            if (n >= len) {
                return -1;
            }

            memcpy(out, p + klen + 1, n);
            out[n] = '\0';

            return 0;
        }

        p = strchr(p, ' ');

        if (p != NULL) {
            p++;
        }
    }

    return -1;
}


int
mfw_status(const mfw_client_t *c, struct mfw_status *st)
{
    int    rc;
    char  *fields, *reply;
    char   frag[4], gen[16];

    rc = simple(c, "STATUS\n", &reply, &fields);
    if (rc != 0) {
        return rc;
    }

    memset(st, 0, sizeof(*st));

    /*
     * OK generation=N drop-ipv4-fragments=0|1 attached=a,b missing=c
     * degraded=d flows=sw_flowd|none
     */
    if (field(fields, "generation", gen, sizeof(gen)) != 0
        || field(fields, "drop-ipv4-fragments", frag, sizeof(frag)) != 0
        || field(fields, "attached", st->attached, sizeof(st->attached)) != 0
        || field(fields, "missing", st->missing, sizeof(st->missing)) != 0
        || field(fields, "degraded", st->degraded, sizeof(st->degraded)) != 0
        || field(fields, "flows", st->flows, sizeof(st->flows)) != 0)
    {
        rc = mfw_err_reply;

    } else {
        st->generation = strtoul(gen, NULL, 10);
        st->drop_ipv4_fragments = frag[0] == '1';
    }

    free(reply);

    return rc;
}


int
mfw_stats(const mfw_client_t *c, __u64 counters[MFW_STAT_MAX])
{
    int    i, rc;
    char  *fields, *reply;
    char   v[24];

    rc = simple(c, "STATS\n", &reply, &fields);
    if (rc != 0) {
        return rc;
    }

    for (i = 0; i < MFW_STAT_MAX; i++) {
        if (field(fields, mfw_stat_names[i], v, sizeof(v)) != 0) {
            rc = mfw_err_reply;
            break;
        }

        counters[i] = strtoull(v, NULL, 10);
    }

    free(reply);

    return rc;
}


int
mfw_show(const mfw_client_t *c, char **policy)
{
    int             rc;
    char           *body, *end, *reply;
    const char     *p;
    unsigned long   lines, n;

    *policy = NULL;

    rc = mfw_request(c, "SHOW\n", &reply, NULL, 0);
    if (rc != 0) {
        return rc;
    }

    /* OK <n>\n then n lines */
    n = strtoul(reply + 3, &end, 10);

    if (reply[2] != ' ' || end == reply + 3 || *end != '\n') {
        free(reply);
        return mfw_err_reply;
    }

    body = end + 1;
    lines = 0;

    for (p = body; *p != '\0'; p++) {
        lines += *p == '\n';
    }

    if (lines != n || (*body != '\0' && body[strlen(body) - 1] != '\n')) {
        free(reply);
        return mfw_err_reply;
    }

    memmove(reply, body, strlen(body) + 1);
    *policy = reply;

    return mfw_ok;
}
