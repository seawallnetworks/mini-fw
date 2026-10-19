// SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
/* Client side of the mfwd protocol. Part of libmfw.a.
 *
 * One request per connection. mfwd sends its whole reply and closes, so a
 * reply is read up to EOF: "OK [fields]\n", "ERR <code> <message>\n", or
 * for SHOW "OK <n>\n" followed by n lines. */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>
#include <unistd.h>

#include "mfw_client.h"

#define REPLY_MAX  (MFW_REQUEST_MAX + 4096)

static const char *const stat_names[MFW_STAT_MAX] = {
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

const char *mfw_stat_name(int id)
{
    return id >= 0 && id < MFW_STAT_MAX ? stat_names[id] : NULL;
}

const char *mfw_strerror(int rc)
{
    switch (rc) {
    case mfw_ok:           return "ok";
    case mfw_err_io:       return "cannot reach mfwd";
    case mfw_err_reply:    return "bad reply from mfwd";
    case mfw_err_badreq:   return "mfwd did not understand the request";
    case mfw_err_invalid:  return "invalid policy";
    case mfw_err_kernel:   return "kernel error";
    case mfw_err_internal: return "mfwd internal error";
    default:               return "unknown error";
    }
}

static int send_all(int fd, const char *p, size_t len)
{
    while (len > 0) {
        ssize_t n = send(fd, p, len, MSG_NOSIGNAL);

        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
            return -1;
        p += n;
        len -= n;
    }
    return 0;
}

/* Reads to EOF into a malloc'd, NUL-terminated buffer. */
static int recv_all(int fd, char **out)
{
    size_t size = 4096, off = 0;
    char *buf = malloc(size), *p;

    if (!buf)
        return -1;
    for (;;) {
        ssize_t n;

        if (off + 1 == size) {
            if (size >= REPLY_MAX) {
                errno = EMSGSIZE;
                goto fail;
            }
            size *= 2;
            p = realloc(buf, size);
            if (!p)
                goto fail;
            buf = p;
        }
        n = recv(fd, buf + off, size - 1 - off, 0);
        if (n < 0 && errno == EINTR)
            continue;
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                errno = ETIMEDOUT;
            goto fail;
        }
        if (n == 0)
            break;
        off += n;
    }
    buf[off] = '\0';
    *out = buf;
    return 0;
fail:
    free(buf);
    return -1;
}

/* "ERR <code> <message>" → rc, message into err. */
static int parse_err(const char *reply, char *err, size_t errlen)
{
    static const struct { const char *code; int rc; } codes[] = {
        { "badreq",   mfw_err_badreq },
        { "invalid",  mfw_err_invalid },
        { "kernel",   mfw_err_kernel },
        { "internal", mfw_err_internal },
    };
    const char *code = reply + 4, *msg;
    size_t n;

    msg = strchr(code, ' ');
    n = msg ? (size_t)(msg - code) : strcspn(code, "\n");
    if (err && errlen) {
        snprintf(err, errlen, "%s", msg ? msg + 1 : "");
        err[strcspn(err, "\n")] = '\0';
    }
    for (size_t i = 0; i < sizeof(codes) / sizeof(codes[0]); i++)
        if (strlen(codes[i].code) == n && !strncmp(code, codes[i].code, n))
            return codes[i].rc;
    return mfw_err_reply;
}

int mfw_request(const mfw_client_t *c, const char *request, char **reply,
                char *err, size_t errlen)
{
    const char *path = c && c->socket_path ? c->socket_path : MFW_SOCKET;
    int timeout = c && c->timeout_ms > 0 ? c->timeout_ms : MFW_TIMEOUT_MS;
    struct sockaddr_un addr = { .sun_family = AF_UNIX };
    struct timeval tv = { timeout / 1000, (timeout % 1000) * 1000 };
    size_t len = strlen(request);
    int fd, saved;
    char *buf = NULL;

    *reply = NULL;
    if (err && errlen)
        err[0] = '\0';
    if (len == 0 || len > MFW_REQUEST_MAX || request[len - 1] != '\n')
        return mfw_err_badreq;
    if (strlen(path) >= sizeof(addr.sun_path)) {
        errno = ENAMETOOLONG;
        return mfw_err_io;
    }
    strcpy(addr.sun_path, path);

    fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0)
        return mfw_err_io;
    /* on Unix sockets the send timeout also bounds connect() */
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) ||
        send_all(fd, request, len) || shutdown(fd, SHUT_WR) ||
        recv_all(fd, &buf)) {
        saved = errno;
        close(fd);
        errno = saved;
        return mfw_err_io;
    }
    close(fd);

    if (!strncmp(buf, "OK", 2) && (buf[2] == '\n' || buf[2] == ' ')) {
        *reply = buf;
        return mfw_ok;
    }
    if (!strncmp(buf, "ERR ", 4)) {
        int rc = parse_err(buf, err, errlen);

        free(buf);
        return rc;
    }
    free(buf);
    return mfw_err_reply;
}

/* A one-line request whose reply is a single line; *fields points just
 * after "OK" (at "" or at the fields), inside *reply. */
static int simple(const mfw_client_t *c, const char *req, char **reply,
                  char **fields)
{
    char *nl;
    int rc = mfw_request(c, req, reply, NULL, 0);

    if (rc)
        return rc;
    nl = strchr(*reply, '\n');
    if (!nl || nl[1] != '\0') {
        free(*reply);
        *reply = NULL;
        return mfw_err_reply;
    }
    *nl = '\0';
    *fields = *reply + 2 + ((*reply)[2] == ' ');
    return mfw_ok;
}

int mfw_ping(const mfw_client_t *c)
{
    char *reply, *fields;
    int rc = simple(c, "PING\n", &reply, &fields);

    if (rc == mfw_ok && *fields)
        rc = mfw_err_reply;
    free(reply);
    return rc;
}

int mfw_apply(const mfw_client_t *c, const char *policy, __u32 *generation,
              char *missing, size_t missing_len, char *err, size_t errlen)
{
    size_t len = strlen(policy);
    char *req, *reply, *nl, *end, *m;
    unsigned long gen;
    int rc;

    if (missing && missing_len)
        missing[0] = '\0';
    /* "END" alone on a line would end the block early */
    for (const char *p = policy; (p = strstr(p, "END")); p += 3)
        if ((p == policy || p[-1] == '\n') && (p[3] == '\n' || p[3] == '\0')) {
            if (err && errlen)
                snprintf(err, errlen, "the policy contains a line \"END\"");
            return mfw_err_badreq;
        }
    req = malloc(len + 16);
    if (!req)
        return mfw_err_io;
    snprintf(req, len + 16, "APPLY\n%s%sEND\n", policy,
             len && policy[len - 1] != '\n' ? "\n" : "");
    rc = mfw_request(c, req, &reply, err, errlen);
    free(req);
    if (rc)
        return rc;

    /* OK <generation>[ missing=a,b] */
    nl = strchr(reply, '\n');
    if (nl)
        *nl = '\0';
    errno = 0;
    gen = strtoul(reply + 3, &end, 10);
    if (!nl || reply[2] != ' ' || end == reply + 3 || errno || gen > 0xffffffffUL ||
        (*end && strncmp(end, " missing=", 9))) {
        free(reply);
        return mfw_err_reply;
    }
    if (generation)
        *generation = gen;
    m = *end ? end + 9 : "";
    if (missing && missing_len)
        snprintf(missing, missing_len, "%s", m);
    free(reply);
    return mfw_ok;
}

/* "key=value key=value" → the value for key, copied into out. */
static int field(const char *fields, const char *key, char *out, size_t len)
{
    size_t klen = strlen(key);

    for (const char *p = fields; p && *p; p = strchr(p, ' '), p = p ? p + 1 : NULL) {
        if (!strncmp(p, key, klen) && p[klen] == '=') {
            size_t n = strcspn(p + klen + 1, " ");

            if (n >= len)
                return -1;
            memcpy(out, p + klen + 1, n);
            out[n] = '\0';
            return 0;
        }
    }
    return -1;
}

int mfw_status(const mfw_client_t *c, struct mfw_status *st)
{
    char *reply, *fields, gen[16], frag[4];
    int rc = simple(c, "STATUS\n", &reply, &fields);

    if (rc)
        return rc;
    memset(st, 0, sizeof(*st));
    /* OK generation=N drop-ipv4-fragments=0|1 attached=a,b missing=c */
    if (field(fields, "generation", gen, sizeof(gen)) ||
        field(fields, "drop-ipv4-fragments", frag, sizeof(frag)) ||
        field(fields, "attached", st->attached, sizeof(st->attached)) ||
        field(fields, "missing", st->missing, sizeof(st->missing))) {
        rc = mfw_err_reply;
    } else {
        st->generation = strtoul(gen, NULL, 10);
        st->drop_ipv4_fragments = frag[0] == '1';
    }
    free(reply);
    return rc;
}

int mfw_stats(const mfw_client_t *c, __u64 counters[MFW_STAT_MAX])
{
    char *reply, *fields, v[24];
    int rc = simple(c, "STATS\n", &reply, &fields);

    if (rc)
        return rc;
    for (int i = 0; i < MFW_STAT_MAX; i++) {
        if (field(fields, stat_names[i], v, sizeof(v))) {
            rc = mfw_err_reply;
            break;
        }
        counters[i] = strtoull(v, NULL, 10);
    }
    free(reply);
    return rc;
}

int mfw_show(const mfw_client_t *c, char **policy)
{
    char *reply, *body, *end;
    unsigned long n, lines = 0;
    int rc = mfw_request(c, "SHOW\n", &reply, NULL, 0);

    *policy = NULL;
    if (rc)
        return rc;
    /* OK <n>\n then n lines */
    n = strtoul(reply + 3, &end, 10);
    if (reply[2] != ' ' || end == reply + 3 || *end != '\n') {
        free(reply);
        return mfw_err_reply;
    }
    body = end + 1;
    for (const char *p = body; *p; p++)
        lines += *p == '\n';
    if (lines != n || (*body && body[strlen(body) - 1] != '\n')) {
        free(reply);
        return mfw_err_reply;
    }
    memmove(reply, body, strlen(body) + 1);
    *policy = reply;
    return mfw_ok;
}
