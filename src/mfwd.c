
/* SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause */

/*
 * mfwd — the mini-fw daemon. The only process that touches the BPF side;
 * clients (sw_configd, the mfw tool) send it whole policies over a Unix
 * socket.
 *
 * One request per connection; the reply is sent and the connection
 * closed:
 *
 *   PING                     OK
 *   STATUS                   OK generation=N drop-ipv4-fragments=0|1
 *                            attached=a,b missing=c
 *                            degraded=d (at TC: another program holds XDP)
 *                            flows=sw_flowd|none (what "reply" ACEs read)
 *   STATS                    OK xdp_pass=N xdp_drop=N ...
 *   SHOW                     OK <n>, then the applied policy in n lines
 *   APPLY                    OK <generation>[ missing=a,b]
 *   <policy lines>
 *   END
 *
 * Errors: ERR <code> <message>, code one of badreq, invalid, kernel,
 * internal. The policy format is described in mfw_policy.h.
 *
 * The applied policy is saved under the run directory (/run/mfwd), so a
 * restarted mfwd applies it again; the kernel side is pinned and keeps
 * filtering while mfwd is down. There is no live update: a starting mfwd
 * replaces the pins, and nothing is filtered until the saved policy is
 * applied again. Single-threaded: requests are handled one at a
 * time. Under systemd (Type=notify) it says it is ready once it serves,
 * so a front end ordered after it, such as sw_configd, finds the socket.
 *
 * Logging, the socket, readiness and the saved policy's file are libsw's
 * (Seawall proposal 0011).
 */


#define _GNU_SOURCE

#include "dataplane.h"
#include "mfw_client.h"
#include "mfw_policy.h"

#include <sw/bpf.h>
#include <sw/conf.h>
#include <sw/file.h>
#include <sw/log.h>
#include <sw/netif.h>
#include <sw/notify.h>
#include <sw/sock.h>

#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>


#define MFWD_VERSION    "0.4.0"
#define MFWD_RUN_DIR    "/run/mfwd"
#define MFWD_READ_SECS  3      /* a client must send its request in time */


typedef struct {
    struct mfw_dp   dp;
    char            run_dir[PATH_MAX - 32];
    char           *policy;       /* applied, canonical; NULL: none yet */
    __u32           generation;   /* of that policy */
} mfwd_t;


static void on_signal(int sig);
static void policy_path(const mfwd_t *d, char *buf, size_t len);
static void save_policy(const mfwd_t *d);
static void error_reply(char **reply, const char *code, const char *fmt,
    ...);
static void append(char *buf, size_t len, const char *name);
static int attach_bound(mfwd_t *d, const struct mfw_policy *p,
    __u32 *ifindex, char *missing, size_t mlen, char *err, size_t errlen);
static int install(mfwd_t *d, const struct mfw_policy *p,
    const __u32 *ifindex, struct mfw_ruleset *rs, __u32 *gen, char *err,
    size_t errlen);
static void detach_unbound(mfwd_t *d, const struct mfw_policy *p,
    const __u32 *ifindex);
static void apply(mfwd_t *d, const char *text, char **reply);
static void status(mfwd_t *d, char **reply);
static void stats(mfwd_t *d, char **reply);
static void show(mfwd_t *d, char **reply);
static void handle(mfwd_t *d, char *req, uid_t uid, char **reply);
static char *read_request(int fd, const char **why);
static void serve(mfwd_t *d, int fd);
static void restore(mfwd_t *d);
static void usage(FILE *f);


static volatile sig_atomic_t  mfwd_stop;


static void
on_signal(int sig)
{
    (void) sig;

    mfwd_stop = 1;
}


/* ---- the saved policy ---- */


static void
policy_path(const mfwd_t *d, char *buf, size_t len)
{
    snprintf(buf, len, "%s/policy", d->run_dir);
}


/*
 * The canonical policy, written atomically, its directory synced too: a
 * crash just after an APPLY keeps it.
 */
static void
save_policy(const mfwd_t *d)
{
    int     e;
    size_t  len;
    char    path[PATH_MAX], err[PATH_MAX + 128];

    policy_path(d, path, sizeof(path));

    if (sw_file_mkdir_p(d->run_dir, 0700) != 0) {
        sw_log_err("cannot save the policy: create %s: %s", d->run_dir,
                   strerror(errno));
        return;
    }

    len = strlen(d->policy);

    e = sw_file_write_atomic(path, d->policy, len, 0600, err, sizeof(err));
    if (e != 0) {
        sw_log_err("cannot save the policy: %s", err);
    }
}


/* ---- APPLY ---- */


/* Writes "ERR <code> <message>\n" into reply. */
static void
error_reply(char **reply, const char *code, const char *fmt, ...)
{
    va_list  ap;
    char     msg[MFW_ERR_LEN];

    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);

    if (asprintf(reply, "ERR %s %s\n", code, msg) < 0) {
        *reply = NULL;
    }
}


/* Adds name to the comma-separated list in buf. */
static void
append(char *buf, size_t len, const char *name)
{
    size_t  off;

    off = strlen(buf);
    snprintf(buf + off, len - off, "%s%s", off > 0 ? "," : "", name);
}


/*
 * Look up every bound interface, putting its index in ifindex (0 if it
 * doesn't exist, and its name in missing), and attach those that exist and
 * aren't attached yet. On failure, the ones attached here are detached
 * again: the old policy runs as it did.
 */
static int
attach_bound(mfwd_t *d, const struct mfw_policy *p, __u32 *ifindex,
    char *missing, size_t mlen, char *err, size_t errlen)
{
    int          i, idx, n_added;
    const char  *ifname;
    char         added[MFW_MAX_IFACES][IF_NAMESIZE];

    n_added = 0;

    for (i = 0; i < p->n_binds; i++) {
        ifname = p->binds[i].ifname;

        /* can't tell whether it exists: the old policy stays */
        idx = sw_netif_index(ifname, err, errlen);
        if (idx < 0) {
            goto undo;
        }

        ifindex[i] = idx;

        if (idx == 0) {
            append(missing, mlen, ifname);
            continue;
        }

        if (mfw_dp_attached(&d->dp, ifname)) {
            continue;
        }

        if (mfw_dp_attach(&d->dp, ifname, err, errlen) != 0) {
            goto undo;
        }

        snprintf(added[n_added++], IF_NAMESIZE, "%s", ifname);
    }

    return 0;

undo:

    for (i = 0; i < n_added; i++) {
        mfw_dp_detach(&d->dp, added[i]);
    }

    return -1;
}


/*
 * Swap in the policy's config, then each existing bound interface's
 * ruleset, compiled into rs and stamped with the new generation, put in
 * *gen. The rulesets of interfaces no longer bound are removed.
 */
static int
install(mfwd_t *d, const struct mfw_policy *p, const __u32 *ifindex,
    struct mfw_ruleset *rs, __u32 *gen, char *err, size_t errlen)
{
    int    i, n_keep;
    __u32  keep[MFW_MAX_IFACES];
    char   msg[MFW_ERR_LEN - IF_NAMESIZE - 2];  /* after "<ifname>: " */

    if (mfw_dp_set_config(&d->dp, p->drop_ipv4_fragments, gen) != 0) {
        snprintf(err, errlen, "update config: %s", strerror(errno));
        return -1;
    }

    n_keep = 0;

    for (i = 0; i < p->n_binds; i++) {
        if (ifindex[i] == 0) {
            continue;
        }

        mfw_policy_compile(p, i, rs);
        rs->generation = *gen;

        if (mfw_dp_install(&d->dp, ifindex[i], rs, msg, sizeof(msg)) != 0) {
            snprintf(err, errlen, "%s: %s", p->binds[i].ifname, msg);
            return -1;
        }

        keep[n_keep++] = ifindex[i];
    }

    mfw_dp_prune(&d->dp, keep, n_keep);

    return 0;
}


/* Detach the interfaces mini-fw is on that are not bound, or not there. */
static void
detach_unbound(mfwd_t *d, const struct mfw_policy *p, const __u32 *ifindex)
{
    int   bound, i, j, n;
    char  attached[MFW_MAX_IFACES][IF_NAMESIZE];

    n = mfw_dp_list_attached(&d->dp, attached, MFW_MAX_IFACES);

    for (i = 0; i < n; i++) {
        bound = 0;

        for (j = 0; j < p->n_binds; j++) {
            bound |= ifindex[j] != 0
                     && strcmp(p->binds[j].ifname, attached[i]) == 0;
        }

        if (!bound) {
            mfw_dp_detach(&d->dp, attached[i]);
        }
    }
}


/*
 * Make the kernel enforce the policy: attach every bound interface that
 * exists, swap in its ruleset, then remove rulesets and detach interfaces
 * that are no longer bound. Validation and new attaches come first, so a
 * refused policy leaves the old one running.
 */
static void
apply(mfwd_t *d, const char *text, char **reply)
{
    char                *canon;
    __u32                gen;
    struct mfw_policy    p;
    struct mfw_ruleset  *rs;
    __u32                ifindex[MFW_MAX_IFACES];
    char                 err[MFW_ERR_LEN], missing[1024];

    if (mfw_policy_parse(text, &p, err, sizeof(err)) != 0) {
        error_reply(reply, "invalid", "%s", err);
        return;
    }

    missing[0] = '\0';
    canon = mfw_policy_format(&p);
    rs = malloc(sizeof(*rs));

    if (canon == NULL || rs == NULL) {
        error_reply(reply, "internal", "out of memory");
        goto out;
    }

    if (attach_bound(d, &p, ifindex, missing, sizeof(missing), err,
                     sizeof(err)) != 0
        || install(d, &p, ifindex, rs, &gen, err, sizeof(err)) != 0)
    {
        error_reply(reply, "kernel", "%s", err);
        goto out;
    }

    detach_unbound(d, &p, ifindex);

    free(d->policy);
    d->policy = canon;
    d->generation = gen;
    canon = NULL;

    save_policy(d);

    if (asprintf(reply, "OK %u%s%s\n", gen,
                 missing[0] != '\0' ? " missing=" : "", missing) < 0)
    {
        *reply = NULL;
    }

out:

    free(canon);
    free(rs);
    mfw_policy_free(&p);
}


/* ---- the other requests ---- */


static void
status(mfwd_t *d, char **reply)
{
    int                 i, n;
    struct mfw_config   cfg = {};
    struct mfw_policy   p;
    char                err[MFW_ERR_LEN];
    char                attached[1024], degraded[1024], missing[1024];
    char                names[MFW_MAX_IFACES][IF_NAMESIZE];

    attached[0] = '\0';
    degraded[0] = '\0';
    missing[0] = '\0';

    n = mfw_dp_list_attached(&d->dp, names, MFW_MAX_IFACES);

    for (i = 0; i < n; i++) {
        append(attached, sizeof(attached), names[i]);

        if (mfw_dp_degraded(&d->dp, names[i])) {
            append(degraded, sizeof(degraded), names[i]);
        }
    }

    if (d->policy != NULL
        && mfw_policy_parse(d->policy, &p, err, sizeof(err)) == 0)
    {
        /* missing only if it isn't there, not if it can't be told */
        for (i = 0; i < p.n_binds; i++) {
            if (sw_netif_index(p.binds[i].ifname, NULL, 0) == 0) {
                append(missing, sizeof(missing), p.binds[i].ifname);
            }
        }

        mfw_policy_free(&p);
    }

    mfw_dp_get_config(&d->dp, &cfg);

    if (asprintf(reply, "OK generation=%u drop-ipv4-fragments=%u attached=%s "
                 "missing=%s degraded=%s flows=%s\n",
                 d->policy != NULL ? d->generation : 0,
                 cfg.drop_ipv4_fragments, attached, missing, degraded,
                 d->dp.flows_fd >= 0 ? "sw_flowd" : "none") < 0)
    {
        *reply = NULL;
    }
}


static void
stats(mfwd_t *d, char **reply)
{
    int     i;
    __u64   c[MFW_STAT_MAX];
    size_t  off;
    char    buf[1024];

    if (mfw_dp_stats(&d->dp, c) != 0) {
        error_reply(reply, "kernel", "read counters: %s", strerror(errno));
        return;
    }

    off = snprintf(buf, sizeof(buf), "OK");

    for (i = 0; i < MFW_STAT_MAX; i++) {
        off += snprintf(buf + off, sizeof(buf) - off, " %s=%llu",
                        mfw_stat_name(i), (unsigned long long) c[i]);
    }

    if (asprintf(reply, "%s\n", buf) < 0) {
        *reply = NULL;
    }
}


static void
show(mfwd_t *d, char **reply)
{
    int          lines;
    const char  *s, *text;

    text = d->policy != NULL ? d->policy : "";
    lines = 0;

    for (s = text; *s != '\0'; s++) {
        lines += *s == '\n';
    }

    if (asprintf(reply, "OK %d\n%s", lines, text) < 0) {
        *reply = NULL;
    }
}


static void
handle(mfwd_t *d, char *req, uid_t uid, char **reply)
{
    char  *body, *end, *nl;

    nl = strchr(req, '\n');
    *nl = '\0';

    if (strcmp(req, "PING") == 0) {
        *reply = strdup("OK\n");

    } else if (strcmp(req, "STATUS") == 0) {
        status(d, reply);

    } else if (strcmp(req, "STATS") == 0) {
        stats(d, reply);

    } else if (strcmp(req, "SHOW") == 0) {
        show(d, reply);

    } else if (strcmp(req, "APPLY") == 0) {
        body = nl + 1;
        end = body + strlen(body) - 4;  /* "END\n" */
        *end = '\0';

        apply(d, body, reply);

        if (*reply != NULL && strncmp(*reply, "OK", 2) == 0) {
            sw_log_info("APPLY from uid %u: generation %u", uid,
                        d->generation);

        } else if (*reply != NULL) {
            sw_log_warn("APPLY from uid %u refused: %.*s", uid,
                        (int) strcspn(*reply, "\n"), *reply);
        }

    } else {
        error_reply(reply, "badreq", "unknown request '%.32s'", req);
    }
}


/* ---- the socket ---- */


/*
 * Reads one request: a line, or for APPLY every line up to "END".
 * Returns the request (malloc'd), or NULL with a reason in *why.
 */
static char *
read_request(int fd, const char **why)
{
    int       apply;
    char     *buf, *nl, *p;
    size_t    len, off, pos, size;
    ssize_t   n;

    size = 4096;
    off = 0;
    pos = 0;
    apply = -1;  /* unknown until the first line is in */

    *why = "out of memory";

    buf = malloc(size);
    if (buf == NULL) {
        return NULL;
    }

    for ( ;; ) {
        /* complete lines from pos on */
        while ((nl = memchr(buf + pos, '\n', off - pos)) != NULL) {
            len = nl - (buf + pos);

            if (apply < 0) {
                apply = len == 5 && memcmp(buf, "APPLY", 5) == 0;
            }

            if (!apply
                || (pos > 0 && len == 3 && memcmp(buf + pos, "END", 3) == 0))
            {
                nl[1] = '\0';
                return buf;
            }

            if (memchr(buf + pos, '\0', len) != NULL) {
                *why = "NUL byte in request";
                goto failed;
            }

            pos = nl + 1 - buf;
        }

        if (off + 1 >= size) {
            /* the buffer holds at most MFW_REQUEST_MAX bytes */
            if (size > MFW_REQUEST_MAX) {
                *why = "request too long";
                goto failed;
            }

            size *= 2;

            if (size > MFW_REQUEST_MAX + 1) {
                size = MFW_REQUEST_MAX + 1;
            }

            p = realloc(buf, size + 1);
            if (p == NULL) {
                goto failed;
            }

            buf = p;
        }

        n = recv(fd, buf + off, size - 1 - off, 0);

        if (n < 0 && errno == EINTR && !mfwd_stop) {
            continue;
        }

        if (n <= 0) {
            *why = n < 0 ? "request not complete in time"
                         : "request not complete";
            goto failed;
        }

        off += n;
    }

failed:

    free(buf);

    return NULL;
}


static void
serve(mfwd_t *d, int fd)
{
    char        *reply, *req;
    uid_t        uid;
    const char  *why;

    uid = (uid_t) -1;
    reply = NULL;

    sw_sock_timeouts(fd, MFWD_READ_SECS * 1000);
    sw_sock_peer(fd, NULL, &uid, NULL);

    req = read_request(fd, &why);

    if (req != NULL) {
        handle(d, req, uid, &reply);

    } else {
        error_reply(&reply, "badreq", "%s", why);
    }

    if (reply == NULL) {
        reply = strdup("ERR internal out of memory\n");
    }

    if (reply != NULL) {
        sw_sock_send_all(fd, reply, strlen(reply));
    }

    /* unread input would reset the connection, and lose the reply */
    sw_sock_drain(fd);

    free(reply);
    free(req);
}


/*
 * A policy saved by an earlier mfwd: applied again, to the new pins.
 * Until it is, every interface passes everything.
 */
static void
restore(mfwd_t *d)
{
    char  *reply, *text;
    char   path[PATH_MAX], err[PATH_MAX + 64];

    policy_path(d, path, sizeof(path));

    text = sw_file_read(path, MFW_REQUEST_MAX, NULL, err, sizeof(err));
    if (text == NULL) {
        if (errno != ENOENT) {
            sw_log_warn("saved policy not restored: %s", err);
        }

        return;
    }

    reply = NULL;
    apply(d, text, &reply);

    if (reply != NULL) {
        sw_log(strncmp(reply, "OK", 2) == 0 ? SW_LOG_INFO : SW_LOG_WARN,
               "saved policy applied again: %.*s",
               (int) strcspn(reply, "\n"), reply);
    }

    free(text);
    free(reply);
}


static void
usage(FILE *f)
{
    fprintf(f,
        "usage: mfwd [-v] [-s socket] [-m mode] [-g group] [-d rundir]\n"
        "       mfwd -P [-d rundir]\n"
        "\n"
        "  -v          debug logging, libbpf's and libxdp's info included\n"
        "              (SW_BPF_DEBUG=1 adds the verifier's log)\n"
        "  -s socket   listen here (default " MFW_SOCKET ")\n"
        "  -m mode     socket permissions, octal (default 0600)\n"
        "  -g group    socket group, e.g. the one sw_configd runs as\n"
        "  -d rundir   where the applied policy is saved\n"
        "              (default " MFWD_RUN_DIR ")\n"
        "  -P          detach every interface, remove all pins and the saved\n"
        "              policy, then exit\n"
        "  -V          print the version\n");
}


int
main(int argc, char **argv)
{
    int                c, cfd, fd, purge;
    mfwd_t             d = {};
    mode_t             mode;
    const char        *group, *how, *sock;
    struct sigaction   sa = {};
    char               err[PATH_MAX + 128], path[PATH_MAX];

    sock = MFW_SOCKET;
    group = NULL;
    mode = 0600;
    purge = 0;

    sw_log_init("mfwd");
    sw_bpf_log_init();
    sw_bpf_libxdp_log_init();

    snprintf(d.run_dir, sizeof(d.run_dir), "%s", MFWD_RUN_DIR);

    while ((c = getopt(argc, argv, "vs:m:g:d:PVh")) != -1) {
        switch (c) {
        case 'v':
            sw_log_set_level(SW_LOG_DEBUG);
            break;

        case 's':
            sock = optarg;
            break;

        case 'm':
            if (sw_conf_mode(optarg, &mode) != 0) {
                sw_log_err("bad mode '%s': octal, at most 0777", optarg);
                return 2;
            }

            break;

        case 'g':
            /* looked up when the socket is made, in /etc/group */
            group = optarg;
            break;

        case 'd':
            snprintf(d.run_dir, sizeof(d.run_dir), "%s", optarg);
            break;

        case 'P':
            purge = 1;
            break;

        case 'V':
            printf("mfwd %s, ABI %d\n", MFWD_VERSION, MFW_ABI_VERSION);
            return 0;

        case 'h':
            usage(stdout);
            return 0;

        default:
            usage(stderr);
            return 2;
        }
    }

    if (optind != argc) {
        usage(stderr);
        return 2;
    }

    if (purge) {
        if (mfw_dp_purge(err, sizeof(err)) != 0) {
            sw_log_err("%s", err);
            return 1;
        }

        policy_path(&d, path, sizeof(path));
        unlink(path);
        rmdir(d.run_dir);

        printf("mfwd: removed %s and the saved policy\n", MFW_PIN_PATH);
        return 0;
    }

    /*
     * The socket first: another mfwd answering on it, or an unknown group,
     * refuses this one before it touches the pins. A client that connects
     * while the policy is restored waits for it.
     */
    fd = sw_sock_listen(sock, mode, group, err, sizeof(err));
    if (fd < 0) {
        sw_log_err("%s", err);
        return 1;
    }

    /*
     * No live update: start afresh, fail-open until restore() applies the
     * saved policy.
     */
    if (mfw_dp_purge(err, sizeof(err)) != 0
        || mfw_dp_open(&d.dp, err, sizeof(err)) != 0)
    {
        sw_log_err("%s", err);
        goto failed;
    }

    restore(&d);

    sa.sa_handler = on_signal;
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);

    /* stderr may be a pipe; the socket's sends are MSG_NOSIGNAL */
    signal(SIGPIPE, SIG_IGN);

    /* accept() wakes up every second, so a signal is never missed */
    sw_sock_timeouts(fd, 1000);

    if (d.dp.no_xdp) {
        how = d.dp.tcx ? "tcx (MFW_NO_XDP)" : "classic TC (MFW_NO_XDP)";

    } else if (d.dp.tcx) {
        how = "libxdp's dispatcher, else tcx";

    } else {
        how = "libxdp's dispatcher, else classic TC (no tcx before "
              "kernel 6.6)";
    }

    sw_log_info("%s, ABI %d: listening on %s, pins under %s, attaching "
                "with %s", MFWD_VERSION, MFW_ABI_VERSION, sock, MFW_PIN_PATH,
                how);

    if (sw_notify_ready() != 0) {
        sw_log_warn("tell systemd mfwd is ready: %s", strerror(errno));
    }

    while (!mfwd_stop) {
        cfd = accept4(fd, NULL, NULL, SOCK_CLOEXEC);

        if (cfd < 0) {
            if (errno != EINTR && errno != EAGAIN && errno != ECONNABORTED) {
                sw_log_warn("accept: %s", strerror(errno));
            }

            continue;
        }

        serve(&d, cfd);
        close(cfd);
    }

    /* the pins keep filtering after we are gone */
    sw_log_info("stopping; interfaces stay protected");

    close(fd);
    unlink(sock);
    mfw_dp_close(&d.dp);
    free(d.policy);

    return 0;

failed:

    close(fd);
    unlink(sock);

    return 1;
}
