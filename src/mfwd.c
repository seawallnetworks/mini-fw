// SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
/* mfwd — the mini-fw daemon. The only process that touches the BPF side;
 * clients (sw_configd, the mfw tool) send it whole policies over a Unix
 * socket.
 *
 * One request per connection; the reply is sent and the connection
 * closed:
 *
 *   PING                     OK
 *   STATUS                   OK generation=N drop-ipv4-fragments=0|1 attached=a,b missing=c
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
 * The applied policy is saved under the state directory (/run/mfwd), so a
 * restarted mfwd knows it; the kernel side is pinned and keeps filtering
 * while mfwd is down. Single-threaded: requests are handled one at a
 * time. */
#define _GNU_SOURCE
#include <errno.h>
#include <getopt.h>
#include <grp.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#include "dataplane.h"
#include "mfw_client.h"
#include "mfw_policy.h"

#define MFWD_VERSION      "0.4.0"
#define MFWD_STATE_DIR    "/run/mfwd"
#define MFWD_READ_SECS    3      /* a client must send its request in time */

struct mfwd {
    struct mfw_dp dp;
    char          state_dir[PATH_MAX - 32];
    char         *policy;         /* applied, canonical; NULL = none yet */
    __u32         generation;     /* of that policy */
};

static volatile sig_atomic_t stop;

static void on_signal(int sig)
{
    (void)sig;
    stop = 1;
}

static void logmsg(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    fprintf(stderr, "mfwd: ");
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    va_end(ap);
}

/* ---- the saved policy ---- */

static void state_path(const struct mfwd *d, char *buf, size_t len, const char *suffix)
{
    snprintf(buf, len, "%s/policy%s", d->state_dir, suffix);
}

/* "# generation N\n" then the canonical policy; written atomically. */
static int save_policy(const struct mfwd *d)
{
    char path[PATH_MAX], tmp[PATH_MAX];
    FILE *f;
    int ok;

    if (mkdir(d->state_dir, 0700) && errno != EEXIST)
        return -1;
    state_path(d, path, sizeof(path), "");
    state_path(d, tmp, sizeof(tmp), ".tmp");
    f = fopen(tmp, "w");
    if (!f)
        return -1;
    ok = fprintf(f, "# generation %u\n%s", d->generation, d->policy) >= 0;
    ok &= fflush(f) == 0 && fsync(fileno(f)) == 0;
    ok &= fclose(f) == 0;
    if (!ok || rename(tmp, path)) {
        unlink(tmp);
        return -1;
    }
    return 0;
}

static char *read_file(const char *path)
{
    FILE *f = fopen(path, "r");
    char *buf;
    long n;

    if (!f)
        return NULL;
    if (fseek(f, 0, SEEK_END) || (n = ftell(f)) < 0 || n > MFW_REQUEST_MAX ||
        fseek(f, 0, SEEK_SET) || !(buf = malloc(n + 1))) {
        fclose(f);
        return NULL;
    }
    if (fread(buf, 1, n, f) != (size_t)n) {
        free(buf);
        fclose(f);
        return NULL;
    }
    buf[n] = '\0';
    fclose(f);
    return buf;
}

/* ---- APPLY ---- */

/* Writes "ERR <code> <message>\n" into reply. */
static void error_reply(char **reply, const char *code, const char *fmt, ...)
{
    char msg[MFW_ERR_LEN];
    va_list ap;

    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);
    if (asprintf(reply, "ERR %s %s\n", code, msg) < 0)
        *reply = NULL;
}

static void append(char *buf, size_t len, const char *name)
{
    size_t off = strlen(buf);

    snprintf(buf + off, len - off, "%s%s", off ? "," : "", name);
}

/*
 * Make the kernel enforce the policy: attach every bound interface that
 * exists, swap in its ruleset, then remove rulesets and detach interfaces
 * that are no longer bound. Validation and new attaches come first, so a
 * refused policy leaves the old one running.
 */
static void apply(struct mfwd *d, const char *text, char **reply)
{
    struct mfw_policy p;
    struct mfw_ruleset *rs;
    char err[MFW_ERR_LEN], missing[1024] = "", *canon;
    char attached[MFW_MAX_IFACES][IF_NAMESIZE], added[MFW_MAX_IFACES][IF_NAMESIZE];
    __u32 ifindex[MFW_MAX_IFACES], keep[MFW_MAX_IFACES], gen;
    int n_keep = 0, n_added = 0, n;

    if (mfw_policy_parse(text, &p, err, sizeof(err))) {
        error_reply(reply, "invalid", "%s", err);
        return;
    }
    canon = mfw_policy_format(&p);
    rs = malloc(sizeof(*rs));
    if (!canon || !rs) {
        error_reply(reply, "internal", "out of memory");
        goto out;
    }

    for (int i = 0; i < p.n_binds; i++) {
        const char *ifname = p.binds[i].ifname;

        ifindex[i] = if_nametoindex(ifname);
        if (!ifindex[i]) {
            append(missing, sizeof(missing), ifname);
            continue;
        }
        if (mfw_dp_attached(&d->dp, ifname))
            continue;
        if (mfw_dp_attach(&d->dp, ifname, err, sizeof(err))) {
            for (int j = 0; j < n_added; j++)  /* back to how it was */
                mfw_dp_detach(&d->dp, added[j]);
            error_reply(reply, "kernel", "%s", err);
            goto out;
        }
        snprintf(added[n_added++], IF_NAMESIZE, "%s", ifname);
    }

    if (mfw_dp_set_config(&d->dp, p.drop_ipv4_fragments, &gen)) {
        error_reply(reply, "kernel", "update config: %s", strerror(errno));
        goto out;
    }
    for (int i = 0; i < p.n_binds; i++) {
        if (!ifindex[i])
            continue;
        mfw_policy_compile(&p, i, rs);
        rs->generation = gen;
        if (mfw_dp_install(&d->dp, ifindex[i], rs, err, sizeof(err))) {
            error_reply(reply, "kernel", "%s: %s", p.binds[i].ifname, err);
            goto out;
        }
        keep[n_keep++] = ifindex[i];
    }
    mfw_dp_prune(&d->dp, keep, n_keep);

    n = mfw_dp_list(&d->dp, attached, MFW_MAX_IFACES);
    for (int i = 0; i < n; i++) {
        int bound = 0;

        for (int j = 0; j < p.n_binds; j++)
            bound |= ifindex[j] && !strcmp(p.binds[j].ifname, attached[i]);
        if (!bound)
            mfw_dp_detach(&d->dp, attached[i]);
    }

    free(d->policy);
    d->policy = canon;
    d->generation = gen;
    canon = NULL;
    if (save_policy(d))
        logmsg("cannot save the policy under %s: %s", d->state_dir, strerror(errno));

    if (asprintf(reply, "OK %u%s%s\n", gen, *missing ? " missing=" : "", missing) < 0)
        *reply = NULL;
out:
    free(canon);
    free(rs);
    mfw_policy_free(&p);
}

/* ---- the other requests ---- */

static void status(struct mfwd *d, char **reply)
{
    char names[MFW_MAX_IFACES][IF_NAMESIZE], attached[1024] = "", missing[1024] = "";
    char degraded[1024] = "";
    struct mfw_config cfg = {};
    struct mfw_policy p;
    char err[MFW_ERR_LEN];
    int n = mfw_dp_list(&d->dp, names, MFW_MAX_IFACES);

    for (int i = 0; i < n; i++) {
        append(attached, sizeof(attached), names[i]);
        if (mfw_dp_degraded(&d->dp, names[i]))
            append(degraded, sizeof(degraded), names[i]);
    }
    if (d->policy && mfw_policy_parse(d->policy, &p, err, sizeof(err)) == 0) {
        for (int i = 0; i < p.n_binds; i++)
            if (!if_nametoindex(p.binds[i].ifname))
                append(missing, sizeof(missing), p.binds[i].ifname);
        mfw_policy_free(&p);
    }
    mfw_dp_get_config(&d->dp, &cfg);
    if (asprintf(reply, "OK generation=%u drop-ipv4-fragments=%u attached=%s missing=%s "
                 "degraded=%s flows=%s\n", d->policy ? d->generation : 0,
                 cfg.drop_ipv4_fragments, attached, missing, degraded,
                 d->dp.flows_fd >= 0 ? "sw_flowd" : "none") < 0)
        *reply = NULL;
}

static void stats(struct mfwd *d, char **reply)
{
    __u64 c[MFW_STAT_MAX];
    char buf[1024] = "OK";
    size_t off = 2;

    if (mfw_dp_stats(&d->dp, c)) {
        error_reply(reply, "kernel", "read counters: %s", strerror(errno));
        return;
    }
    for (int i = 0; i < MFW_STAT_MAX; i++)
        off += snprintf(buf + off, sizeof(buf) - off, " %s=%llu", mfw_stat_name(i),
                        (unsigned long long)c[i]);
    if (asprintf(reply, "%s\n", buf) < 0)
        *reply = NULL;
}

static void show(struct mfwd *d, char **reply)
{
    const char *text = d->policy ? d->policy : "";
    int lines = 0;

    for (const char *s = text; *s; s++)
        lines += *s == '\n';
    if (asprintf(reply, "OK %d\n%s", lines, text) < 0)
        *reply = NULL;
}

static void handle(struct mfwd *d, char *req, uid_t uid, char **reply)
{
    char *nl = strchr(req, '\n');

    *nl = '\0';
    if (!strcmp(req, "PING")) {
        *reply = strdup("OK\n");
    } else if (!strcmp(req, "STATUS")) {
        status(d, reply);
    } else if (!strcmp(req, "STATS")) {
        stats(d, reply);
    } else if (!strcmp(req, "SHOW")) {
        show(d, reply);
    } else if (!strcmp(req, "APPLY")) {
        char *body = nl + 1, *end = body + strlen(body) - 4;  /* "END\n" */

        *end = '\0';
        apply(d, body, reply);
        if (*reply && !strncmp(*reply, "OK", 2))
            logmsg("APPLY from uid %u: generation %u", uid, d->generation);
        else if (*reply)
            logmsg("APPLY from uid %u refused: %.*s", uid,
                   (int)strcspn(*reply, "\n"), *reply);
    } else {
        error_reply(reply, "badreq", "unknown request '%.32s'", req);
    }
}

/* ---- the socket ---- */

/*
 * Reads one request: a line, or for APPLY every line up to "END".
 * Returns the request (malloc'd), or NULL with a reason in *why.
 */
static char *read_request(int fd, const char **why)
{
    size_t size = 4096, off = 0, pos = 0;
    char *buf = malloc(size), *p;
    int apply = -1;   /* unknown until the first line is in */

    *why = "out of memory";
    while (buf) {
        char *nl;

        /* complete lines from pos on */
        while ((nl = memchr(buf + pos, '\n', off - pos))) {
            size_t len = nl - (buf + pos);

            if (apply < 0)
                apply = len == 5 && !memcmp(buf, "APPLY", 5);
            if (!apply || (pos > 0 && len == 3 && !memcmp(buf + pos, "END", 3))) {
                buf[nl + 1 - buf] = '\0';
                return buf;
            }
            if (memchr(buf + pos, '\0', len)) {
                *why = "NUL byte in request";
                goto fail;
            }
            pos = nl + 1 - buf;
        }
        if (off + 1 >= size) {
            /* the buffer holds at most MFW_REQUEST_MAX bytes */
            if (size > MFW_REQUEST_MAX) {
                *why = "request too long";
                goto fail;
            }
            size = size * 2 > MFW_REQUEST_MAX + 1 ? MFW_REQUEST_MAX + 1 : size * 2;
            p = realloc(buf, size + 1);
            if (!p)
                goto fail;
            buf = p;
        }

        ssize_t n = recv(fd, buf + off, size - 1 - off, 0);

        if (n < 0 && errno == EINTR && !stop)
            continue;
        if (n <= 0) {
            *why = n < 0 ? "request not complete in time" : "request not complete";
            goto fail;
        }
        off += n;
    }
fail:
    free(buf);
    return NULL;
}

static void send_all(int fd, const char *p, size_t len)
{
    while (len > 0) {
        ssize_t n = send(fd, p, len, MSG_NOSIGNAL);

        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
            return;
        p += n;
        len -= n;
    }
}

/*
 * Reads and drops what the client still sends, for at most a second.
 * Closing a Unix socket with unread input resets the connection, and the
 * client would lose the reply (e.g. "request too long") before reading it.
 */
static void drain(int fd)
{
    struct timeval tv = { 0, 100 * 1000 }, start, now;
    char buf[65536];

    shutdown(fd, SHUT_WR);
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    gettimeofday(&start, NULL);
    while (recv(fd, buf, sizeof(buf), 0) > 0) {
        gettimeofday(&now, NULL);
        if (now.tv_sec - start.tv_sec >= 1)
            break;
    }
}

static void serve(struct mfwd *d, int fd)
{
    struct timeval tv = { MFWD_READ_SECS, 0 };
    struct ucred cred = {};
    socklen_t clen = sizeof(cred);
    char *req, *reply = NULL;
    const char *why;

    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cred, &clen);

    req = read_request(fd, &why);
    if (req)
        handle(d, req, cred.uid, &reply);
    else
        error_reply(&reply, "badreq", "%s", why);
    if (!reply)
        reply = strdup("ERR internal out of memory\n");
    if (reply)
        send_all(fd, reply, strlen(reply));
    drain(fd);
    free(reply);
    free(req);
}

static int listen_on(const char *path, mode_t mode, gid_t gid)
{
    struct sockaddr_un addr = { .sun_family = AF_UNIX };
    struct stat st;
    int fd;

    if (strlen(path) >= sizeof(addr.sun_path)) {
        logmsg("socket path too long: %s", path);
        return -1;
    }
    strcpy(addr.sun_path, path);
    if (lstat(path, &st) == 0) {
        if (!S_ISSOCK(st.st_mode)) {
            logmsg("%s exists and is not a socket", path);
            return -1;
        }
        unlink(path);
    }
    fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0 || bind(fd, (struct sockaddr *)&addr, sizeof(addr)) ||
        chmod(path, mode) || (gid != (gid_t)-1 && chown(path, -1, gid)) ||
        listen(fd, 16)) {
        logmsg("listen on %s: %s", path, strerror(errno));
        if (fd >= 0)
            close(fd);
        return -1;
    }
    return fd;
}

/* A policy saved by an earlier mfwd: kept if the kernel still runs its
 * generation, applied again if the pins are new (e.g. after mfwd -P). */
static void restore(struct mfwd *d)
{
    char path[PATH_MAX], *text, *reply = NULL;
    struct mfw_config cfg = {};
    unsigned gen;

    state_path(d, path, sizeof(path), "");
    text = read_file(path);
    if (!text)
        return;
    if (sscanf(text, "# generation %u", &gen) != 1) {
        logmsg("%s: no generation line; ignored", path);
        free(text);
        return;
    }
    mfw_dp_get_config(&d->dp, &cfg);
    if (cfg.generation == gen) {
        d->policy = strdup(strchr(text, '\n') + 1);
        d->generation = gen;
        logmsg("policy generation %u is in place", gen);
    } else {
        logmsg("kernel has generation %u, saved policy %u: applying it again",
               cfg.generation, gen);
        apply(d, strchr(text, '\n') + 1, &reply);
        if (reply)
            logmsg("%.*s", (int)strcspn(reply, "\n"), reply);
        free(reply);
    }
    free(text);
}

/* /etc/group read directly: mfwd is static, and getgrnam's NSS would
 * dlopen modules (libnss_systemd) built for a different libc */
static struct group *find_group(const char *name)
{
    FILE *f = fopen("/etc/group", "re");
    struct group *g;

    if (!f)
        return NULL;
    while ((g = fgetgrent(f)) && strcmp(g->gr_name, name))
        ;
    fclose(f);
    return g;
}

static void usage(FILE *f)
{
    fprintf(f,
        "usage: mfwd [-s socket] [-m mode] [-g group] [-p pinroot] [-d statedir]\n"
        "       mfwd -P [-p pinroot] [-d statedir]\n"
        "\n"
        "  -s socket   listen here (default " MFW_SOCKET ")\n"
        "  -m mode     socket permissions, octal (default 0600)\n"
        "  -g group    socket group, e.g. the one sw_configd runs as\n"
        "  -p pinroot  bpffs directory for maps and links (default " MFW_PIN_ROOT ")\n"
        "  -d dir      where the applied policy is saved (default " MFWD_STATE_DIR ")\n"
        "  -P          detach every interface, remove all pins and the saved\n"
        "              policy, then exit\n"
        "  -V          print the version\n");
}

int main(int argc, char **argv)
{
    const char *sock = MFW_SOCKET, *root = MFW_PIN_ROOT;
    struct mfwd d = {};
    struct sigaction sa = { .sa_handler = on_signal };
    char err[MFW_ERR_LEN], path[PATH_MAX];
    mode_t mode = 0600;
    gid_t gid = -1;
    int c, fd, purge = 0;
    char *end;

    snprintf(d.state_dir, sizeof(d.state_dir), "%s", MFWD_STATE_DIR);
    while ((c = getopt(argc, argv, "s:m:g:p:d:PVh")) != -1) {
        switch (c) {
        case 's': sock = optarg; break;
        case 'p': root = optarg; break;
        case 'd': snprintf(d.state_dir, sizeof(d.state_dir), "%s", optarg); break;
        case 'P': purge = 1; break;
        case 'm':
            mode = strtol(optarg, &end, 8);
            if (*end || mode > 0777) {
                fprintf(stderr, "mfwd: bad mode '%s'\n", optarg);
                return 2;
            }
            break;
        case 'g': {
            struct group *g = find_group(optarg);

            if (!g) {
                fprintf(stderr, "mfwd: no such group '%s'\n", optarg);
                return 2;
            }
            gid = g->gr_gid;
            break;
        }
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
        mfw_dp_purge(root);
        state_path(&d, path, sizeof(path), "");
        unlink(path);
        rmdir(d.state_dir);
        printf("mfwd: removed %s and the saved policy\n", root);
        return 0;
    }

    if (mfw_dp_open(&d.dp, root, err, sizeof(err))) {
        logmsg("%s", err);
        return 1;
    }
    restore(&d);

    fd = listen_on(sock, mode, gid);
    if (fd < 0) {
        mfw_dp_close(&d.dp);
        return 1;
    }
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);
    signal(SIGPIPE, SIG_IGN);
    /* accept() wakes up every second, so a signal is never missed */
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &(struct timeval){ 1, 0 },
               sizeof(struct timeval));
    logmsg("%s, ABI %d: listening on %s, pins under %s, attaching with %s",
           MFWD_VERSION, MFW_ABI_VERSION, sock, root,
           d.dp.no_xdp ? (d.dp.tcx ? "tcx (MFW_NO_XDP)" : "classic TC (MFW_NO_XDP)")
           : d.dp.tcx ? "libxdp's dispatcher, else tcx"
           : "libxdp's dispatcher, else classic TC (no tcx before kernel 6.6)");

    while (!stop) {
        int cfd = accept4(fd, NULL, NULL, SOCK_CLOEXEC);

        if (cfd < 0) {
            if (errno != EINTR && errno != EAGAIN && errno != ECONNABORTED)
                logmsg("accept: %s", strerror(errno));
            continue;
        }
        serve(&d, cfd);
        close(cfd);
    }

    /* the pinned links keep filtering after we are gone */
    logmsg("stopping; interfaces stay protected");
    close(fd);
    unlink(sock);
    mfw_dp_close(&d.dp);
    free(d.policy);
    return 0;
}
