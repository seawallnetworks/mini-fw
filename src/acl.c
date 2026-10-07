// SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
/* ACL store (userspace-only pinned maps) and materialization into acl_std/acl_ext.
 *
 * state/acl_db   HASH  mfw_db_key(acl, seq) → mfw_rule   every defined ACE
 * state/bindings ARRAY slot → mfw_binding                ip access-group
 *
 * Both live on bpffs, so lists can be defined before attach and survive
 * process exit without a config file; reboot clears them (as with all pins).
 */
#include <errno.h>
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <bpf/bpf.h>

#include "mfw_cli.h"

struct state {
    int db_fd;
    int bind_fd;
};

static int open_or_create(const char *path, enum bpf_map_type type,
                          const char *name, __u32 vsize, __u32 max, int create)
{
    int fd = bpf_obj_get(path);

    if (fd >= 0 || !create)
        return fd >= 0 ? fd : -errno;
    if (mfw_ensure_dir(MFW_STATE_DIR))
        return -errno;
    fd = bpf_map_create(type, name, sizeof(__u32), vsize, max, NULL);
    if (fd < 0)
        return -errno;
    if (bpf_obj_pin(fd, path)) {
        int err = -errno;

        close(fd);
        return err;
    }
    return fd;
}

/* create=0: missing store reads as empty (fds = -1). */
static int state_open(struct state *st, int create)
{
    st->db_fd = open_or_create(MFW_STATE_DIR "/acl_db", BPF_MAP_TYPE_HASH,
                               "mfw_acl_db", sizeof(struct mfw_rule),
                               MFW_ACL_DB_MAX, create);
    st->bind_fd = open_or_create(MFW_STATE_DIR "/bindings", BPF_MAP_TYPE_ARRAY,
                                 "mfw_bindings", sizeof(struct mfw_binding),
                                 MFW_BIND_MAX, create);
    if (create && (st->db_fd < 0 || st->bind_fd < 0)) {
        fprintf(stderr, "mfw: cannot open ACL store under %s: %s "
                        "(is bpffs mounted? are you root?)\n",
                MFW_STATE_DIR, strerror(-(st->db_fd < 0 ? st->db_fd : st->bind_fd)));
        return EXIT_KERNEL;
    }
    return EXIT_OK;
}

static void state_close(struct state *st)
{
    if (st->db_fd >= 0)
        close(st->db_fd);
    if (st->bind_fd >= 0)
        close(st->bind_fd);
}

static void load_bindings(const struct state *st, struct mfw_binding b[MFW_BIND_MAX])
{
    memset(b, 0, sizeof(*b) * MFW_BIND_MAX);
    if (st->bind_fd < 0)
        return;
    for (__u32 i = 0; i < MFW_BIND_MAX; i++)
        bpf_map_lookup_elem(st->bind_fd, &i, &b[i]);
}

static int rule_cmp(const void *a, const void *b)
{
    const struct mfw_rule *x = a, *y = b;

    if (x->acl_id != y->acl_id)
        return x->acl_id - y->acl_id;
    return x->seq - y->seq;
}

/* All ACEs sorted by (list, seq). Caller frees. */
static struct mfw_rule *load_rules(const struct state *st, int *count)
{
    struct mfw_rule *rules = calloc(MFW_ACL_DB_MAX, sizeof(*rules));
    __u32 key, next, *prev = NULL;
    int n = 0;

    *count = 0;
    if (!rules || st->db_fd < 0)
        return rules;
    while (n < MFW_ACL_DB_MAX && bpf_map_get_next_key(st->db_fd, prev, &next) == 0) {
        if (bpf_map_lookup_elem(st->db_fd, &next, &rules[n]) == 0)
            n++;
        key = next;
        prev = &key;
    }
    qsort(rules, n, sizeof(*rules), rule_cmp);
    *count = n;
    return rules;
}

static void bump_generation(void)
{
    int fd = mfw_open_pinned(MFW_MAPS_DIR "/config");
    struct mfw_config cfg;
    __u32 k = 0;

    if (fd < 0)
        return;
    if (bpf_map_lookup_elem(fd, &k, &cfg) == 0) {
        cfg.generation++;
        bpf_map_update_elem(fd, &k, &cfg, BPF_ANY);
    }
    close(fd);
}

/* Append list `acl` ACEs to out[] with direction bits `dir`. */
static int append_list(struct mfw_rule *out, int n, int max,
                       const struct mfw_rule *rules, int count,
                       __u16 acl, __u8 dir)
{
    for (int i = 0; i < count; i++) {
        if (rules[i].acl_id != acl)
            continue;
        if (n >= max)
            return -1;
        out[n] = rules[i];
        out[n].direction = dir;
        n++;
    }
    return n;
}

static int append_implicit_deny(struct mfw_rule *out, int n, int max, __u16 acl, __u8 dir)
{
    if (n >= max)
        return -1;
    memset(&out[n], 0, sizeof(out[n]));
    out[n].acl_id = acl;
    out[n].seq = 0xffff;
    out[n].action = MFW_ACTION_DENY;
    out[n].direction = dir;
    out[n].enabled = 1;
    out[n].kind = MFW_ACL_EXTENDED;
    out[n].flags = MFW_RULE_F_IMPLICIT;
    return n + 1;
}

/* Write compiled[0..n) and zero the rest (new entries first, then the tail). */
static int write_map(int fd, const struct mfw_rule *compiled, int n, int max)
{
    struct mfw_rule zero = {};

    for (__u32 i = 0; i < (__u32)max; i++) {
        const struct mfw_rule *v = (int)i < n ? &compiled[i] : &zero;

        if (bpf_map_update_elem(fd, &i, v, BPF_ANY))
            return -errno;
    }
    return 0;
}

/* Compile bound lists into std[]/ext[]. Returns 0 or EXIT_VALIDATION. */
static int compile(const struct state *st, struct mfw_rule *std, int *n_std,
                   struct mfw_rule *ext, int *n_ext)
{
    struct mfw_binding b[MFW_BIND_MAX];
    struct mfw_rule *rules;
    int count, ns = 0, ne = 0;
    __u16 si, ei;

    load_bindings(st, b);
    rules = load_rules(st, &count);
    if (!rules)
        return EXIT_KERNEL;
    si = b[MFW_BIND_STD_IN].acl_id;
    ei = b[MFW_BIND_EXT_IN].acl_id;

    /* Standard: blacklist, no implicit deny. */
    if (si)
        ns = append_list(std, ns, MFW_MAX_STD_ACES, rules, count, si, MFW_DIR_INGRESS);

    /* Extended: ends with a synthetic deny ip any any, so a bound-but-empty
     * list still denies. */
    if (ei) {
        ne = append_list(ext, ne, MFW_MAX_EXT_ACES, rules, count, ei, MFW_DIR_INGRESS);
        if (ne >= 0)
            ne = append_implicit_deny(ext, ne, MFW_MAX_EXT_ACES, ei, MFW_DIR_INGRESS);
    }
    free(rules);

    if (ns < 0) {
        fprintf(stderr, "mfw: bound standard lists exceed %d ACEs\n", MFW_MAX_STD_ACES);
        return EXIT_VALIDATION;
    }
    if (ne < 0) {
        fprintf(stderr, "mfw: bound extended list exceeds %d ACEs "
                        "(including the implicit deny)\n",
                MFW_MAX_EXT_ACES);
        return EXIT_VALIDATION;
    }
    *n_std = ns;
    *n_ext = ne;
    return EXIT_OK;
}

static int materialize_state(const struct state *st)
{
    struct mfw_rule std[MFW_MAX_STD_ACES], ext[MFW_MAX_EXT_ACES];
    int ns, ne, rc, std_fd, ext_fd, err = 0;

    rc = compile(st, std, &ns, ext, &ne);
    if (rc)
        return rc;

    std_fd = mfw_open_pinned(MFW_MAPS_DIR "/acl_std");
    ext_fd = mfw_open_pinned(MFW_MAPS_DIR "/acl_ext");
    if (std_fd < 0 || ext_fd < 0) {
        /* Not attached yet: attach materializes. */
        if (std_fd >= 0) close(std_fd);
        if (ext_fd >= 0) close(ext_fd);
        return EXIT_OK;
    }
    err = write_map(std_fd, std, ns, MFW_MAX_STD_ACES);
    if (!err)
        err = write_map(ext_fd, ext, ne, MFW_MAX_EXT_ACES);
    close(std_fd);
    close(ext_fd);
    if (err) {
        fprintf(stderr, "mfw: update ACL maps: %s\n", strerror(-err));
        return EXIT_KERNEL;
    }
    bump_generation();
    return EXIT_OK;
}

int mfw_materialize(void)
{
    struct state st;
    int rc = state_open(&st, 1);

    if (rc)
        return rc;
    rc = materialize_state(&st);
    state_close(&st);
    return rc;
}

int cmd_access_list(int argc, char **argv)
{
    struct mfw_rule r, *rules;
    struct state st;
    char err[160];
    int rc, count;
    __u32 key;

    rc = mfw_parse_ace(argc, argv, &r, err, sizeof(err));
    if (rc) {
        fprintf(stderr, "mfw: %s\n", err);
        return rc;
    }
    if ((rc = state_open(&st, 1)))
        return rc;

    if (r.seq == 0) {  /* Cisco default: last seq in list + 10 */
        int max = 0;

        rules = load_rules(&st, &count);
        for (int i = 0; rules && i < count; i++)
            if (rules[i].acl_id == r.acl_id && rules[i].seq > max)
                max = rules[i].seq;
        free(rules);
        if (max + 10 > 65534) {
            fprintf(stderr, "mfw: list %u: sequence numbers exhausted; give one explicitly\n",
                    r.acl_id);
            rc = EXIT_VALIDATION;
            goto out;
        }
        r.seq = max + 10;
    }
    key = mfw_db_key(r.acl_id, r.seq);
    r.rule_id = key;
    if (bpf_map_update_elem(st.db_fd, &key, &r, BPF_NOEXIST)) {
        if (errno == EEXIST)
            fprintf(stderr, "mfw: list %u already has sequence %u\n", r.acl_id, r.seq);
        else
            fprintf(stderr, "mfw: store ACE: %s\n", strerror(errno));
        rc = errno == EEXIST ? EXIT_VALIDATION : EXIT_KERNEL;
        goto out;
    }
    rc = materialize_state(&st);
    if (rc)  /* e.g. bound list now too long: undo */
        bpf_map_delete_elem(st.db_fd, &key);
out:
    state_close(&st);
    return rc;
}

int cmd_no_access_list(int argc, char **argv)
{
    struct mfw_rule *rules;
    struct state st;
    long acl, seq = -1;
    int rc, count, found = 0;
    char *end;

    if (argc < 1 || argc > 2) {
        fprintf(stderr, "usage: mfw no ip access-list <list> [<seq>]\n");
        return EXIT_USAGE;
    }
    acl = strtol(argv[0], &end, 10);
    if (*end || !(mfw_is_std(acl) || mfw_is_ext(acl))) {
        fprintf(stderr, "mfw: bad list number '%s'\n", argv[0]);
        return EXIT_VALIDATION;
    }
    if (argc == 2) {
        seq = strtol(argv[1], &end, 10);
        if (*end || seq < 1 || seq > 65535) {
            fprintf(stderr, "mfw: bad sequence number '%s'\n", argv[1]);
            return EXIT_VALIDATION;
        }
    }
    if ((rc = state_open(&st, 1)))
        return rc;
    rules = load_rules(&st, &count);
    for (int i = 0; rules && i < count; i++) {
        __u32 key;

        if (rules[i].acl_id != acl || (seq >= 0 && rules[i].seq != seq))
            continue;
        key = mfw_db_key(rules[i].acl_id, rules[i].seq);
        bpf_map_delete_elem(st.db_fd, &key);
        found++;
    }
    free(rules);
    if (!found) {
        fprintf(stderr, "mfw: no such %s\n", seq >= 0 ? "ACE" : "access list");
        rc = EXIT_VALIDATION;
    } else {
        rc = materialize_state(&st);  /* bindings stay, as on IOS */
    }
    state_close(&st);
    return rc;
}

static int slot_for(int acl)
{
    return mfw_is_std(acl) ? MFW_BIND_STD_IN : MFW_BIND_EXT_IN;
}

/* Only "in" exists: mini-fw protects the local host and does not filter egress. */
static int check_dir(const char *s)
{
    if (!strcmp(s, "in"))
        return 0;
    if (!strcmp(s, "out"))
        fprintf(stderr, "mfw: 'out' is not supported: egress is not filtered\n");
    else
        fprintf(stderr, "mfw: direction must be 'in'\n");
    return -1;
}

/* ip access-group <list> in <if>   |   no ip access-group [<list>] in <if> */
int cmd_access_group(int argc, char **argv, int negate)
{
    struct mfw_binding b[MFW_BIND_MAX], nb = {};
    struct state st;
    long acl = 0;
    int rc, i = 0;
    char *end;

    if (argc != 3 && !(negate && argc == 2)) {
        fprintf(stderr, negate ?
                "usage: mfw no ip access-group [<list>] in <ifname>\n" :
                "usage: mfw ip access-group <list> in <ifname>\n");
        return EXIT_USAGE;
    }
    if (argc == 3) {
        acl = strtol(argv[i++], &end, 10);
        if (*end || !(mfw_is_std(acl) || mfw_is_ext(acl))) {
            fprintf(stderr, "mfw: list number must be 1-99 or 100-199\n");
            return EXIT_VALIDATION;
        }
    }
    if (check_dir(argv[i++]))
        return EXIT_VALIDATION;
    const char *ifname = argv[i];

    if (!negate && !mfw_iface_attached(ifname)) {
        fprintf(stderr, "mfw: %s is not attached (run: mfw attach -i %s)\n", ifname, ifname);
        return EXIT_NOT_ATTACHED;
    }
    if ((rc = state_open(&st, 1)))
        return rc;
    load_bindings(&st, b);

    if (negate) {
        /* With a list number, unbind just that list; else unbind both. */
        for (__u32 s = 0; s < MFW_BIND_MAX; s++) {
            if (!b[s].acl_id || (acl && b[s].acl_id != acl))
                continue;
            bpf_map_update_elem(st.bind_fd, &s, &nb, BPF_ANY);
        }
        rc = materialize_state(&st);
        goto out;
    }

    __u32 s = slot_for(acl);

    if (b[s].acl_id && (b[s].acl_id != acl || strcmp(b[s].ifname, ifname)))
        fprintf(stderr, "mfw: note: replacing list %u (bound via %s); "
                        "bindings are host-global in v1\n", b[s].acl_id, b[s].ifname);
    nb.acl_id = (__u16)acl;
    snprintf(nb.ifname, sizeof(nb.ifname), "%s", ifname);
    if (bpf_map_update_elem(st.bind_fd, &s, &nb, BPF_ANY)) {
        fprintf(stderr, "mfw: store binding: %s\n", strerror(errno));
        rc = EXIT_KERNEL;
        goto out;
    }
    rc = materialize_state(&st);
    if (rc)  /* restore previous binding */
        bpf_map_update_elem(st.bind_fd, &s, &b[s], BPF_ANY);
out:
    state_close(&st);
    return rc;
}

static const char *slot_name[MFW_BIND_MAX] = {
    "standard in",
    "extended in",
};

int cmd_show_access_lists(int argc, char **argv)
{
    struct mfw_binding b[MFW_BIND_MAX];
    struct mfw_rule *rules;
    struct state st;
    long only = 0;
    int count, last = -1;
    char line[160];

    if (argc > 1) {
        fprintf(stderr, "usage: mfw show ip access-lists [<list>]\n");
        return EXIT_USAGE;
    }
    if (argc == 1)
        only = strtol(argv[0], NULL, 10);
    state_open(&st, 0);
    load_bindings(&st, b);
    rules = load_rules(&st, &count);
    for (int i = 0; rules && i < count; i++) {
        const struct mfw_rule *r = &rules[i];

        if (only && r->acl_id != only)
            continue;
        if (r->acl_id != last) {
            printf("%s IP access list %u", mfw_is_std(r->acl_id) ? "Standard" : "Extended",
                   r->acl_id);
            for (int s = 0; s < MFW_BIND_MAX; s++)
                if (b[s].acl_id == r->acl_id)
                    printf("  [in %s]", b[s].ifname);
            printf("\n");
            last = r->acl_id;
        }
        mfw_format_ace(r, line, sizeof(line));
        printf("    %u %s\n", r->seq, line);
    }
    free(rules);
    state_close(&st);
    return EXIT_OK;
}

int cmd_show_access_group(int argc, char **argv)
{
    struct mfw_binding b[MFW_BIND_MAX];
    struct state st;

    state_open(&st, 0);
    load_bindings(&st, b);
    state_close(&st);
    for (int s = 0; s < MFW_BIND_MAX; s++) {
        if (argc == 1 && b[s].acl_id && strcmp(b[s].ifname, argv[0]))
            continue;
        if (b[s].acl_id)
            printf("%-12s list %-3u (via %s)\n", slot_name[s], b[s].acl_id, b[s].ifname);
        else
            printf("%-12s not set (fail-open)\n", slot_name[s]);
    }
    return EXIT_OK;
}
