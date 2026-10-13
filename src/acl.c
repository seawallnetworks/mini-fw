// SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
/* ACL store (userspace-only pinned maps) and materialization into the
 * per-interface rulesets.
 *
 * state/acl_db   HASH  mfw_db_key(acl, seq) → mfw_rule   every defined ACE
 * state/bindings HASH  ifindex → mfw_binding             ip access-group
 * maps/rulesets  HASH_OF_MAPS  ifindex → inner map holding one
 *                mfw_ruleset, read by XDP
 *
 * The state maps live on bpffs, so lists can be defined before attach and
 * survive process exit without a config file; reboot clears them (as with
 * all pins). An installed ruleset is never written again: a change builds
 * a new inner map and swaps it in, so each packet sees one whole ruleset.
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

/* one entry of state/bindings */
struct bind_ent {
    __u32 ifindex;
    struct mfw_binding b;
};

/* A pin left by an older mini-fw has another layout: refuse it. */
static int check_layout(int fd, const char *path, enum bpf_map_type type,
                        __u32 vsize)
{
    struct bpf_map_info info = {};
    __u32 len = sizeof(info);

    if (bpf_map_get_info_by_fd(fd, &info, &len))
        return -errno;
    if (info.type == type && info.value_size == vsize)
        return 0;
    fprintf(stderr, "mfw: %s is from an older mini-fw "
                    "(detach --purge-maps first)\n", path);
    return -EINVAL;
}

static int open_or_create(const char *path, enum bpf_map_type type,
                          const char *name, __u32 vsize, __u32 max, int create)
{
    int fd = bpf_obj_get(path);

    if (fd >= 0) {
        int err = check_layout(fd, path, type, vsize);

        if (err) {
            close(fd);
            return err;
        }
        return fd;
    }
    if (!create)
        return -errno;
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
    st->bind_fd = open_or_create(MFW_STATE_DIR "/bindings", BPF_MAP_TYPE_HASH,
                                 "mfw_bindings", sizeof(struct mfw_binding),
                                 MFW_MAX_IFACES, create);
    if (create && (st->db_fd < 0 || st->bind_fd < 0)) {
        int err = st->db_fd < 0 ? st->db_fd : st->bind_fd;

        if (err != -EINVAL)
            fprintf(stderr, "mfw: cannot open ACL store under %s: %s "
                            "(is bpffs mounted? are you root?)\n",
                    MFW_STATE_DIR, strerror(-err));
        if (st->db_fd >= 0)
            close(st->db_fd);
        if (st->bind_fd >= 0)
            close(st->bind_fd);
        return err == -EINVAL ? EXIT_VALIDATION : EXIT_KERNEL;
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

static int bind_cmp(const void *a, const void *b)
{
    const struct bind_ent *x = a, *y = b;

    return strcmp(x->b.ifname, y->b.ifname);
}

/* Every interface's bindings, sorted by name; returns how many. */
static int load_bindings(const struct state *st, struct bind_ent out[MFW_MAX_IFACES])
{
    __u32 key, next, *prev = NULL;
    int n = 0;

    if (st->bind_fd < 0)
        return 0;
    while (n < MFW_MAX_IFACES && bpf_map_get_next_key(st->bind_fd, prev, &next) == 0) {
        if (bpf_map_lookup_elem(st->bind_fd, &next, &out[n].b) == 0) {
            out[n].ifindex = next;
            n++;
        }
        key = next;
        prev = &key;
    }
    qsort(out, n, sizeof(*out), bind_cmp);
    return n;
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

/* Bumps and returns the generation stamped on new rulesets (0 if not
 * attached). */
static __u32 bump_generation(void)
{
    int fd = mfw_open_pinned(MFW_MAPS_DIR "/config");
    struct mfw_config cfg;
    __u32 k = 0, gen = 0;

    if (fd < 0)
        return 0;
    if (bpf_map_lookup_elem(fd, &k, &cfg) == 0) {
        gen = ++cfg.generation;
        bpf_map_update_elem(fd, &k, &cfg, BPF_ANY);
    }
    close(fd);
    return gen;
}

/* Append list `acl` ACEs to out[0..n). Returns the new n, or -1 if full. */
static int append_list(struct mfw_rule *out, int n, int max,
                       const struct mfw_rule *rules, int count, __u16 acl)
{
    for (int i = 0; i < count; i++) {
        if (rules[i].acl_id != acl)
            continue;
        if (n >= max)
            return -1;
        out[n] = rules[i];
        out[n].direction = MFW_DIR_INGRESS;
        n++;
    }
    return n;
}

/* One interface's ruleset from its bindings. Returns 0 or EXIT_VALIDATION. */
static int compile(const struct mfw_binding *b, const struct mfw_rule *rules,
                   int count, struct mfw_ruleset *rs)
{
    int n;

    memset(rs, 0, sizeof(*rs));
    rs->std_acl = b->std_acl;
    rs->ext_acl = b->ext_acl;

    /* Standard: blacklist, no implicit deny. */
    if (b->std_acl) {
        n = append_list(rs->std, 0, MFW_MAX_STD_ACES, rules, count, b->std_acl);
        if (n < 0) {
            fprintf(stderr, "mfw: %s: standard list %u exceeds %d ACEs\n",
                    b->ifname, b->std_acl, MFW_MAX_STD_ACES);
            return EXIT_VALIDATION;
        }
        rs->n_std = n;
    }

    /* Extended: BPF denies when it runs off the end, so a bound-but-empty
     * list still denies. */
    if (b->ext_acl) {
        n = append_list(rs->ext, 0, MFW_MAX_EXT_ACES, rules, count, b->ext_acl);
        if (n < 0) {
            fprintf(stderr, "mfw: %s: extended list %u exceeds %d ACEs\n",
                    b->ifname, b->ext_acl, MFW_MAX_EXT_ACES);
            return EXIT_VALIDATION;
        }
        rs->n_ext = n;
    }
    return EXIT_OK;
}

/* Swap rs in for ifindex: a new inner map, filled, then one outer update. */
static int install(int outer_fd, __u32 ifindex, const struct mfw_ruleset *rs)
{
    __u32 zero = 0;
    int fd, err = 0;

    fd = bpf_map_create(BPF_MAP_TYPE_ARRAY, "mfw_ruleset", sizeof(__u32),
                        sizeof(*rs), 1, NULL);
    if (fd < 0)
        return -errno;
    if (bpf_map_update_elem(fd, &zero, rs, BPF_ANY) ||
        bpf_map_update_elem(outer_fd, &ifindex, &fd, BPF_ANY))
        err = -errno;
    close(fd);  /* the outer map holds the inner map now */
    return err;
}

/* Is ifindex one of the n interfaces that got a ruleset? */
static int installed(const __u32 *ifs, int n, __u32 ifindex)
{
    for (int i = 0; i < n; i++)
        if (ifs[i] == ifindex)
            return 1;
    return 0;
}

/*
 * Every attached interface with bindings gets its ruleset; every other
 * entry in maps/rulesets is removed (fail-open). All rulesets are compiled
 * first, so a validation error changes nothing.
 */
static int materialize_state(const struct state *st)
{
    struct bind_ent b[MFW_MAX_IFACES];
    struct mfw_ruleset *rs = NULL;
    struct mfw_rule *rules = NULL;
    __u32 ifs[MFW_MAX_IFACES], last, next, gen;
    int nb, n = 0, count, outer_fd, rc = EXIT_OK, err, kept = 0;
    char name[IF_NAMESIZE];

    outer_fd = mfw_open_pinned(MFW_MAPS_DIR "/rulesets");
    if (outer_fd < 0)
        return EXIT_OK;  /* not attached yet: attach materializes */

    nb = load_bindings(st, b);
    rules = load_rules(st, &count);
    rs = calloc(MFW_MAX_IFACES, sizeof(*rs));
    if (!rules || !rs) {
        rc = EXIT_KERNEL;
        goto out;
    }

    for (int i = 0; i < nb; i++) {
        /* only attached interfaces whose ifindex still has that name */
        if (!mfw_iface_attached(b[i].b.ifname) || !if_indextoname(b[i].ifindex, name) ||
            strcmp(name, b[i].b.ifname))
            continue;
        rc = compile(&b[i].b, rules, count, &rs[n]);
        if (rc)
            goto out;
        ifs[n++] = b[i].ifindex;
    }

    gen = bump_generation();
    for (int i = 0; i < n; i++) {
        rs[i].generation = gen;
        err = install(outer_fd, ifs[i], &rs[i]);
        if (err) {
            fprintf(stderr, "mfw: install ruleset: %s\n", strerror(-err));
            rc = EXIT_KERNEL;
            goto out;
        }
    }

    /* drop rulesets of interfaces that lost their bindings */
    while (bpf_map_get_next_key(outer_fd, kept ? &last : NULL, &next) == 0) {
        if (!installed(ifs, n, next) && bpf_map_delete_elem(outer_fd, &next) == 0)
            continue;  /* deleted: carry on after the last key kept */
        last = next;
        kept = 1;
    }
out:
    free(rs);
    free(rules);
    close(outer_fd);
    return rc;
}

/* Removes ifindex's ruleset, e.g. on detach. Nothing to do if not attached. */
void mfw_forget_iface(__u32 ifindex)
{
    int fd = mfw_open_pinned(MFW_MAPS_DIR "/rulesets");

    if (fd < 0)
        return;
    bpf_map_delete_elem(fd, &ifindex);
    close(fd);
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

/* The binding stored for ifname: by its ifindex, or by name if the
 * interface is gone. Returns 1 and fills *ifindex / *b if found. */
static int find_binding(const struct state *st, const char *ifname,
                        __u32 *ifindex, struct mfw_binding *b)
{
    struct bind_ent all[MFW_MAX_IFACES];
    int n = load_bindings(st, all);

    for (int i = 0; i < n; i++) {
        if (strcmp(all[i].b.ifname, ifname))
            continue;
        *ifindex = all[i].ifindex;
        *b = all[i].b;
        return 1;
    }
    return 0;
}

/* Stores b for ifindex, or deletes the entry when nothing is bound. */
static int store_binding(const struct state *st, __u32 ifindex,
                         const struct mfw_binding *b)
{
    if (!b->std_acl && !b->ext_acl)
        return bpf_map_delete_elem(st->bind_fd, &ifindex) && errno != ENOENT ? -errno : 0;
    return bpf_map_update_elem(st->bind_fd, &ifindex, b, BPF_ANY) ? -errno : 0;
}

/*
 * ip access-group <list> in <if>   |   no ip access-group [<list>] in <if>
 *
 * Each interface has one standard and one extended slot; binding a list
 * replaces the one of the same kind on that interface only.
 */
int cmd_access_group(int argc, char **argv, int negate)
{
    struct mfw_binding old = {}, nb;
    struct state st;
    __u32 ifindex = 0;
    long acl = 0;
    int rc, had, i = 0, err;
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

    if (strlen(ifname) >= sizeof(nb.ifname)) {
        fprintf(stderr, "mfw: interface name too long: %s\n", ifname);
        return EXIT_VALIDATION;
    }
    if (!negate && !mfw_iface_attached(ifname)) {
        fprintf(stderr, "mfw: %s is not attached (run: mfw attach -i %s)\n", ifname, ifname);
        return EXIT_NOT_ATTACHED;
    }
    if ((rc = state_open(&st, 1)))
        return rc;
    had = find_binding(&st, ifname, &ifindex, &old);

    if (negate) {
        if (!had) {
            rc = EXIT_OK;  /* nothing bound there */
            goto out;
        }
        /* With a list number, unbind just that list; else unbind both. */
        nb = old;
        if (!acl || nb.std_acl == acl)
            nb.std_acl = 0;
        if (!acl || nb.ext_acl == acl)
            nb.ext_acl = 0;
    } else {
        __u32 now = if_nametoindex(ifname);

        if (!now) {
            fprintf(stderr, "mfw: no such interface '%s'\n", ifname);
            rc = EXIT_VALIDATION;
            goto out;
        }
        if (had && ifindex != now)  /* re-created under a new ifindex */
            bpf_map_delete_elem(st.bind_fd, &ifindex);
        ifindex = now;
        nb = had ? old : (struct mfw_binding){};
        snprintf(nb.ifname, sizeof(nb.ifname), "%s", ifname);
        if (mfw_is_std(acl))
            nb.std_acl = acl;
        else
            nb.ext_acl = acl;
    }

    err = store_binding(&st, ifindex, &nb);
    if (err) {
        fprintf(stderr, "mfw: store binding: %s\n", strerror(-err));
        rc = EXIT_KERNEL;
        goto out;
    }
    rc = materialize_state(&st);
    if (rc)  /* e.g. list too long: restore the previous binding */
        store_binding(&st, ifindex, had ? &old : &(struct mfw_binding){});
out:
    state_close(&st);
    return rc;
}

int cmd_show_access_lists(int argc, char **argv)
{
    struct bind_ent b[MFW_MAX_IFACES];
    struct mfw_rule *rules;
    struct state st;
    long only = 0;
    int nb, count, last = -1;
    char line[160];

    if (argc > 1) {
        fprintf(stderr, "usage: mfw show ip access-lists [<list>]\n");
        return EXIT_USAGE;
    }
    if (argc == 1)
        only = strtol(argv[0], NULL, 10);
    if (state_open(&st, 0) == EXIT_OK) {
        nb = load_bindings(&st, b);
        rules = load_rules(&st, &count);
    } else {
        nb = count = 0;
        rules = NULL;
    }
    for (int i = 0; rules && i < count; i++) {
        const struct mfw_rule *r = &rules[i];

        if (only && r->acl_id != only)
            continue;
        if (r->acl_id != last) {
            printf("%s IP access list %u", mfw_is_std(r->acl_id) ? "Standard" : "Extended",
                   r->acl_id);
            for (int j = 0; j < nb; j++)
                if (b[j].b.std_acl == r->acl_id || b[j].b.ext_acl == r->acl_id)
                    printf("  [in %s]", b[j].b.ifname);
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

static void print_list(__u16 acl)
{
    if (acl)
        printf("  %-11u", acl);
    else
        printf("  %-11s", "-");
}

int cmd_show_access_group(int argc, char **argv)
{
    struct bind_ent b[MFW_MAX_IFACES];
    struct state st;
    int n = 0, shown = 0;

    if (argc > 1) {
        fprintf(stderr, "usage: mfw show ip access-group [<ifname>]\n");
        return EXIT_USAGE;
    }
    if (state_open(&st, 0) == EXIT_OK)
        n = load_bindings(&st, b);
    state_close(&st);

    for (int i = 0; i < n; i++) {
        if (argc == 1 && strcmp(b[i].b.ifname, argv[0]))
            continue;
        if (!shown++)
            printf("%-15s  %-11s  %s\n", "Interface", "Standard in", "Extended in");
        printf("%-15s", b[i].b.ifname);
        print_list(b[i].b.std_acl);
        print_list(b[i].b.ext_acl);
        printf("%s\n", mfw_iface_attached(b[i].b.ifname) ? "" : "  (not attached)");
    }
    if (!shown)
        printf("No access-group set%s%s: fail-open\n", argc == 1 ? " on " : "",
               argc == 1 ? argv[0] : "");
    return EXIT_OK;
}
