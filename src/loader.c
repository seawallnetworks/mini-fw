// SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
/* attach / detach: one XDP program per interface, shared map pins.
 * Egress is not filtered, so nothing is attached to TC. */
#include <dirent.h>
#include <errno.h>
#include <getopt.h>
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <unistd.h>
#include <linux/if_link.h>
#include <linux/magic.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "mfw_cli.h"
#include "mfw.skel.h"

int mfw_ensure_dir(const char *path)
{
    char tmp[256];
    char *p;

    snprintf(tmp, sizeof(tmp), "%s", path);
    for (p = tmp + 1; *p; p++) {
        if (*p != '/')
            continue;
        *p = '\0';
        if (mkdir(tmp, 0700) && errno != EEXIST)
            return -errno;
        *p = '/';
    }
    if (mkdir(tmp, 0700) && errno != EEXIST)
        return -errno;
    return 0;
}

int mfw_open_pinned(const char *path)
{
    int fd = bpf_obj_get(path);

    return fd < 0 ? -errno : fd;
}

static void link_path(char *buf, size_t len, const char *ifname)
{
    snprintf(buf, len, MFW_LINK_DIR "/xdp_%s", ifname);
}

int mfw_iface_attached(const char *ifname)
{
    char path[128];

    link_path(path, sizeof(path), ifname);
    return access(path, F_OK) == 0;
}

static int check_bpffs(void)
{
    struct statfs st;

    if (statfs("/sys/fs/bpf", &st) || st.f_type != BPF_FS_MAGIC) {
        fprintf(stderr, "mfw: bpffs is not mounted at /sys/fs/bpf "
                        "(mount -t bpf bpf /sys/fs/bpf)\n");
        return -1;
    }
    return 0;
}

static int init_config(struct mfw_bpf *skel)
{
    int fd = bpf_map__fd(skel->maps.config);
    struct mfw_config cfg;
    __u32 k = 0;

    if (bpf_map_lookup_elem(fd, &k, &cfg))
        return -errno;
    if (cfg.abi_version == MFW_ABI_VERSION)
        return 0;  /* reused pins: keep operator settings */
    if (cfg.abi_version != 0) {
        fprintf(stderr, "mfw: pinned maps have ABI %u, expected %u "
                        "(detach --purge-maps first)\n",
                cfg.abi_version, MFW_ABI_VERSION);
        return -EINVAL;
    }
    memset(&cfg, 0, sizeof(cfg));
    cfg.default_action = MFW_ACTION_DENY;
    cfg.abi_version = MFW_ABI_VERSION;
    return bpf_map_update_elem(fd, &k, &cfg, BPF_ANY) ? -errno : 0;
}

static int attach_xdp(int prog_fd, int ifindex, const char *ifname,
                      const char *mode)
{
    char path[128];
    __u32 modes[2];
    int n = 0, i, fd, err = 0;

    link_path(path, sizeof(path), ifname);
    fd = bpf_obj_get(path);
    if (fd >= 0) {
        /* Replace: atomically swap the program behind the existing link. */
        err = bpf_link_update(fd, prog_fd, NULL) ? -errno : 0;
        close(fd);
        if (err)
            fprintf(stderr, "mfw: XDP link update on %s: %s\n", ifname, strerror(-err));
        return err;
    }

    if (!strcmp(mode, "native") || !strcmp(mode, "auto"))
        modes[n++] = XDP_FLAGS_DRV_MODE;
    if (!strcmp(mode, "generic") || !strcmp(mode, "auto"))
        modes[n++] = XDP_FLAGS_SKB_MODE;

    for (i = 0; i < n; i++) {
        LIBBPF_OPTS(bpf_link_create_opts, opts, .flags = modes[i]);

        fd = bpf_link_create(prog_fd, ifindex, BPF_XDP, &opts);
        if (fd >= 0)
            break;
        err = -errno;
    }
    if (fd < 0) {
        fprintf(stderr, "mfw: XDP attach on %s (%s): %s\n", ifname, mode, strerror(-err));
        return err;
    }
    err = bpf_obj_pin(fd, path) ? -errno : 0;
    if (err)
        fprintf(stderr, "mfw: pin %s: %s\n", path, strerror(-err));
    close(fd);  /* pin keeps the link alive */
    return err;
}

static int libbpf_print(enum libbpf_print_level level, const char *fmt, va_list ap)
{
    if (level == LIBBPF_DEBUG && !getenv("MFW_DEBUG"))
        return 0;
    return vfprintf(stderr, fmt, ap);
}

int cmd_attach(int argc, char **argv)
{
    static const struct option longopts[] = {
        { "interface", required_argument, NULL, 'i' },
        { "xdp-mode",  required_argument, NULL, 'm' },
        { 0 },
    };
    const char *ifname = NULL, *mode = "auto";
    struct mfw_bpf *skel;
    int c, ifindex, err;

    optind = 1;
    while ((c = getopt_long(argc, argv, "i:", longopts, NULL)) != -1) {
        switch (c) {
        case 'i': ifname = optarg; break;
        case 'm': mode = optarg; break;
        default:  return EXIT_USAGE;
        }
    }
    if (!ifname || (strcmp(mode, "auto") && strcmp(mode, "native") &&
                    strcmp(mode, "generic"))) {
        fprintf(stderr, "usage: mfw attach -i <ifname> [--xdp-mode native|generic|auto]\n");
        return EXIT_USAGE;
    }
    ifindex = if_nametoindex(ifname);
    if (!ifindex) {
        fprintf(stderr, "mfw: no such interface '%s'\n", ifname);
        return EXIT_VALIDATION;
    }
    if (check_bpffs())
        return EXIT_KERNEL;
    if (mfw_ensure_dir(MFW_MAPS_DIR) || mfw_ensure_dir(MFW_LINK_DIR)) {
        fprintf(stderr, "mfw: cannot create %s: %s\n", MFW_PIN_PATH, strerror(errno));
        return EXIT_KERNEL;
    }

    libbpf_set_print(libbpf_print);
    LIBBPF_OPTS(bpf_object_open_opts, oopts, .pin_root_path = MFW_MAPS_DIR);
    skel = mfw_bpf__open_opts(&oopts);
    if (!skel) {
        fprintf(stderr, "mfw: open BPF object: %s\n", strerror(errno));
        return EXIT_KERNEL;
    }
    err = mfw_bpf__load(skel);  /* reuses pinned maps, pins new ones */
    if (err) {
        fprintf(stderr, "mfw: load BPF object: %s\n", strerror(-err));
        goto out;
    }
    if ((err = init_config(skel)) ||
        (err = attach_xdp(bpf_program__fd(skel->progs.mfw_xdp), ifindex, ifname, mode)))
        goto out;
    mfw_bpf__destroy(skel);
    skel = NULL;

    err = mfw_materialize();
    if (err)
        return err;
    printf("attached to %s\n", ifname);
    return EXIT_OK;
out:
    mfw_bpf__destroy(skel);
    return EXIT_KERNEL;
}

/* Other interfaces still attached (besides ifname)? */
static int others_attached(const char *ifname)
{
    char self[64];
    struct dirent *de;
    DIR *d = opendir(MFW_LINK_DIR);
    int n = 0;

    if (!d)
        return 0;
    snprintf(self, sizeof(self), "xdp_%s", ifname);
    while ((de = readdir(d)))
        if (!strncmp(de->d_name, "xdp_", 4) && strcmp(de->d_name, self))
            n++;
    closedir(d);
    return n;
}

static void rm_dir_files(const char *dir)
{
    char path[512];
    struct dirent *de;
    DIR *d = opendir(dir);

    if (!d)
        return;
    while ((de = readdir(d))) {
        if (de->d_name[0] == '.')
            continue;
        snprintf(path, sizeof(path), "%s/%s", dir, de->d_name);
        unlink(path);
    }
    closedir(d);
    rmdir(dir);
}

int cmd_detach(int argc, char **argv)
{
    static const struct option longopts[] = {
        { "interface",  required_argument, NULL, 'i' },
        { "purge-maps", no_argument,       NULL, 'p' },
        { 0 },
    };
    const char *ifname = NULL;
    int c, purge = 0;
    char path[128];

    optind = 1;
    while ((c = getopt_long(argc, argv, "i:", longopts, NULL)) != -1) {
        switch (c) {
        case 'i': ifname = optarg; break;
        case 'p': purge = 1; break;
        default:  return EXIT_USAGE;
        }
    }
    if (!ifname) {
        fprintf(stderr, "usage: mfw detach -i <ifname> [--purge-maps]\n");
        return EXIT_USAGE;
    }
    if (purge && others_attached(ifname)) {
        fprintf(stderr, "mfw: --purge-maps refused: other interfaces are still attached\n");
        return EXIT_VALIDATION;
    }

    /* Best effort: tolerate a vanished interface. */
    link_path(path, sizeof(path), ifname);
    unlink(path);  /* last reference → kernel detaches XDP */

    if (purge) {
        rm_dir_files(MFW_MAPS_DIR);
        rm_dir_files(MFW_STATE_DIR);
        rm_dir_files(MFW_LINK_DIR);
        rmdir(MFW_PIN_PATH);
    }
    printf("detached from %s%s\n", ifname, purge ? " (maps purged)" : "");
    return EXIT_OK;
}
