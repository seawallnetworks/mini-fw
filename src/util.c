
/* SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause */

/*
 * mfwd's helpers: error messages, directories.
 */


#include "util.h"

#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>


int
mfw_fail(char *err, size_t len, const char *fmt, ...)
{
    va_list  ap;

    va_start(ap, fmt);
    vsnprintf(err, len, fmt, ap);
    va_end(ap);

    return -1;
}


int
mfw_ensure_dir(const char *path)
{
    char  *p;
    char   tmp[PATH_MAX];

    snprintf(tmp, sizeof(tmp), "%s", path);

    for (p = tmp + 1; *p != '\0'; p++) {
        if (*p != '/') {
            continue;
        }

        *p = '\0';

        if (mkdir(tmp, 0700) != 0 && errno != EEXIST) {
            return -1;
        }

        *p = '/';
    }

    if (mkdir(tmp, 0700) != 0 && errno != EEXIST) {
        return -1;
    }

    return 0;
}


void
mfw_rm_dir(const char *dir)
{
    DIR            *d;
    struct dirent  *de;
    char            path[PATH_MAX];

    d = opendir(dir);
    if (d == NULL) {
        return;
    }

    while ((de = readdir(d)) != NULL) {
        if (de->d_name[0] == '.') {
            continue;
        }

        snprintf(path, sizeof(path), "%s/%s", dir, de->d_name);
        unlink(path);
    }

    closedir(d);
    rmdir(dir);
}
