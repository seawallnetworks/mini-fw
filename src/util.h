
/* SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause */

/*
 * mfwd's helpers: error messages, directories.
 */


#ifndef _MFW_UTIL_H_INCLUDED_
#define _MFW_UTIL_H_INCLUDED_


#include <stddef.h>


/* Put the message in err; returns -1. */
int mfw_fail(char *err, size_t len, const char *fmt, ...)
    __attribute__((format(printf, 3, 4)));

/* mkdir -p, mode 0700. Returns 0, or -1 with errno set. */
int mfw_ensure_dir(const char *path);
/* Delete dir's entries (not recursively), then dir itself. */
void mfw_rm_dir(const char *dir);


#endif /* _MFW_UTIL_H_INCLUDED_ */
