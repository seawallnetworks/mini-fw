
/* SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause */

/*
 * mfwd's helpers: error messages.
 */


#ifndef _MFW_UTIL_H_INCLUDED_
#define _MFW_UTIL_H_INCLUDED_


#include <stddef.h>


/* Put the message in err; returns -1. */
int mfw_fail(char *err, size_t len, const char *fmt, ...)
    __attribute__((format(printf, 3, 4)));

/*
 * Logs, once, that an interface couldn't be looked up (sw_netif_index()
 * returned -1, with err): glibc's if_nametoindex() needs AF_UNIX, and
 * every interface fails alike until the unit allows it.
 */
void mfw_netif_unknown(const char *err);


#endif /* _MFW_UTIL_H_INCLUDED_ */
