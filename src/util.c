
/* SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause */

/*
 * mfwd's helpers: error messages.
 */


#include "util.h"

#include <sw/log.h>

#include <stdarg.h>
#include <stdio.h>


int
mfw_fail(char *err, size_t len, const char *fmt, ...)
{
    va_list  ap;

    va_start(ap, fmt);
    vsnprintf(err, len, fmt, ap);
    va_end(ap);

    return -1;
}


void
mfw_netif_unknown(const char *err)
{
    static int  said;

    if (!said) {
        sw_log_warn("%s: no interface is attached or detached until it can",
                    err);
        said = 1;
    }
}
