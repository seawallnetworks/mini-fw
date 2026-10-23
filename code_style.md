# mini-fw C style

Formatting follows the nginx Code style chapter:

https://nginx.org/en/docs/dev/development_guide.html#code_style

This file is mini-fw's version: same rules, `mfw_` / `MFW_` names, and
the deviations in the last section. It is voidgate's guide, adjusted:
both projects in the Seawall stack read the same way.

Hand-written C and H in `src/`, `src/bpf/`, `include/` and `tests/`
follow this guide. Makefile recipes stay tab-indented (required by make).
Do not hand-edit `src/mfw.skel.h` (bpftool generates it).

Existing files may still lag some of these rules. New code should match
this document. Do not mix a partial restyle into an unrelated change.

## General rules

- Maximum text width is 80 characters.
- Indentation is 4 spaces.
- No tabs, no trailing spaces.
- List elements on the same line are separated with spaces.
- Hexadecimal literals are lowercase.
- Function and type names, and global variables have the `mfw_` prefix,
  or a more specific one such as `mfw_dp_`; the daemon's own use
  `mfwd_`. Public headers in `include/` are named `mfw*.h`; files in
  `src/` are not prefixed.

```c
static int
mfw_rule_find(const struct mfw_ruleset *rs, __u32 rule_id)
{
    int  i;

    for (i = 0; i < rs->n_ext; i++) {
        if (rs->ext[i].rule_id == rule_id) {
            return i;
        }
    }

    return -1;
}
```

## Files

A typical source file may contain the following sections, separated by
two empty lines, except for the license spacing described below:

- SPDX license comment
- includes
- preprocessor definitions
- type definitions
- function prototypes
- variable definitions
- function definitions

All of mini-fw is `GPL-2.0-only OR BSD-2-Clause`: userspace, the BPF
program, the shared header and the tests alike. Hand-written C sources
and headers begin with one empty line, the license comment, and one
empty line. A file's description comment follows it:

```c

/* SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause */

/*
 * The BPF side of mfwd: pinned maps, XDP and TC attachments, rulesets,
 * counters.
 */
```

Project headers come first, then system and library headers:

```c
#include "dataplane.h"
#include "mfw.skel.h"

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <string.h>
#include <xdp/libxdp.h>
```

A file that needs a feature macro (`#define _GNU_SOURCE`) defines it
before every include.

Header files use include guards:

```c
#ifndef _MFW_POLICY_H_INCLUDED_
#define _MFW_POLICY_H_INCLUDED_
...
#endif /* _MFW_POLICY_H_INCLUDED_ */
```

## Comments

- `//` comments are not used.
- Text is written in English; American spelling is preferred.
- Multi-line comments are formatted like this:

```c
/*
 * Standard ACEs match the source only; a miss passes. Extended ACEs end
 * in a synthetic "deny ip any any" when the list is bound.
 */

/* the dispatcher's pins keep mfw_xdp attached while mfwd is down */
```

## Preprocessor

Macro names start with `mfw_` or `MFW_` (or a more specific prefix,
such as `MFWD_`). Constant macros are uppercase. Parameterized macros
and initializer macros are lowercase. The macro name and value are
separated by at least two spaces:

```c
#define MFW_MAX_EXT_ACES  128

#define mfw_dp_hook(dp)  ((dp)->no_xdp ? "tc" : "xdp")

#define mfw_cidr_host(c, a)                                              \
    do {                                                                 \
        (c)->addr = (a);                                                 \
        (c)->prefix = 32;                                                \
    } while (0)
```

`#if` conditions are inside parentheses; negation is outside:

```c
#if (MFW_DEBUG)
...
#elif (defined(BPF_F_BEFORE) && !(MFW_NO_TCX))
...
#else /* no BPF_F_BEFORE */
...
#endif /* MFW_DEBUG */
```

## Types

Type names end with the `_t` suffix. A defined type name is separated
by at least two spaces:

```c
typedef __u32  mfw_gen_t;
```

Structure types are defined using `typedef`. Inside structures, member
types and names are aligned:

```c
typedef struct {
    const char  *socket_path;
    int          timeout_ms;
} mfw_client_t;
```

Keep alignment identical among different structures in the file. A
structure that points to itself has a name ending with `_s`. Adjacent
structure definitions are separated with two empty lines:

```c
typedef struct mfw_conn_s  mfw_conn_t;

struct mfw_conn_s {
    int              fd;
    size_t           len;
    time_t           deadline;
    mfw_conn_t      *next;
};


typedef struct {
    mfw_conn_t      *free;
    unsigned         nconns;
} mfw_conn_pool_t;
```

Each structure member is declared on its own line.

Function pointers inside structures have defined types ending with
`_pt`:

```c
typedef int (*mfw_attach_pt)(struct mfw_dp *dp, const char *ifname,
    int ifindex);

typedef struct {
    mfw_attach_pt    attach;
    mfw_attach_pt    detach;
} mfw_hook_ops_t;
```

Enumerations have types ending with `_e`:

```c
typedef enum {
    mfw_hook_xdp = 0,
    mfw_hook_tc
} mfw_hook_e;
```

The public headers keep the types they have, whatever this section
says; see [mini-fw notes](#mini-fw-notes).

## Variables

Variables are declared sorted by length of a base type, then
alphabetically. Type names and variable names are aligned. The type and
name columns are separated with two spaces. Large arrays are put at the
end of a declaration block:

```c
int                     fd, i, n;
__u32                   key;
size_t                  len;
struct mfw_rule        *r;
struct mfw_ruleset      rs;
char                    path[PATH_MAX];
```

Static and global variables may be initialized on declaration:

```c
static const char  *mfwd_sock = MFW_SOCKET;

static int  mfwd_purge = 0;
```

## Functions

All functions (even static ones) should have prototypes. Prototypes
include argument names. Long prototypes are wrapped with a single
indentation on continuation lines:

```c
static int mfw_xdp_bpffs_mounted(void);
static int fail(char *err, size_t errlen, const char *fmt, ...);

int mfw_dp_open(struct mfw_dp *dp, const char *root, char *err,
    size_t errlen);
int mfw_dp_attach(struct mfw_dp *dp, const char *ifname, char *err,
    size_t errlen);
```

The function name in a definition starts on a new line. The function
body opening and closing braces are on separate lines. The body is
indented. There are two empty lines between functions:

```c
static int
mfw_xdp_bpffs_mounted(void)
{
    const char     *dir;
    struct statfs   st;

    dir = getenv("LIBXDP_BPFFS");
    if (dir == NULL) {
        dir = "/sys/fs/bpf";
    }

    return statfs(dir, &st) == 0 && st.f_type == BPF_FS_MAGIC;
}


int
mfw_dp_attach(struct mfw_dp *dp, const char *ifname, char *err,
    size_t errlen)
{
    ...
}
```

There is no space after the function name and the opening parenthesis.
Long function calls are wrapped so continuation lines start from the
position of the first argument. If that is impossible, format the first
continuation line so it ends at position 79:

```c
    return fail(err, errlen, "%s: attach XDP: %s", ifname,
                strerror(-e));

    fprintf(stderr, "mfwd: %s: %s holds the XDP hook\n",
            ifname, holder);

    e = bpf_map_update_elem(dp->rulesets_fd, &key, rs,
                                         BPF_ANY);
```

Put an empty line before the last `return` of a function, unless it is
the only statement in the body. Early `return`s inside an `if` / `else`
or loop body do not need one:

```c
static struct group *
find_group(const char *name)
{
    FILE          *f;
    struct group  *g;

    f = fopen("/etc/group", "re");
    if (f == NULL) {
        return NULL;
    }

    while ((g = fgetgrent(f)) != NULL && strcmp(g->gr_name, name) != 0)
        /* void */ ;

    fclose(f);

    return g;
}


int
mfw_abi_version(void)
{
    return MFW_ABI_VERSION;
}
```

Prefer `static inline` in headers. Do not use a bare `inline` without
`static` in a header.

## Expressions

Binary operators except `.` and `->` are separated from their operands
by one space. Unary operators and subscripts are not:

```c
    port = port * 10 + (*p++ - '0');

    r->src.prefix = (__u8) (plen < 0 ? 32 : plen);

    rs = &dp->rulesets[i + 1];
```

Type casts are separated by one space from the cast expression. An
asterisk inside a type cast is separated with a space from the type
name:

```c
    if (bind(fd, (struct sockaddr *) &sun, sizeof(sun)) < 0) {
        close(fd);
        return -1;
    }
```

If an expression does not fit on a single line, wrap it. The preferred
point to break is a binary operator. Put that operator at the start of
the continuation line. Line the continuation up with the start of the
expression (the first token after `if (` or the `(` of a call), not a
fixed extra indent:

```c
        if (r->proto == MFW_PROTO_TCP
            || r->proto == MFW_PROTO_UDP)
        {
            ...
        }

        msg = "mfwd refuses XDP without bpffs at /sys/fs/bpf: "
              "libxdp would take the hook alone";
```

As a last resort, wrap so the continuation line ends at position 79:

```c
    need = sizeof(struct mfw_ruleset)
                               + (size_t) n * sizeof(struct mfw_rule);
```

The same rules apply to sub-expressions; each sub-expression has its
own indentation level:

```c
    if (((r->proto == MFW_PROTO_TCP && (r->flags & MFW_RULE_F_ESTABLISHED))
         || r->proto == MFW_PROTO_ICMP) && r->action == MFW_ACTION_PERMIT
        && r->kind == MFW_ACL_EXTENDED)
    {
        ...
    }
```

Sometimes it is convenient to wrap after a cast. In that case the
continuation line is indented:

```c
    sin = (struct sockaddr_in *)
              ((__u8 *) sa + offsetof(struct sockaddr_in, sin_addr));
```

Pointers are compared to `NULL` (not `0`):

```c
    if (dp->skel != NULL) {
        ...
    }
```

## Conditionals and loops

The `if` keyword is separated from the condition by one space. The
opening brace is on the same line, or on a dedicated line if the
condition takes several lines. The closing brace is on a dedicated
line, optionally followed by `else if` / `else`. Usually there is an
empty line before the `else if` / `else` part:

```c
    if (e == 0) {
        return 0;

    } else if (e == -ENOTSUP) {
        return fail(err, errlen, "%s: attach XDP: libxdp needs bpffs "
                    "at /sys/fs/bpf", ifname);

    } else if (e < 0) {
        return fail(err, errlen, "%s: attach XDP: %s", ifname,
                    strerror(-e));
    }
```

Always put braces on `if` / `else` / `for` bodies, even one-liners.

When an `if` / `else if` / `while` / `for` condition wraps, put `{` on
the next line at the `if` indent. A one-line condition keeps `) {`.

Put a blank line before and after an `if` / `else` chain or a `for`
when it sits next to another statement. Do not insert that blank
against the enclosing `{` or `}`:

```c
    slash = strchr(tmp, '/');

    if (slash != NULL) {
        *slash = '\0';
        plen = atoi(slash + 1);

    } else {
        plen = -1;
    }

    if (inet_pton(AF_INET, tmp, &c->addr) != 1) {
        return -1;
    }
```

Similar formatting applies to `do` and `while`. A `while` whose body is
a single statement may omit braces:

```c
    while (p < last && *p == ' ') {
        p++;
    }

    while (p < last && *p == ' ')
        p++;

    do {
        n = read(fd, buf + len, sizeof(buf) - len);
        len += n;
    } while (n > 0);
```

The `switch` keyword is separated from the condition by one space. The
opening brace is on the same line. `case` labels line up with `switch`:

```c
    switch (r->proto) {
    case MFW_PROTO_TCP:
        name = "tcp";
        break;

    case MFW_PROTO_UDP:
        name = "udp";
        break;

    default:
        name = "ip";
        break;
    }
```

Most `for` loops are formatted like this:

```c
    for (i = 0; i < rs->n_ext; i++) {
        ...
    }

    for (i = 0, r = rs->ext;
         i < rs->n_ext;
         i++, r++)
    {
        ...
    }
```

If some part of the `for` statement is omitted, mark it with
`/* void */`. A loop with an empty body uses the same comment, which
may sit on the same line:

```c
    for (i = 0; /* void */ ; i++) {
        ...
    }

    for (p = line; *p != '\0' && *p != '\n'; p++) { /* void */ }
```

An endless loop looks like this:

```c
    for ( ;; ) {
        ...
    }
```

## Labels

Labels are surrounded with empty lines and are indented at the previous
level:

```c
    fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        goto failed;
    }

    if (connect(fd, (struct sockaddr *) &sun, sizeof(sun)) < 0) {
        goto failed;
    }

    return fd;

failed:

    if (fd >= 0) {
        close(fd);
    }

    return -1;
```

## mini-fw notes

These override nginx where they conflict.

- Always brace `if` / `else` / `for`, including one-liners. Leave
  `while` unbraced when the body is a single statement.
- Exported functions, types, and globals use the `mfw_` / `MFW_` prefix
  (`mfwd_` / `MFWD_` for the daemon's). File-local static helpers may
  omit it.
- Blank line before and after an `if` / `else` chain or `for` when it
  sits next to another statement (not against the enclosing `{` / `}`).
- Blank line before `} else {` and, usually, before `} else if`.
- Blank line before the last `return` of a function, unless it is the
  only statement in the body.
- SPDX instead of nginx `Copyright (C)` banners: every file is
  `GPL-2.0-only OR BSD-2-Clause`, in a `/* */` comment. No `//`
  comments anywhere, the BPF program included.
- `include/mfw.h` is shared with the BPF program: fixed-width `__u*`
  members, explicit padding (no holes), no libc, no pointers. It keeps
  `struct mfw_*` / `enum mfw_*` without typedefs, and uppercase enum
  values (`MFW_ACTION_PERMIT`), since both sides use those forms and the
  BPF maps' BTF names them.
- `include/mfw_policy.h` and `include/mfw_client.h` are libmfw.a's API,
  which sw_configd links against: their names (`struct mfw_policy`,
  `enum mfw_rc`, `mfw_client_t`, ...) stay as they are. New public types
  follow this guide.
- Definitions that stand in for kernel UAPI missing from older headers
  (`BPF_TCX_INGRESS`, `BPF_F_BEFORE`) keep the kernel's names.
- BPF verifier constraints (bounded loops, `data_end` checks, the
  `__noinline` parser) are in docs/implementation.md, not here.
- Makefile recipes stay tab-indented. Hand-written C/H is 4-space.
