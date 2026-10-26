# mini-fw: mfwd (the daemon), mfw (its client) and libmfw.a (for front
# ends such as sw_configd: policy checks and the mfwd client, no libbpf)
CLANG     ?= clang
BPFTOOL   ?= bpftool
CC        ?= cc
ARCH      ?= $(shell uname -m | sed -e 's/x86_64/x86/' -e 's/aarch64/arm64/')
MULTIARCH ?= $(shell $(CC) -print-multiarch 2>/dev/null)
# shared by the Seawall stack (libcli-plus, sw_authd, sw_configd)
PREFIX    ?= /usr/local/seawall
# sw_flowd's header, <sw_flowd/sw_flowd.h>: the flow table "reply" ACEs
# read (sw_flowd's "make install-header" puts it there). Only mfwd and
# its program need it, not libmfw.a.
SW_FLOWD_PREFIX ?= $(PREFIX)
SW_FLOWD_H := $(SW_FLOWD_PREFIX)/include/sw_flowd/sw_flowd.h
# libpkt, the stack's packet parser (Seawall proposal 0010):
# <libpkt/parse.h>, which libpkt's "make install" puts there. Only the
# BPF program needs it.
LIBPKT_PREFIX ?= $(PREFIX)
LIBPKT_H := $(LIBPKT_PREFIX)/include/libpkt/parse.h

CFLAGS     ?= -O2 -g -Wall -Wextra
CFLAGS     += -Iinclude -Isrc -MMD -MP
BPF_CFLAGS := -O2 -g -Wall -target bpf -D__TARGET_ARCH_$(ARCH) -Iinclude \
              -I$(SW_FLOWD_PREFIX)/include -I$(LIBPKT_PREFIX)/include \
              $(if $(MULTIARCH),-I/usr/include/$(MULTIARCH))
BPFDIR     := src/bpf
# mfwd is linked fully static (libxdp, which carries its dispatcher,
# libbpf, libelf, zlib, libzstd and libc), so it needs nothing on the machine
LIBBPF     := -static $(or $(shell pkg-config --static --libs libxdp 2>/dev/null), \
              -lxdp -lbpf -lelf -lz -lzstd)

LIB_OBJS   := build/acl_parse.o build/policy.o build/client.o
MFWD_OBJS  := build/mfwd.o build/dataplane.o build/dp_xdp.o build/dp_tc.o \
              build/util.o
HEADERS    := include/mfw.h include/mfw_policy.h include/mfw_client.h

.PHONY: all clean test test-bpf test-mfwd smoke install install-runtime \
	install-static-lib uninstall
all: mfwd mfw libmfw.a

build:
	mkdir -p $@

build/mfw.bpf.o: $(BPFDIR)/mfw.bpf.c include/mfw.h $(SW_FLOWD_H) $(LIBPKT_H) \
		| build
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

$(SW_FLOWD_H):
	@echo "$@ missing: install sw_flowd's header first" \
	    "(make -C ../sw_flowd install-header), or set SW_FLOWD_PREFIX" >&2
	@exit 1

$(LIBPKT_H):
	@echo "$@ missing: install libpkt first" \
	    "(make -C ../libpkt install), or set LIBPKT_PREFIX" >&2
	@exit 1

src/mfw.skel.h: build/mfw.bpf.o
	$(BPFTOOL) gen skeleton $< name mfw_bpf > $@

build/%.o: src/%.c | build
	$(CC) $(CFLAGS) -c $< -o $@

build/dataplane.o: CFLAGS += -I$(SW_FLOWD_PREFIX)/include
build/dataplane.o: $(SW_FLOWD_H)

# the skeleton embeds the BPF object
build/dataplane.o build/dp_xdp.o: src/mfw.skel.h

libmfw.a: $(LIB_OBJS)
	$(AR) rcs $@ $^

mfwd: $(MFWD_OBJS) libmfw.a
	$(CC) $(CFLAGS) -o $@ $(MFWD_OBJS) libmfw.a $(LIBBPF)

mfw: build/mfw.o libmfw.a
	$(CC) $(CFLAGS) -o $@ build/mfw.o libmfw.a

tests/test_acl: tests/test_acl.c libmfw.a
	$(CC) $(CFLAGS) -o $@ $< libmfw.a

tests/test_policy: tests/test_policy.c libmfw.a
	$(CC) $(CFLAGS) -o $@ $< libmfw.a

tests/test_bpf: tests/test_bpf.c src/mfw.skel.h libmfw.a
	$(CC) $(CFLAGS) -I$(SW_FLOWD_PREFIX)/include -o $@ $< libmfw.a $(LIBBPF)

# no privileges needed
test: tests/test_acl tests/test_policy
	./tests/test_acl
	./tests/test_policy

# the BPF program on crafted packets (BPF_PROG_TEST_RUN); root
test-bpf: tests/test_bpf
	sudo ./tests/test_bpf

# mfwd's protocol, attach/detach and restarts, on dummy interfaces; root
test-mfwd: mfwd mfw
	sudo ./tests/test_mfwd.sh

# real traffic through mfwd in two network namespaces; root
smoke: mfwd mfw
	sudo ./scripts/smoke-test.sh

install: install-runtime install-static-lib

# what runs on the machine. The unit gives the socket to the group mfw,
# from the seawall repo; without it (checked unless staging into DESTDIR)
# mfwd couldn't start, so nothing is installed.
install-runtime: mfwd mfw
	[ -n "$(DESTDIR)" ] || getent group mfw >/dev/null || { \
	    echo "group mfw missing: install seawall first" >&2; \
	    exit 1; }
	install -D -m 0755 mfwd $(DESTDIR)$(PREFIX)/sbin/mfwd
	install -D -m 0755 mfw $(DESTDIR)$(PREFIX)/bin/mfw
	install -D -m 0644 mfwd.service $(DESTDIR)/etc/systemd/system/mfwd.service

# the client library and its headers, for linking (sw_configd)
install-static-lib: libmfw.a
	install -D -m 0644 libmfw.a $(DESTDIR)$(PREFIX)/lib/libmfw.a
	install -D -m 0644 -t $(DESTDIR)$(PREFIX)/include $(HEADERS)

# removes the files only: "mfwd -P" removes mini-fw from the interfaces
uninstall:
	rm -f $(DESTDIR)$(PREFIX)/sbin/mfwd $(DESTDIR)$(PREFIX)/bin/mfw \
	    $(DESTDIR)$(PREFIX)/lib/libmfw.a \
	    $(addprefix $(DESTDIR)$(PREFIX)/include/,$(notdir $(HEADERS))) \
	    $(DESTDIR)/etc/systemd/system/mfwd.service

clean:
	rm -rf build src/mfw.skel.h mfwd mfw libmfw.a tests/test_acl tests/test_policy tests/test_bpf tests/*.d

-include build/*.d
