# mini-fw: mfwd (the daemon), mfw (its client) and libmfw.a (for front
# ends such as sw_configd: policy checks and the mfwd client, no libbpf)
CLANG     ?= clang
CC        ?= cc
ARCH      ?= $(shell uname -m | sed -e 's/x86_64/x86/' -e 's/aarch64/arm64/')
MULTIARCH ?= $(shell $(CC) -print-multiarch 2>/dev/null)
PREFIX    ?= /usr/local

CFLAGS     ?= -O2 -g -Wall -Wextra
CFLAGS     += -Iinclude -Ibpf -Isrc -Ibuild -MMD -MP
BPF_CFLAGS := -O2 -g -Wall -target bpf -D__TARGET_ARCH_$(ARCH) -Ibpf \
              $(if $(MULTIARCH),-I/usr/include/$(MULTIARCH))
LIBBPF     := $(shell pkg-config --libs libbpf 2>/dev/null || echo -lbpf -lelf -lz)

LIB_OBJS   := build/acl_parse.o build/policy.o build/client.o
MFWD_OBJS  := build/mfwd.o build/dataplane.o
HEADERS    := bpf/mfw.h include/mfw_policy.h include/mfw_client.h

.PHONY: all clean test test-bpf test-mfwd smoke install
all: mfwd mfw libmfw.a

build:
	mkdir -p $@

build/mfw.bpf.o: bpf/mfw.bpf.c bpf/mfw.h | build
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

build/mfw.skel.h: build/mfw.bpf.o
	bpftool gen skeleton $< name mfw_bpf > $@

build/%.o: src/%.c | build
	$(CC) $(CFLAGS) -c $< -o $@

# the skeleton embeds the BPF object
build/dataplane.o: build/mfw.skel.h

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

tests/test_bpf: tests/test_bpf.c build/mfw.skel.h libmfw.a
	$(CC) $(CFLAGS) -o $@ $< libmfw.a $(LIBBPF)

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

install: all
	install -D -m 0755 mfwd $(DESTDIR)$(PREFIX)/sbin/mfwd
	install -D -m 0755 mfw $(DESTDIR)$(PREFIX)/bin/mfw
	install -D -m 0644 libmfw.a $(DESTDIR)$(PREFIX)/lib/libmfw.a
	install -D -m 0644 -t $(DESTDIR)$(PREFIX)/include $(HEADERS)
	install -D -m 0644 mfwd.service $(DESTDIR)/etc/systemd/system/mfwd.service

clean:
	rm -rf build mfwd mfw libmfw.a tests/test_acl tests/test_policy tests/test_bpf tests/*.d

-include build/*.d
