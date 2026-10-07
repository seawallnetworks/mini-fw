# mini-fw — step 1 (stateless ACL)
CLANG     ?= clang
CC        ?= cc
ARCH      ?= $(shell uname -m | sed -e 's/x86_64/x86/' -e 's/aarch64/arm64/')
MULTIARCH ?= $(shell $(CC) -print-multiarch 2>/dev/null)

CFLAGS     ?= -O2 -g -Wall -Wextra
CFLAGS     += -Iinclude -Ibpf -Isrc
BPF_CFLAGS := -O2 -g -Wall -target bpf -D__TARGET_ARCH_$(ARCH) -Ibpf \
              $(if $(MULTIARCH),-I/usr/include/$(MULTIARCH))
LIBS       := $(shell pkg-config --libs libbpf 2>/dev/null || echo -lbpf -lelf -lz)

SRCS := src/main.c src/loader.c src/acl.c src/acl_parse.c src/stats.c

.PHONY: all clean test test-bpf smoke
all: mfw

bpf/mfw.bpf.o: bpf/mfw.bpf.c bpf/mfw.h
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

bpf/mfw.skel.h: bpf/mfw.bpf.o
	bpftool gen skeleton $< name mfw_bpf > $@

mfw: $(SRCS) src/mfw_cli.h bpf/mfw.h bpf/mfw.skel.h
	$(CC) $(CFLAGS) -o $@ $(SRCS) $(LIBS)

tests/test_acl: tests/test_acl.c src/acl_parse.c src/mfw_cli.h bpf/mfw.h
	$(CC) $(CFLAGS) -o $@ tests/test_acl.c src/acl_parse.c

tests/test_bpf: tests/test_bpf.c src/acl_parse.c src/mfw_cli.h bpf/mfw.h bpf/mfw.skel.h
	$(CC) $(CFLAGS) -o $@ tests/test_bpf.c src/acl_parse.c $(LIBS)

test: tests/test_acl
	./tests/test_acl

# Runs the BPF programs on crafted packets (BPF_PROG_TEST_RUN); needs root.
test-bpf: tests/test_bpf
	sudo ./tests/test_bpf

smoke: mfw
	sudo ./scripts/smoke-test.sh

clean:
	rm -f mfw bpf/*.o bpf/*.skel.h tests/test_acl tests/test_bpf
