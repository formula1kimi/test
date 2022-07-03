# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
OUTPUT := _output
CLANG ?= clang
LLVM_STRIP ?= llvm-strip
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/' | sed 's/ppc64le/powerpc/' | sed 's/mips.*/mips/')
# Use our own libbpf API headers and Linux UAPI headers distributed with
# libbpf to avoid dependency on system-wide headers, which could be missing or
# outdated
INCLUDES := -Ilibbpf/src/_output/usr/include 
CFLAGS := -static -g -Wall
LDFLAGS := -Llibbpf/src/_output/usr/lib64

APPS = example traffic tracepoint xdp_redirect

.PHONY: all
all: $(APPS)

.PHONY: clean
clean:
	$(Q)rm -rf $(OUTPUT) $(APPS) *.bpf.o

$(OUTPUT):
	$(Q)mkdir -p $@

# Build BPF code
%.bpf.o: %.bpf.c 
	$(Q)$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) $(INCLUDES) -c $(filter %.c,$^) -o $@
	$(Q)$(LLVM_STRIP) -g $@ # strip useless DWARF info


$(OUTPUT)/%.o: %.c $(wildcard %.h) | $(OUTPUT)
	$(Q)$(CC) $(CFLAGS) $(INCLUDES) -c $(filter %.c,$^) -o $@

# Build application binary
$(APPS): %: $(OUTPUT)/%.o  | %.bpf.o  $(OUTPUT)
	$(Q)$(CC) $(CFLAGS) $(LDFLAGS) $^ -lbpf -lelf -lz -o $@

# delete failed targets
.DELETE_ON_ERROR:

# keep intermediate (.skel.h, .bpf.o, etc) targets
.SECONDARY:

