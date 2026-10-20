CC      ?= cc
CFLAGS  ?= -O2 -Wall -Wextra -std=c11 -D_GNU_SOURCE -Iinclude
LDFLAGS ?= -lpthread

SRCS = src/a64_rewriter.c \
       src/elf2macho.c \
       src/jitless_signer.c \
       src/bionic_shim.c \
       src/jni_dvm.c \
       src/jitless_linker.c

.PHONY: all test clean

all: build/husk-jitless-cli build/test_translation_layer

build/husk-jitless-cli: $(SRCS) tools/husk-jitless-cli.c
	@mkdir -p build
	$(CC) $(CFLAGS) $(SRCS) tools/husk-jitless-cli.c -o $@ $(LDFLAGS)

build/test_translation_layer: $(SRCS) tests/test_translation_layer.c
	@mkdir -p build
	$(CC) $(CFLAGS) $(SRCS) tests/test_translation_layer.c -o $@ $(LDFLAGS)

test: build/test_translation_layer
	./build/test_translation_layer

clean:
	rm -rf build
