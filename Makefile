LIB_SRCS := $(shell find src/lib -type f -name "*.c")
LIB_OBJS := $(LIB_SRCS:src/%.c=build/%.o)

SRCS := $(shell find src -type f -name "*.c")
HDRS := $(shell find src -type f -name "*.h")
DEPS := $(shell find build -type f -name "*.d")

CC := gcc
OBJCOPY := llvm-objcopy

CFLAGS ?=
CFLAGS += -Wall -Wextra
CFLAGS += -Wimplicit-fallthrough
CFLAGS += -Wno-packed-bitfield-compat
CFLAGS += -Werror
CFLAGS += -mno-sse -mno-avx
CFLAGS += -flto -fuse-linker-plugin
CFLAGS += -fomit-frame-pointer -fno-exceptions -fno-asynchronous-unwind-tables -fno-unwind-tables
CFLAGS += -fno-stack-protector
CFLAGS += -Os
# CFLAGS += -DPIS_MINI
CFLAGS += -g

LDFLAGS ?=

# the `all` target is initially empty but is later filled in different places whenever we want to include anything under this target.
.phony: all
all:

build/%.o: src/%.c
	@mkdir -p $(@D)
	$(CC) -c -MMD $(CFLAGS) $< -o $@

-include $(DEPS)

build/%.elf:
	$(CC) $(LDFLAGS) $(CFLAGS) $^ -o $@

# example binaries support
include makefiles/examples.mk

# emulation tests shellcode support
include makefiles/emu_test_shellcodes.mk

# tests support
include makefiles/tests.mk

# x86 tables codegen
include makefiles/x86_tables.mk

.phony: format
format:
	clang-format -i $(SRCS) $(HDRS)

.phony: clean
clean:
	rm -rf build
