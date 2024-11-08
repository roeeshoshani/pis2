LIB_SRCS := $(shell find src/lib -type f -name "*.c")
LIB_OBJS := $(LIB_SRCS:src/%.c=build/%.o)

SRCS := $(shell find src -type f -name "*.c")
HDRS := $(shell find src -type f -name "*.h")
OBJS := $(SRCS:src/%.c=build/%.o)
DEPS := $(OBJS:%.o=%.d)

ARCHS := x86_64 i386

CC := clang
OBJCOPY := llvm-objcopy

CFLAGS ?=
CFLAGS += -Wall -Wextra
CFLAGS += -Wimplicit-fallthrough
CFLAGS += -Werror
CFLAGS += -mno-sse -mno-avx
CFLAGS += -flto
CFLAGS += -Oz
CFLAGS += -DPIS_MINI
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

# test shellcode support
include makefiles/test_shellcodes.mk

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
