SHELLCODE_SRCS := $(wildcard src/test_shellcodes/*.c)
SHELLCODE_UTIL_SRCS := $(shell find src/test_shellcodes/utils/ -type f -name "*.c")

SHELLCODE_CFLAGS ?=
SHELLCODE_CFLAGS += -static
SHELLCODE_CFLAGS += -ffreestanding -nostdlib
SHELLCODE_CFLAGS += -Wall -Wextra
SHELLCODE_CFLAGS += -Werror
SHELLCODE_CFLAGS += -Wno-unused-function
SHELLCODE_CFLAGS += -mno-sse -mno-avx
SHELLCODE_CFLAGS += -O3

SHELLCODE_LDFLAGS ?=
SHELLCODE_LDFLAGS += -Tsrc/test_shellcodes/shellcode.lds
SHELLCODE_LDFLAGS += -Wl,--build-id=none

SHELLCODE_CC ?= clang-18

.PRECIOUS: build/test_shellcodes/%.bin.shellcode
build/test_shellcodes/%.bin.shellcode: build/test_shellcodes/%.elf.shellcode
	$(OBJCOPY) -j .all -O binary $< $@

build/test_shellcodes/%.bin.o.shellcode: build/test_shellcodes/%.bin.shellcode
	$(CC) -c -DWRAP_FILENAME='"$<"' -DSHELLCODE_NAME=$* src/test_shellcodes/shellcode_wrapper.S -o $@

SHELLCODE_ELFS :=

define SHELLCODE_IMPL_ARCH
SHELLCODE_ELFS += $$(SHELLCODE_SRCS:src/%.c=build/%_$(ARCH).elf.shellcode)

.PRECIOUS: build/test_shellcodes/%_$(ARCH).elf.shellcode
build/test_shellcodes/%_$(ARCH).elf.shellcode: src/test_shellcodes/%.c $(SHELLCODE_UTIL_SRCS)
	@mkdir -p $$(@D)
	$(SHELLCODE_CC) -MMD -target $(ARCH) $(SHELLCODE_LDFLAGS) $(SHELLCODE_CFLAGS) src/test_shellcodes/$$*.c $(SHELLCODE_UTIL_SRCS) -o $$@
endef

$(foreach ARCH,$(ARCHS),$(eval $(SHELLCODE_IMPL_ARCH)))

SHELLCODE_BIN_OBJS := $(SHELLCODE_ELFS:build/%.elf.shellcode=build/%.bin.o.shellcode)

