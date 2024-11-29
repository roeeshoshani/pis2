EMU_SHELLCODE_ARCHS := x86_64 i686 mipsbe32r1 mipsel32r1

EMU_SHELLCODE_SRCS := $(wildcard src/emu_test_shellcodes/*.c)
EMU_SHELLCODE_UTIL_SRCS := $(shell find src/emu_test_shellcodes/utils/ -type f -name "*.c")

EMU_SHELLCODE_CFLAGS ?=
EMU_SHELLCODE_CFLAGS += -static
EMU_SHELLCODE_CFLAGS += -ffreestanding -nostdlib
EMU_SHELLCODE_CFLAGS += -Wall -Wextra
EMU_SHELLCODE_CFLAGS += -Werror
EMU_SHELLCODE_CFLAGS += -Wno-unused-function
EMU_SHELLCODE_CFLAGS += -fomit-frame-pointer -fno-exceptions -fno-asynchronous-unwind-tables -fno-unwind-tables 
EMU_SHELLCODE_CFLAGS += -fno-stack-protector
EMU_SHELLCODE_CFLAGS += -Os

EMU_SHELLCODE_LDFLAGS ?=
EMU_SHELLCODE_LDFLAGS += -Tsrc/emu_test_shellcodes/shellcode.lds
EMU_SHELLCODE_LDFLAGS += -Wl,--build-id=none

CC_i686 := i686-linux-gnu-gcc
EMU_SHELLCODE_CFLAGS_i686 := -mno-sse -mno-avx

CC_x86_64 := x86_64-linux-gnu-gcc
EMU_SHELLCODE_CFLAGS_x86_64 := -mno-sse -mno-avx

CC_mipsbe32r1 := mips-linux-gnu-gcc
EMU_SHELLCODE_CFLAGS_mipsbe32r1 := -march=mips1 -mfp32 -mno-check-zero-division

CC_mipsel32r1 := mipsel-linux-gnu-gcc
EMU_SHELLCODE_CFLAGS_mipsel32r1 := -march=mips1 -mfp32 -mno-check-zero-division

.PRECIOUS: build/emu_test_shellcodes/%.bin.shellcode
build/emu_test_shellcodes/%.bin.shellcode: build/emu_test_shellcodes/%.elf.shellcode
	$(OBJCOPY) -j .all -O binary $< $@

build/emu_test_shellcodes/%.bin.o.shellcode: build/emu_test_shellcodes/%.bin.shellcode
	$(CC) -c -DWRAP_FILENAME='"$<"' -DSHELLCODE_NAME=emu_$* src/emu_test_shellcodes/shellcode_wrapper.S -o $@

EMU_SHELLCODE_ELFS :=

define EMU_SHELLCODE_IMPL_ARCH
EMU_SHELLCODE_ELFS += $$(EMU_SHELLCODE_SRCS:src/%.c=build/%_$(ARCH).elf.shellcode)

.PRECIOUS: build/emu_test_shellcodes/%_$(ARCH).elf.shellcode
build/emu_test_shellcodes/%_$(ARCH).elf.shellcode: src/emu_test_shellcodes/%.c $(EMU_SHELLCODE_UTIL_SRCS)
	@mkdir -p $$(@D)
	$$(CC_$(ARCH)) \
		-MMD \
		$(EMU_SHELLCODE_LDFLAGS) \
		$(EMU_SHELLCODE_CFLAGS) \
		$$(EMU_SHELLCODE_CFLAGS_$(ARCH)) \
		src/emu_test_shellcodes/$$*.c \
		$(EMU_SHELLCODE_UTIL_SRCS) \
		-o $$@
endef

$(foreach ARCH,$(EMU_SHELLCODE_ARCHS),$(eval $(EMU_SHELLCODE_IMPL_ARCH)))

EMU_SHELLCODE_BIN_OBJS := $(EMU_SHELLCODE_ELFS:build/%.elf.shellcode=build/%.bin.o.shellcode)

