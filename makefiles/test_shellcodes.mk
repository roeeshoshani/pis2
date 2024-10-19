SHELLCODE_SRCS := $(wildcard find src/test_shellcodes/*.c)

SHELLCODE_CFLAGS ?=
SHELLCODE_CFLAGS += -static
SHELLCODE_CFLAGS += -ffreestanding -nostdlib
SHELLCODE_CFLAGS += -Wall -Wextra
SHELLCODE_CFLAGS += -Werror

SHELLCODE_LDFLAGS ?=
SHELLCODE_LDFLAGS += -Tsrc/test_shellcodes/shellcode.lds

.PRECIOUS: build/test_shellcodes/%.shellcode.bin
build/test_shellcodes/%.shellcode.bin: build/test_shellcodes/%.shellcode.elf
	$(OBJCOPY) -j .all -O binary $< $@

build/test_shellcodes/%.shellcode.o: build/test_shellcodes/%.shellcode.bin
	$(CC) -c -DWRAP_FILENAME='"$<"' -DSHELLCODE_NAME=$* src/test_shellcodes/shellcode_wrapper.S -o $@

SHELLCODE_ELFS :=

define SHELLCODE_IMPL_ARCH
SHELLCODE_ELFS += $$(SHELLCODE_SRCS:src/%.c=build/%_$(ARCH).shellcode.elf)

.PRECIOUS: build/test_shellcodes/%_$(ARCH).shellcode.elf
build/test_shellcodes/%_$(ARCH).shellcode.elf: src/test_shellcodes/%.c
	@mkdir -p $$(@D)
	$(CC) -target $(ARCH) $(SHELLCODE_LDFLAGS) $(SHELLCODE_CFLAGS) $$< -o $$@
endef

$(foreach ARCH,$(ARCHS),$(eval $(SHELLCODE_IMPL_ARCH)))

SHELLCODE_BINS := $(SHELLCODE_ELFS:build/%.shellcode.elf=build/%.shellcode.o)

