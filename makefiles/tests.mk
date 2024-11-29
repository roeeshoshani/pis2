TESTS_SRCS := $(shell find src/tests -type f -name "*.c")
TESTS_OBJS := $(TESTS_SRCS:src/%.c=build/%.o)

TESTS_ELF := build/tests.elf

$(TESTS_ELF): $(LIB_OBJS) $(TESTS_OBJS) $(EMU_SHELLCODE_BIN_OBJS)

all: $(TESTS_ELF)

.phony: test
test: $(TESTS_ELF)
	$(TESTS_ELF)

