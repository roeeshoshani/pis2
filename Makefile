LIB_SRCS := $(shell find src/lib -type f -name "*.c")
LIB_OBJS := $(LIB_SRCS:src/%.c=build/%.o)

EXAMPLE_SRCS := $(shell find src/example -type f -name "*.c")
EXAMPLE_OBJS := $(EXAMPLE_SRCS:src/%.c=build/%.o)

TESTS_SRCS := $(shell find src/tests -type f -name "*.c")
TESTS_OBJS := $(TESTS_SRCS:src/%.c=build/%.o)

SRCS := $(shell find src -type f -name "*.c")
HDRS := $(shell find src -type f -name "*.h")
OBJS := $(SRCS:src/%.c=build/%.o)
DEPS := $(OBJS:%.o=%.d)

EXAMPLE_BIN := build/example.elf
TESTS_BIN := build/tests.elf

CC := clang

CFLAGS ?=
CFLAGS += -Isrc/lib
CFLAGS += -Wall -Wextra
CFLAGS += -Werror

.phony: all
all: $(EXAMPLE_BIN) $(TESTS_BIN) $(OBJS)

.phony: test
test: $(TESTS_BIN)
	$(TESTS_BIN)

build/%.o: src/%.c
	@mkdir -p $(@D)
	$(CC) -c -MMD $(CFLAGS) $< -o $@

-include $(DEPS)

build/%.elf:
	$(CC) $(LDFLAGS) $(CFLAGS) $^ -o $@

$(TESTS_BIN): $(LIB_OBJS) $(TESTS_OBJS)
$(EXAMPLE_BIN): $(LIB_OBJS) $(EXAMPLE_OBJS)

.phony: format
format:
	clang-format -i $(SRCS) $(HDRS)

.phony: clean
clean:
	rm -rf build
