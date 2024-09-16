LIB_SRCS := $(shell find src/lib -type f -name "*.c")
LIB_OBJS := $(LIB_SRCS:src/%.c=build/%.o)

EXAMPLE_SRCS := $(shell find src/example -type f -name "*.c")
EXAMPLE_OBJS := $(EXAMPLE_SRCS:src/%.c=build/%.o)

SRCS := $(shell find src -type f -name "*.c")
HDRS := $(shell find src -type f -name "*.h")
OBJS := $(SRCS:src/%.c=build/%.o)
DEPS := $(OBJS:%.o=%.d)

EXAMPLE := build/example.elf

CC := clang

CFLAGS ?=
CFLAGS += -Isrc/lib
CFLAGS += -Wall -Wextra
CFLAGS += -Werror

.phony: all
all: $(EXAMPLE)

build/%.o: src/%.c
	@mkdir -p $(@D)
	$(CC) -c -MMD $(CFLAGS) $< -o $@


-include $(DEPS)

$(EXAMPLE): $(LIB_OBJS) $(EXAMPLE_OBJS)
	$(CC) $(LDFLAGS) $(CFLAGS) $^ -o $@

.phony: format
format:
	clang-format -i $(SRCS) $(HDRS)

.phony: clean
clean:
	rm -rf build
