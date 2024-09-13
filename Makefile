SRCS := $(shell find src -type f -name "*.c")
HDRS := $(shell find src -type f -name "*.h")
OBJS := $(SRCS:src/%.c=build/%.o)
DEPS := $(OBJS:%.o=%.d)

BIN := build/main

CC := clang

CFLAGS ?=
CFLAGS += -Isrc
CFLAGS += -Wall -Wextra
CFLAGS += -Werror

.phony: all
all: $(BIN) $(OBJS)

build/%.o: src/%.c
	@mkdir -p $(@D)
	$(CC) -c -MMD $(CFLAGS) $< -o $@


-include $(DEPS)

$(BIN): $(OBJS)
	$(CC) $(LDFLAGS) $(CFLAGS) $^ -o $@

.phony: format
format:
	clang-format -i $(SRCS) $(HDRS)

.phony: clean
clean:
	rm -rf build
