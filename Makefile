SRCS := $(shell find src -type f -name "*.c")
OBJS := $(SRCS:src/%.c=build/%.o)
DEPS := $(OBJS:%.o=%.d)

BIN := build/main

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

.phony: clean
clean:
	rm -rf build
