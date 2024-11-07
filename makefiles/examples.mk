EXAMPLE_SRCS := $(shell find src/examples -type f -name "*.c")
EXAMPLE_OBJS := $(EXAMPLE_SRCS:src/%.c=build/%.o)
EXAMPLE_ELFS := $(EXAMPLE_SRCS:src/%.c=build/%.elf)

define EXAMPLE_ELF_IMPL
# each example file depends on all pis library files and on the example's main object file
$(EXAMPLE_ELF): $(LIB_OBJS) $(EXAMPLE_ELF:build/%.elf=build/%.o)
endef

$(foreach EXAMPLE_ELF,$(EXAMPLE_ELFS),$(eval $(EXAMPLE_ELF_IMPL)))

all: $(EXAMPLE_ELFS)
