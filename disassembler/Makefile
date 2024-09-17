OBJ := build/main.o
BIN := build/main.elf

.phony: dump
dump: $(OBJ)
	objdump -Mintel -d $(OBJ)

.phony: debug
debug: $(BIN)
	gdb -x gdbscript $(BIN)

build/%.o: src/%.asm
	@mkdir -p $(@D)
	nasm -felf64 $< -o $@

build/%.elf:
	gcc $^ -o $@

$(BIN): $(OBJ)

.phony: clean
clean:
	rm -rf build
