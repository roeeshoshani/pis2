OBJ32 := build/main_32.o
OBJ64 := build/main_64.o
BIN64 := build/main_64.elf
BIN32 := build/main_32.elf

.phony: dump
dump: $(OBJ64) $(OBJ32)
	objdump -Mintel -d $(OBJ64)
	objdump -Mintel -d $(OBJ32)

.phony: dump64
dump64: $(OBJ64)
	objdump -Mintel -d $(OBJ64)

.phony: dump32
dump32: $(OBJ32)
	objdump -Mintel -d $(OBJ32)

.phony: debug
debug: $(BIN64)
	gdb -x gdbscript $(BIN64)

build/%_64.o: src/%_64.asm
	@mkdir -p $(@D)
	nasm -felf64 $< -o $@

build/%_32.o: src/%_32.asm
	@mkdir -p $(@D)
	nasm -felf32 $< -o $@

build/%_64.elf:
	gcc $^ -o $@

build/%_32.elf:
	gcc -m32 $^ -o $@

$(BIN64): $(OBJ64)
$(BIN32): $(OBJ32)

.phony: clean
clean:
	rm -rf build
