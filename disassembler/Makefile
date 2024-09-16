OBJ := build/main.o

.phony: dump
dump: $(OBJ)
	objdump -Mintel -d $(OBJ)

build/%.o: src/%.asm
	@mkdir -p $(@D)
	nasm -felf64 $< -o $@

.phony: clean
clean:
	rm -rf build
