.phony: x86_tables_codegen
x86_tables_codegen:
	cd x86_tables && cargo run ../src/lib/arch/x86/x86_tables/
	clang-format -i $(SRCS) $(HDRS)
