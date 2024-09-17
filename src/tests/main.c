#include "arch/x86/ctx.h"
#include "arch/x86/regs.h"
#include "errors.h"
#include "except.h"
#include "pis.h"
#include "utils.h"
#include <stdarg.h>
#include <stdio.h>

typedef err_t (*test_func_t)();

// define an example trace function
void trace(const char* format, ...) {
    va_list args;
    va_start(args, format);
    vprintf(format, args);
    va_end(args);
}

static err_t assert_pis_lift_result_equals(
    const pis_lift_result_t* result, const pis_insn_t* insns, size_t insns_amount
) {
    err_t err = SUCCESS;
    CHECK(result->insns_amount == insns_amount);
    for (size_t i = 0; i < insns_amount; i++) {
        CHECK(pis_insn_equals(&result->insns[i], &insns[i]));
    }
cleanup:
    return err;
}

static err_t generic_test_push_reg(const u8* code, size_t code_len, pis_operand_t pushed_reg) {
    err_t err = SUCCESS;

    pis_lift_result_t result = {};

    pis_x86_ctx_t ctx = {
        .cpumode = PIS_X86_CPUMODE_64_BIT,
    };

    CHECK_RETHROW(pis_x86_lift(&ctx, code, code_len, &result));

    pis_insn_t expected[] = {
        PIS_INSN(PIS_OPCODE_ADD, rsp, PIS_OPERAND_CONST(-8, PIS_OPERAND_SIZE_8)),
        PIS_INSN(PIS_OPCODE_STORE, rsp, pushed_reg),
    };
    CHECK_RETHROW(assert_pis_lift_result_equals(&result, expected, ARRAY_SIZE(expected)));

cleanup:
    return err;
}

static err_t test_push_reg() {
    err_t err = SUCCESS;
    CHECK_RETHROW(generic_test_push_reg((u8[]) {0x50}, 1, rax));
    CHECK_RETHROW(generic_test_push_reg((u8[]) {0x51}, 1, rcx));
    CHECK_RETHROW(generic_test_push_reg((u8[]) {0x52}, 1, rdx));
    CHECK_RETHROW(generic_test_push_reg((u8[]) {0x53}, 1, rbx));
    CHECK_RETHROW(generic_test_push_reg((u8[]) {0x54}, 1, rsp));
    CHECK_RETHROW(generic_test_push_reg((u8[]) {0x55}, 1, rbp));
    CHECK_RETHROW(generic_test_push_reg((u8[]) {0x56}, 1, rsi));
    CHECK_RETHROW(generic_test_push_reg((u8[]) {0x57}, 1, rdi));

    CHECK_RETHROW(generic_test_push_reg((u8[]) {0x41, 0x50}, 2, r8));
    CHECK_RETHROW(generic_test_push_reg((u8[]) {0x41, 0x51}, 2, r9));
    CHECK_RETHROW(generic_test_push_reg((u8[]) {0x41, 0x52}, 2, r10));
    CHECK_RETHROW(generic_test_push_reg((u8[]) {0x41, 0x53}, 2, r11));
    CHECK_RETHROW(generic_test_push_reg((u8[]) {0x41, 0x54}, 2, r12));
    CHECK_RETHROW(generic_test_push_reg((u8[]) {0x41, 0x55}, 2, r13));
    CHECK_RETHROW(generic_test_push_reg((u8[]) {0x41, 0x56}, 2, r14));
    CHECK_RETHROW(generic_test_push_reg((u8[]) {0x41, 0x57}, 2, r15));

    // TODO: add tests for push <reg> with operand size override prefix.
    // TODO: add tests for push <reg> in 32 and 16 bit cpu modes.
cleanup:
    return err;
}

const test_func_t test_funcs[] = {test_push_reg};

int main() {
    err_t err = SUCCESS;

    for (size_t i = 0; i < ARRAY_SIZE(test_funcs); i++) {
        CHECK_RETHROW(test_funcs[i]());
    }

    TRACE(":)");

cleanup:
    return err;
}
