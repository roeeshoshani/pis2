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
    const pis_lift_result_t* result, const pis_insn_t* expected_insns, size_t expected_insns_amount
) {
    err_t err = SUCCESS;
    CHECK(result->insns_amount == expected_insns_amount);
    for (size_t i = 0; i < expected_insns_amount; i++) {
        if (!pis_insn_equals(&result->insns[i], &expected_insns[i])) {
            TRACE("expected insn:");
            pis_insn_dump(&expected_insns[i]);
            TRACE();

            TRACE("instead got:");
            pis_insn_dump(&result->insns[i]);
            TRACE();

            CHECK_FAIL();
        }
    }
cleanup:
    return err;
}

static err_t generic_test_push_reg_mode_64(
    const u8* code, size_t code_len, pis_operand_t pushed_reg, u64 rsp_add_amount
) {
    err_t err = SUCCESS;

    pis_lift_result_t result = {};

    pis_x86_ctx_t ctx = {
        .cpumode = PIS_X86_CPUMODE_64_BIT,
    };

    CHECK_RETHROW_VERBOSE(pis_x86_lift(&ctx, code, code_len, &result));

    pis_insn_t expected[] = {
        PIS_INSN(PIS_OPCODE_ADD, rsp, PIS_OPERAND_CONST(rsp_add_amount, PIS_OPERAND_SIZE_8)),
        PIS_INSN(PIS_OPCODE_STORE, rsp, pushed_reg),
    };
    CHECK_RETHROW_VERBOSE(assert_pis_lift_result_equals(&result, expected, ARRAY_SIZE(expected)));

cleanup:
    return err;
}

static err_t test_push_reg() {
    err_t err = SUCCESS;

    CHECK_RETHROW_VERBOSE(generic_test_push_reg_mode_64((u8[]) {0x50}, 1, rax, 0xfffffffffffffff8));
    CHECK_RETHROW_VERBOSE(generic_test_push_reg_mode_64((u8[]) {0x51}, 1, rcx, 0xfffffffffffffff8));
    CHECK_RETHROW_VERBOSE(generic_test_push_reg_mode_64((u8[]) {0x52}, 1, rdx, 0xfffffffffffffff8));
    CHECK_RETHROW_VERBOSE(generic_test_push_reg_mode_64((u8[]) {0x53}, 1, rbx, 0xfffffffffffffff8));
    CHECK_RETHROW_VERBOSE(generic_test_push_reg_mode_64((u8[]) {0x54}, 1, rsp, 0xfffffffffffffff8));
    CHECK_RETHROW_VERBOSE(generic_test_push_reg_mode_64((u8[]) {0x55}, 1, rbp, 0xfffffffffffffff8));
    CHECK_RETHROW_VERBOSE(generic_test_push_reg_mode_64((u8[]) {0x56}, 1, rsi, 0xfffffffffffffff8));
    CHECK_RETHROW_VERBOSE(generic_test_push_reg_mode_64((u8[]) {0x57}, 1, rdi, 0xfffffffffffffff8));

    CHECK_RETHROW_VERBOSE(
        generic_test_push_reg_mode_64((u8[]) {0x41, 0x50}, 2, r8, 0xfffffffffffffff8)
    );
    CHECK_RETHROW_VERBOSE(
        generic_test_push_reg_mode_64((u8[]) {0x41, 0x51}, 2, r9, 0xfffffffffffffff8)
    );
    CHECK_RETHROW_VERBOSE(
        generic_test_push_reg_mode_64((u8[]) {0x41, 0x52}, 2, r10, 0xfffffffffffffff8)
    );
    CHECK_RETHROW_VERBOSE(
        generic_test_push_reg_mode_64((u8[]) {0x41, 0x53}, 2, r11, 0xfffffffffffffff8)
    );
    CHECK_RETHROW_VERBOSE(
        generic_test_push_reg_mode_64((u8[]) {0x41, 0x54}, 2, r12, 0xfffffffffffffff8)
    );
    CHECK_RETHROW_VERBOSE(
        generic_test_push_reg_mode_64((u8[]) {0x41, 0x55}, 2, r13, 0xfffffffffffffff8)
    );
    CHECK_RETHROW_VERBOSE(
        generic_test_push_reg_mode_64((u8[]) {0x41, 0x56}, 2, r14, 0xfffffffffffffff8)
    );
    CHECK_RETHROW_VERBOSE(
        generic_test_push_reg_mode_64((u8[]) {0x41, 0x57}, 2, r15, 0xfffffffffffffff8)
    );

    CHECK_RETHROW_VERBOSE(
        generic_test_push_reg_mode_64((u8[]) {0x66, 0x50}, 2, ax, 0xfffffffffffffffe)
    );
    CHECK_RETHROW_VERBOSE(
        generic_test_push_reg_mode_64((u8[]) {0x66, 0x51}, 2, cx, 0xfffffffffffffffe)
    );
    CHECK_RETHROW_VERBOSE(
        generic_test_push_reg_mode_64((u8[]) {0x66, 0x52}, 2, dx, 0xfffffffffffffffe)
    );
    CHECK_RETHROW_VERBOSE(
        generic_test_push_reg_mode_64((u8[]) {0x66, 0x53}, 2, bx, 0xfffffffffffffffe)
    );
    CHECK_RETHROW_VERBOSE(
        generic_test_push_reg_mode_64((u8[]) {0x66, 0x54}, 2, sp, 0xfffffffffffffffe)
    );
    CHECK_RETHROW_VERBOSE(
        generic_test_push_reg_mode_64((u8[]) {0x66, 0x55}, 2, bp, 0xfffffffffffffffe)
    );
    CHECK_RETHROW_VERBOSE(
        generic_test_push_reg_mode_64((u8[]) {0x66, 0x56}, 2, si, 0xfffffffffffffffe)
    );
    CHECK_RETHROW_VERBOSE(
        generic_test_push_reg_mode_64((u8[]) {0x66, 0x57}, 2, di, 0xfffffffffffffffe)
    );

    CHECK_RETHROW_VERBOSE(
        generic_test_push_reg_mode_64((u8[]) {0x66, 0x41, 0x50}, 3, r8w, 0xfffffffffffffffe)
    );
    CHECK_RETHROW_VERBOSE(
        generic_test_push_reg_mode_64((u8[]) {0x66, 0x41, 0x51}, 3, r9w, 0xfffffffffffffffe)
    );
    CHECK_RETHROW_VERBOSE(
        generic_test_push_reg_mode_64((u8[]) {0x66, 0x41, 0x52}, 3, r10w, 0xfffffffffffffffe)
    );
    CHECK_RETHROW_VERBOSE(
        generic_test_push_reg_mode_64((u8[]) {0x66, 0x41, 0x53}, 3, r11w, 0xfffffffffffffffe)
    );
    CHECK_RETHROW_VERBOSE(
        generic_test_push_reg_mode_64((u8[]) {0x66, 0x41, 0x54}, 3, r12w, 0xfffffffffffffffe)
    );
    CHECK_RETHROW_VERBOSE(
        generic_test_push_reg_mode_64((u8[]) {0x66, 0x41, 0x55}, 3, r13w, 0xfffffffffffffffe)
    );
    CHECK_RETHROW_VERBOSE(
        generic_test_push_reg_mode_64((u8[]) {0x66, 0x41, 0x56}, 3, r14w, 0xfffffffffffffffe)
    );
    CHECK_RETHROW_VERBOSE(
        generic_test_push_reg_mode_64((u8[]) {0x66, 0x41, 0x57}, 3, r15w, 0xfffffffffffffffe)
    );

    CHECK_RETHROW_VERBOSE(
        generic_test_push_reg_mode_64((u8[]) {0x66, 0x48, 0x50}, 3, rax, 0xfffffffffffffff8)
    );
    CHECK_RETHROW_VERBOSE(
        generic_test_push_reg_mode_64((u8[]) {0x66, 0x48, 0x51}, 3, rcx, 0xfffffffffffffff8)
    );
    CHECK_RETHROW_VERBOSE(
        generic_test_push_reg_mode_64((u8[]) {0x66, 0x48, 0x52}, 3, rdx, 0xfffffffffffffff8)
    );
    CHECK_RETHROW_VERBOSE(
        generic_test_push_reg_mode_64((u8[]) {0x66, 0x48, 0x53}, 3, rbx, 0xfffffffffffffff8)
    );
    CHECK_RETHROW_VERBOSE(
        generic_test_push_reg_mode_64((u8[]) {0x66, 0x48, 0x54}, 3, rsp, 0xfffffffffffffff8)
    );
    CHECK_RETHROW_VERBOSE(
        generic_test_push_reg_mode_64((u8[]) {0x66, 0x48, 0x55}, 3, rbp, 0xfffffffffffffff8)
    );
    CHECK_RETHROW_VERBOSE(
        generic_test_push_reg_mode_64((u8[]) {0x66, 0x48, 0x56}, 3, rsi, 0xfffffffffffffff8)
    );
    CHECK_RETHROW_VERBOSE(
        generic_test_push_reg_mode_64((u8[]) {0x66, 0x48, 0x57}, 3, rdi, 0xfffffffffffffff8)
    );

    // TODO: add tests for push <reg> in 32 and 16 bit cpu modes.
cleanup:
    return err;
}

const test_func_t test_funcs[] = {test_push_reg};

int main() {
    err_t err = SUCCESS;

    for (size_t i = 0; i < ARRAY_SIZE(test_funcs); i++) {
        CHECK_RETHROW_VERBOSE(test_funcs[i]());
    }

    TRACE(":)");

cleanup:
    return err;
}
