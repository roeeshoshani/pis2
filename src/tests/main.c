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

static err_t generic_test_push_reg(
    const u8* code,
    size_t code_len,
    pis_operand_t pushed_reg,
    u64 sp_add_amount,
    pis_x86_cpumode_t cpumode,
    pis_operand_t sp
) {
    err_t err = SUCCESS;

    pis_lift_result_t result = {};

    pis_x86_ctx_t ctx = {
        .cpumode = cpumode,
    };

    CHECK_RETHROW_VERBOSE(pis_x86_lift(&ctx, code, code_len, &result));

    pis_insn_t expected[] = {
        PIS_INSN(PIS_OPCODE_ADD, sp, PIS_OPERAND_CONST(sp_add_amount, sp.size)),
        PIS_INSN(PIS_OPCODE_STORE, sp, pushed_reg),
    };
    CHECK_RETHROW_VERBOSE(assert_pis_lift_result_equals(&result, expected, ARRAY_SIZE(expected)));

cleanup:
    return err;
}

static err_t generic_test_push_reg_mode_64(
    const u8* code, size_t code_len, pis_operand_t pushed_reg, u64 rsp_add_amount
) {
    err_t err = SUCCESS;
    CHECK_RETHROW_VERBOSE(generic_test_push_reg(
        code,
        code_len,
        pushed_reg,
        rsp_add_amount,
        PIS_X86_CPUMODE_64_BIT,
        rsp
    ));
cleanup:
    return err;
}

static err_t generic_test_push_reg_mode_32(
    const u8* code, size_t code_len, pis_operand_t pushed_reg, u32 esp_add_amount
) {
    err_t err = SUCCESS;
    CHECK_RETHROW_VERBOSE(generic_test_push_reg(
        code,
        code_len,
        pushed_reg,
        esp_add_amount,
        PIS_X86_CPUMODE_32_BIT,
        esp
    ));
cleanup:
    return err;
}

static err_t generic_test_push_reg_mode_16(
    const u8* code, size_t code_len, pis_operand_t pushed_reg, u16 sp_add_amount
) {
    err_t err = SUCCESS;
    CHECK_RETHROW_VERBOSE(
        generic_test_push_reg(code, code_len, pushed_reg, sp_add_amount, PIS_X86_CPUMODE_16_BIT, sp)
    );
cleanup:
    return err;
}

static err_t test_push_reg_64_bit_mode() {
    err_t err = SUCCESS;

    // regular 64 bit push
    CHECK_RETHROW_VERBOSE(generic_test_push_reg_mode_64((u8[]) {0x50}, 1, rax, 0xfffffffffffffff8));
    CHECK_RETHROW_VERBOSE(generic_test_push_reg_mode_64((u8[]) {0x55}, 1, rbp, 0xfffffffffffffff8));

    // REX.B 64 bit push
    CHECK_RETHROW_VERBOSE(
        generic_test_push_reg_mode_64((u8[]) {0x41, 0x50}, 2, r8, 0xfffffffffffffff8)
    );
    CHECK_RETHROW_VERBOSE(
        generic_test_push_reg_mode_64((u8[]) {0x41, 0x55}, 2, r13, 0xfffffffffffffff8)
    );

    // operand size override 64 bit push
    CHECK_RETHROW_VERBOSE(
        generic_test_push_reg_mode_64((u8[]) {0x66, 0x50}, 2, ax, 0xfffffffffffffffe)
    );
    CHECK_RETHROW_VERBOSE(
        generic_test_push_reg_mode_64((u8[]) {0x66, 0x55}, 2, bp, 0xfffffffffffffffe)
    );

    // operand size override and REX.B 64 bit push
    CHECK_RETHROW_VERBOSE(
        generic_test_push_reg_mode_64((u8[]) {0x66, 0x41, 0x50}, 3, r8w, 0xfffffffffffffffe)
    );
    CHECK_RETHROW_VERBOSE(
        generic_test_push_reg_mode_64((u8[]) {0x66, 0x41, 0x55}, 3, r13w, 0xfffffffffffffffe)
    );

    // operand size override and REX.W 64 bit push
    CHECK_RETHROW_VERBOSE(
        generic_test_push_reg_mode_64((u8[]) {0x66, 0x48, 0x50}, 3, rax, 0xfffffffffffffff8)
    );
    CHECK_RETHROW_VERBOSE(
        generic_test_push_reg_mode_64((u8[]) {0x66, 0x48, 0x55}, 3, rbp, 0xfffffffffffffff8)
    );

    // operand size override and REX.BW 64 bit push
    CHECK_RETHROW_VERBOSE(
        generic_test_push_reg_mode_64((u8[]) {0x66, 0x49, 0x50}, 3, r8, 0xfffffffffffffff8)
    );
    CHECK_RETHROW_VERBOSE(
        generic_test_push_reg_mode_64((u8[]) {0x66, 0x49, 0x55}, 3, r13, 0xfffffffffffffff8)
    );

cleanup:
    return err;
}

static err_t test_push_reg_32_bit_mode() {
    err_t err = SUCCESS;

    // regular 32 bit push
    CHECK_RETHROW_VERBOSE(generic_test_push_reg_mode_32((u8[]) {0x50}, 1, eax, 0xfffffffc));
    CHECK_RETHROW_VERBOSE(generic_test_push_reg_mode_32((u8[]) {0x55}, 1, ebp, 0xfffffffc));

    // operand size override 32 bit push
    CHECK_RETHROW_VERBOSE(generic_test_push_reg_mode_32((u8[]) {0x66, 0x50}, 2, ax, 0xfffffffe));
    CHECK_RETHROW_VERBOSE(generic_test_push_reg_mode_32((u8[]) {0x66, 0x55}, 2, bp, 0xfffffffe));

cleanup:
    return err;
}


static err_t test_push_reg_16_bit_mode() {
    err_t err = SUCCESS;

    // regular 16 bit push
    CHECK_RETHROW_VERBOSE(generic_test_push_reg_mode_16((u8[]) {0x50}, 1, ax, 0xfffe));
    CHECK_RETHROW_VERBOSE(generic_test_push_reg_mode_16((u8[]) {0x55}, 1, bp, 0xfffe));

    // operand size override 16 bit push
    CHECK_RETHROW_VERBOSE(generic_test_push_reg_mode_16((u8[]) {0x66, 0x50}, 2, eax, 0xfffc));
    CHECK_RETHROW_VERBOSE(generic_test_push_reg_mode_16((u8[]) {0x66, 0x55}, 2, ebp, 0xfffc));

cleanup:
    return err;
}

const test_func_t test_funcs[] = {
    test_push_reg_64_bit_mode,
    test_push_reg_32_bit_mode,
    test_push_reg_16_bit_mode,
};

int main() {
    err_t err = SUCCESS;

    for (size_t i = 0; i < ARRAY_SIZE(test_funcs); i++) {
        CHECK_RETHROW_VERBOSE(test_funcs[i]());
    }

    TRACE(":)");

cleanup:
    return err;
}
