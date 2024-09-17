#include "arch/x86/ctx.h"
#include "arch/x86/regs.h"
#include "errors.h"
#include "except.h"
#include "pis.h"
#include "utils.h"
#include <stdarg.h>
#include <stdio.h>

typedef err_t (*test_fn_t)();

typedef struct {
    test_fn_t fn;
    const char* name;
} test_entry_t;

extern test_entry_t __start_test_entries[];
extern test_entry_t __stop_test_entries[];

typedef struct {
    const pis_insn_t* insns;
    size_t amount;
} expected_insns_t;

typedef struct {
    const u8* code;
    size_t len;
} code_t;

#define EXPECTED_INSNS(...)                                                                        \
    ({                                                                                             \
        (expected_insns_t) {                                                                       \
            .insns = (pis_insn_t[]) {__VA_ARGS__},                                                 \
            .amount = sizeof((pis_insn_t[]) {__VA_ARGS__}) / sizeof(pis_insn_t),                   \
        };                                                                                         \
    })

#define CODE(...)                                                                                  \
    ({                                                                                             \
        static const u8 code[] = {__VA_ARGS__};                                                    \
        (code_t) {                                                                                 \
            .code = code,                                                                          \
            .len = ARRAY_SIZE(code),                                                               \
        };                                                                                         \
    })

#define DEFINE_TEST(NAME)                                                                          \
    static err_t NAME();                                                                           \
    static test_entry_t __attribute__((used, section("test_entries"))) NAME##_test_entry = {       \
        .fn = NAME,                                                                                \
        .name = STRINGIFY(NAME),                                                                   \
    };                                                                                             \
    static err_t NAME()

// define an example trace function
void trace(const char* format, ...) {
    va_list args;
    va_start(args, format);
    vprintf(format, args);
    va_end(args);
}

static err_t
    assert_pis_lift_result_equals(const pis_lift_result_t* result, expected_insns_t expected) {
    err_t err = SUCCESS;
    CHECK(result->insns_amount == expected.amount);
    for (size_t i = 0; i < expected.amount; i++) {
        if (!pis_insn_equals(&result->insns[i], &expected.insns[i])) {
            TRACE("expected insn:");
            pis_insn_dump(&expected.insns[i]);
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

static err_t generic_test_lift(code_t code, pis_x86_cpumode_t cpumode, expected_insns_t expected) {
    err_t err = SUCCESS;

    pis_lift_result_t result = {};

    pis_x86_ctx_t ctx = {
        .cpumode = cpumode,
    };

    CHECK_RETHROW_VERBOSE(pis_x86_lift(&ctx, code.code, code.len, &result));

    CHECK_RETHROW_VERBOSE(assert_pis_lift_result_equals(&result, expected));

cleanup:
    return err;
}

static err_t generic_test_push_reg(
    code_t code,
    pis_x86_cpumode_t cpumode,
    pis_operand_t pushed_reg,
    u64 sp_add_amount,
    pis_operand_t sp
) {
    err_t err = SUCCESS;

    CHECK_RETHROW_VERBOSE(generic_test_lift(
        code,
        cpumode,
        EXPECTED_INSNS(
            PIS_INSN(PIS_OPCODE_ADD, sp, PIS_OPERAND_CONST(sp_add_amount, sp.size)),
            PIS_INSN(PIS_OPCODE_STORE, sp, pushed_reg)
        )
    ));

cleanup:
    return err;
}

static err_t
    generic_test_push_reg_mode_64(code_t code, pis_operand_t pushed_reg, u64 rsp_add_amount) {
    err_t err = SUCCESS;
    CHECK_RETHROW_VERBOSE(
        generic_test_push_reg(code, PIS_X86_CPUMODE_64_BIT, pushed_reg, rsp_add_amount, rsp)
    );
cleanup:
    return err;
}

static err_t
    generic_test_push_reg_mode_32(code_t code, pis_operand_t pushed_reg, u32 esp_add_amount) {
    err_t err = SUCCESS;
    CHECK_RETHROW_VERBOSE(
        generic_test_push_reg(code, PIS_X86_CPUMODE_32_BIT, pushed_reg, esp_add_amount, esp)
    );
cleanup:
    return err;
}

static err_t
    generic_test_push_reg_mode_16(code_t code, pis_operand_t pushed_reg, u16 sp_add_amount) {
    err_t err = SUCCESS;
    CHECK_RETHROW_VERBOSE(
        generic_test_push_reg(code, PIS_X86_CPUMODE_16_BIT, pushed_reg, sp_add_amount, sp)
    );
cleanup:
    return err;
}

DEFINE_TEST(test_push_reg_64_bit_mode) {
    err_t err = SUCCESS;

    // regular 64 bit push
    CHECK_RETHROW_VERBOSE(generic_test_push_reg_mode_64(CODE(0x50), rax, 0xfffffffffffffff8));
    CHECK_RETHROW_VERBOSE(generic_test_push_reg_mode_64(CODE(0x55), rbp, 0xfffffffffffffff8));

    // REX.B 64 bit push
    CHECK_RETHROW_VERBOSE(generic_test_push_reg_mode_64(CODE(0x41, 0x50), r8, 0xfffffffffffffff8));
    CHECK_RETHROW_VERBOSE(generic_test_push_reg_mode_64(CODE(0x41, 0x55), r13, 0xfffffffffffffff8));

    // operand size override 64 bit push
    CHECK_RETHROW_VERBOSE(generic_test_push_reg_mode_64(CODE(0x66, 0x50), ax, 0xfffffffffffffffe));
    CHECK_RETHROW_VERBOSE(generic_test_push_reg_mode_64(CODE(0x66, 0x55), bp, 0xfffffffffffffffe));

    // operand size override and REX.B 64 bit push
    CHECK_RETHROW_VERBOSE(
        generic_test_push_reg_mode_64(CODE(0x66, 0x41, 0x50), r8w, 0xfffffffffffffffe)
    );
    CHECK_RETHROW_VERBOSE(
        generic_test_push_reg_mode_64(CODE(0x66, 0x41, 0x55), r13w, 0xfffffffffffffffe)
    );

    // operand size override and REX.W 64 bit push
    CHECK_RETHROW_VERBOSE(
        generic_test_push_reg_mode_64(CODE(0x66, 0x48, 0x50), rax, 0xfffffffffffffff8)
    );
    CHECK_RETHROW_VERBOSE(
        generic_test_push_reg_mode_64(CODE(0x66, 0x48, 0x55), rbp, 0xfffffffffffffff8)
    );

    // operand size override and REX.BW 64 bit push
    CHECK_RETHROW_VERBOSE(
        generic_test_push_reg_mode_64(CODE(0x66, 0x49, 0x50), r8, 0xfffffffffffffff8)
    );
    CHECK_RETHROW_VERBOSE(
        generic_test_push_reg_mode_64(CODE(0x66, 0x49, 0x55), r13, 0xfffffffffffffff8)
    );

cleanup:
    return err;
}

DEFINE_TEST(test_push_reg_32_bit_mode) {
    err_t err = SUCCESS;

    // regular 32 bit push
    CHECK_RETHROW_VERBOSE(generic_test_push_reg_mode_32(CODE(0x50), eax, 0xfffffffc));
    CHECK_RETHROW_VERBOSE(generic_test_push_reg_mode_32(CODE(0x55), ebp, 0xfffffffc));

    // operand size override 32 bit push
    CHECK_RETHROW_VERBOSE(generic_test_push_reg_mode_32(CODE(0x66, 0x50), ax, 0xfffffffe));
    CHECK_RETHROW_VERBOSE(generic_test_push_reg_mode_32(CODE(0x66, 0x55), bp, 0xfffffffe));

cleanup:
    return err;
}


DEFINE_TEST(test_push_reg_16_bit_mode) {
    err_t err = SUCCESS;

    // regular 16 bit push
    CHECK_RETHROW_VERBOSE(generic_test_push_reg_mode_16(CODE(0x50), ax, 0xfffe));
    CHECK_RETHROW_VERBOSE(generic_test_push_reg_mode_16(CODE(0x55), bp, 0xfffe));

    // operand size override 16 bit push
    CHECK_RETHROW_VERBOSE(generic_test_push_reg_mode_16(CODE(0x66, 0x50), eax, 0xfffc));
    CHECK_RETHROW_VERBOSE(generic_test_push_reg_mode_16(CODE(0x66, 0x55), ebp, 0xfffc));

cleanup:
    return err;
}

DEFINE_TEST(test_mov_rm_r_64) {
    err_t err = SUCCESS;

    goto cleanup;
cleanup:
    return err;
}

int main() {
    err_t err = SUCCESS;

    for (test_entry_t* cur = __start_test_entries; cur < __stop_test_entries; cur++) {
        TRACE("[*] %s", cur->name);
        CHECK_RETHROW_TRACE(cur->fn(), "[!] %s", cur->name);
    }

    TRACE(":)");

cleanup:
    return err;
}
