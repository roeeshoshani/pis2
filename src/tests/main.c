#include "arch/x86/ctx.h"
#include "arch/x86/regs.h"
#include "arch/x86/tmps.h"
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
    if (result->insns_amount != expected.amount) {
        TRACE("expected %lu insns, got %lu insns", expected.amount, result->insns_amount);

        TRACE("expected insns:");
        for (size_t i = 0; i < expected.amount; i++) {
            pis_insn_dump(&expected.insns[i]);
            TRACE();
        }

        TRACE("intead got:");
        pis_lift_result_dump(result);

        CHECK_FAIL();
    }
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
        generic_test_push_reg(code, PIS_X86_CPUMODE_64_BIT, pushed_reg, rsp_add_amount, RSP)
    );
cleanup:
    return err;
}

static err_t
    generic_test_push_reg_mode_32(code_t code, pis_operand_t pushed_reg, u32 esp_add_amount) {
    err_t err = SUCCESS;
    CHECK_RETHROW_VERBOSE(
        generic_test_push_reg(code, PIS_X86_CPUMODE_32_BIT, pushed_reg, esp_add_amount, ESP)
    );
cleanup:
    return err;
}

static err_t
    generic_test_push_reg_mode_16(code_t code, pis_operand_t pushed_reg, u16 sp_add_amount) {
    err_t err = SUCCESS;
    CHECK_RETHROW_VERBOSE(
        generic_test_push_reg(code, PIS_X86_CPUMODE_16_BIT, pushed_reg, sp_add_amount, SP)
    );
cleanup:
    return err;
}

DEFINE_TEST(test_push_reg_64_bit_mode) {
    err_t err = SUCCESS;

    // regular 64 bit push
    CHECK_RETHROW_VERBOSE(generic_test_push_reg_mode_64(CODE(0x50), RAX, 0xfffffffffffffff8));
    CHECK_RETHROW_VERBOSE(generic_test_push_reg_mode_64(CODE(0x55), RBP, 0xfffffffffffffff8));

    // REX.B 64 bit push
    CHECK_RETHROW_VERBOSE(generic_test_push_reg_mode_64(CODE(0x41, 0x50), R8, 0xfffffffffffffff8));
    CHECK_RETHROW_VERBOSE(generic_test_push_reg_mode_64(CODE(0x41, 0x55), R13, 0xfffffffffffffff8));

    // operand size override 64 bit push
    CHECK_RETHROW_VERBOSE(generic_test_push_reg_mode_64(CODE(0x66, 0x50), AX, 0xfffffffffffffffe));
    CHECK_RETHROW_VERBOSE(generic_test_push_reg_mode_64(CODE(0x66, 0x55), BP, 0xfffffffffffffffe));

    // operand size override and REX.B 64 bit push
    CHECK_RETHROW_VERBOSE(
        generic_test_push_reg_mode_64(CODE(0x66, 0x41, 0x50), R8W, 0xfffffffffffffffe)
    );
    CHECK_RETHROW_VERBOSE(
        generic_test_push_reg_mode_64(CODE(0x66, 0x41, 0x55), R13W, 0xfffffffffffffffe)
    );

    // operand size override and REX.W 64 bit push
    CHECK_RETHROW_VERBOSE(
        generic_test_push_reg_mode_64(CODE(0x66, 0x48, 0x50), RAX, 0xfffffffffffffff8)
    );
    CHECK_RETHROW_VERBOSE(
        generic_test_push_reg_mode_64(CODE(0x66, 0x48, 0x55), RBP, 0xfffffffffffffff8)
    );

    // operand size override and REX.BW 64 bit push
    CHECK_RETHROW_VERBOSE(
        generic_test_push_reg_mode_64(CODE(0x66, 0x49, 0x50), R8, 0xfffffffffffffff8)
    );
    CHECK_RETHROW_VERBOSE(
        generic_test_push_reg_mode_64(CODE(0x66, 0x49, 0x55), R13, 0xfffffffffffffff8)
    );

cleanup:
    return err;
}

DEFINE_TEST(test_push_reg_32_bit_mode) {
    err_t err = SUCCESS;

    // regular 32 bit push
    CHECK_RETHROW_VERBOSE(generic_test_push_reg_mode_32(CODE(0x50), EAX, 0xfffffffc));
    CHECK_RETHROW_VERBOSE(generic_test_push_reg_mode_32(CODE(0x55), EBP, 0xfffffffc));

    // operand size override 32 bit push
    CHECK_RETHROW_VERBOSE(generic_test_push_reg_mode_32(CODE(0x66, 0x50), AX, 0xfffffffe));
    CHECK_RETHROW_VERBOSE(generic_test_push_reg_mode_32(CODE(0x66, 0x55), BP, 0xfffffffe));

cleanup:
    return err;
}


DEFINE_TEST(test_push_reg_16_bit_mode) {
    err_t err = SUCCESS;

    // regular 16 bit push
    CHECK_RETHROW_VERBOSE(generic_test_push_reg_mode_16(CODE(0x50), AX, 0xfffe));
    CHECK_RETHROW_VERBOSE(generic_test_push_reg_mode_16(CODE(0x55), BP, 0xfffe));

    // operand size override 16 bit push
    CHECK_RETHROW_VERBOSE(generic_test_push_reg_mode_16(CODE(0x66, 0x50), EAX, 0xfffc));
    CHECK_RETHROW_VERBOSE(generic_test_push_reg_mode_16(CODE(0x66, 0x55), EBP, 0xfffc));

cleanup:
    return err;
}

DEFINE_TEST(test_mov_64_bit_mode) {
    err_t err = SUCCESS;
    pis_operand_t addr_tmp = PIS_OPERAND(g_modrm_rm_tmp_addr, PIS_OPERAND_SIZE_8);
    pis_operand_t sib_tmp = PIS_OPERAND(g_sib_index_tmp_addr, PIS_OPERAND_SIZE_8);

    CHECK_RETHROW_VERBOSE(generic_test_lift(
        CODE(0x89, 0xe5),
        PIS_X86_CPUMODE_64_BIT,
        EXPECTED_INSNS(PIS_INSN(PIS_OPCODE_MOVE, EBP, ESP))
    ));

    CHECK_RETHROW_VERBOSE(generic_test_lift(
        CODE(0x48, 0x89, 0xe5),
        PIS_X86_CPUMODE_64_BIT,
        EXPECTED_INSNS(PIS_INSN(PIS_OPCODE_MOVE, RBP, RSP))
    ));

    CHECK_RETHROW_VERBOSE(generic_test_lift(
        CODE(0x4d, 0x89, 0xc8),
        PIS_X86_CPUMODE_64_BIT,
        EXPECTED_INSNS(PIS_INSN(PIS_OPCODE_MOVE, R8, R9))
    ));

    CHECK_RETHROW_VERBOSE(generic_test_lift(
        CODE(0x45, 0x89, 0xf4),
        PIS_X86_CPUMODE_64_BIT,
        EXPECTED_INSNS(PIS_INSN(PIS_OPCODE_MOVE, R12D, R14D))
    ));

    CHECK_RETHROW_VERBOSE(generic_test_lift(
        CODE(0x66, 0x41, 0x89, 0xe5),
        PIS_X86_CPUMODE_64_BIT,
        EXPECTED_INSNS(PIS_INSN(PIS_OPCODE_MOVE, R13W, SP))
    ));

    CHECK_RETHROW_VERBOSE(generic_test_lift(
        CODE(0x44, 0x89, 0xfe),
        PIS_X86_CPUMODE_64_BIT,
        EXPECTED_INSNS(PIS_INSN(PIS_OPCODE_MOVE, ESI, R15D))
    ));

    CHECK_RETHROW_VERBOSE(generic_test_lift(
        CODE(0x4c, 0x89, 0x26),
        PIS_X86_CPUMODE_64_BIT,
        EXPECTED_INSNS(
            PIS_INSN(PIS_OPCODE_MOVE, addr_tmp, RSI),
            PIS_INSN(PIS_OPCODE_STORE, addr_tmp, R12)
        )
    ));

    CHECK_RETHROW_VERBOSE(generic_test_lift(
        CODE(0x49, 0x89, 0x6d, 0x07),
        PIS_X86_CPUMODE_64_BIT,
        EXPECTED_INSNS(
            PIS_INSN(PIS_OPCODE_MOVE, addr_tmp, R13),
            PIS_INSN(PIS_OPCODE_ADD, addr_tmp, PIS_OPERAND_CONST(0x7, PIS_OPERAND_SIZE_8)),
            PIS_INSN(PIS_OPCODE_STORE, addr_tmp, RBP)
        )
    ));

    CHECK_RETHROW_VERBOSE(generic_test_lift(
        CODE(0x48, 0x89, 0x48, 0x02),
        PIS_X86_CPUMODE_64_BIT,
        EXPECTED_INSNS(
            PIS_INSN(PIS_OPCODE_MOVE, addr_tmp, RAX),
            PIS_INSN(PIS_OPCODE_ADD, addr_tmp, PIS_OPERAND_CONST(0x2, PIS_OPERAND_SIZE_8)),
            PIS_INSN(PIS_OPCODE_STORE, addr_tmp, RCX)
        )
    ));

    CHECK_RETHROW_VERBOSE(generic_test_lift(
        CODE(0x4d, 0x89, 0x48, 0xfa),
        PIS_X86_CPUMODE_64_BIT,
        EXPECTED_INSNS(
            PIS_INSN(PIS_OPCODE_MOVE, addr_tmp, R8),
            PIS_INSN(
                PIS_OPCODE_ADD,
                addr_tmp,
                PIS_OPERAND_CONST(0xfffffffffffffffa, PIS_OPERAND_SIZE_8)
            ),
            PIS_INSN(PIS_OPCODE_STORE, addr_tmp, R9)
        )
    ));

    CHECK_RETHROW_VERBOSE(generic_test_lift(
        CODE(0x49, 0x89, 0x9a, 0x44, 0x33, 0x22, 0x11),
        PIS_X86_CPUMODE_64_BIT,
        EXPECTED_INSNS(
            PIS_INSN(PIS_OPCODE_MOVE, addr_tmp, R10),
            PIS_INSN(PIS_OPCODE_ADD, addr_tmp, PIS_OPERAND_CONST(0x11223344, PIS_OPERAND_SIZE_8)),
            PIS_INSN(PIS_OPCODE_STORE, addr_tmp, RBX)
        )
    ));

    CHECK_RETHROW_VERBOSE(generic_test_lift(
        CODE(0x4c, 0x89, 0x9a, 0xbc, 0xbc, 0xbd, 0xbe),
        PIS_X86_CPUMODE_64_BIT,
        EXPECTED_INSNS(
            PIS_INSN(PIS_OPCODE_MOVE, addr_tmp, RDX),
            PIS_INSN(
                PIS_OPCODE_ADD,
                addr_tmp,
                PIS_OPERAND_CONST_NEG(0x41424344, PIS_OPERAND_SIZE_8)
            ),
            PIS_INSN(PIS_OPCODE_STORE, addr_tmp, R11)
        )
    ));

    CHECK_RETHROW_VERBOSE(generic_test_lift(
        CODE(0x4a, 0x89, 0x1c, 0xa0),
        PIS_X86_CPUMODE_64_BIT,
        EXPECTED_INSNS(
            PIS_INSN(PIS_OPCODE_MOVE, addr_tmp, RAX),
            PIS_INSN(PIS_OPCODE_MOVE, sib_tmp, R12),
            PIS_INSN(PIS_OPCODE_MUL, sib_tmp, PIS_OPERAND_CONST(4, PIS_OPERAND_SIZE_8)),
            PIS_INSN(PIS_OPCODE_ADD, addr_tmp, sib_tmp),
            PIS_INSN(PIS_OPCODE_STORE, addr_tmp, RBX)
        )
    ));

    CHECK_RETHROW_VERBOSE(generic_test_lift(
        CODE(0x48, 0x89, 0x14, 0x24),
        PIS_X86_CPUMODE_64_BIT,
        EXPECTED_INSNS(
            PIS_INSN(PIS_OPCODE_MOVE, addr_tmp, RSP),
            PIS_INSN(PIS_OPCODE_STORE, addr_tmp, RDX)
        )
    ));

    CHECK_RETHROW_VERBOSE(generic_test_lift(
        CODE(0x4c, 0x89, 0x04, 0xbd, 0x00, 0x00, 0x00, 0x00),
        PIS_X86_CPUMODE_64_BIT,
        EXPECTED_INSNS(
            PIS_INSN(PIS_OPCODE_MOVE, addr_tmp, PIS_OPERAND_CONST(0, PIS_OPERAND_SIZE_8)),
            PIS_INSN(PIS_OPCODE_MOVE, sib_tmp, RDI),
            PIS_INSN(PIS_OPCODE_MUL, sib_tmp, PIS_OPERAND_CONST(4, PIS_OPERAND_SIZE_8)),
            PIS_INSN(PIS_OPCODE_ADD, addr_tmp, sib_tmp),
            PIS_INSN(PIS_OPCODE_STORE, addr_tmp, R8)
        )
    ));

    CHECK_RETHROW_VERBOSE(generic_test_lift(
        CODE(0x4a, 0x89, 0x64, 0x4d, 0x00),
        PIS_X86_CPUMODE_64_BIT,
        EXPECTED_INSNS(
            PIS_INSN(PIS_OPCODE_MOVE, addr_tmp, RBP),
            PIS_INSN(PIS_OPCODE_MOVE, sib_tmp, R9),
            PIS_INSN(PIS_OPCODE_MUL, sib_tmp, PIS_OPERAND_CONST(2, PIS_OPERAND_SIZE_8)),
            PIS_INSN(PIS_OPCODE_ADD, addr_tmp, sib_tmp),
            PIS_INSN(PIS_OPCODE_ADD, addr_tmp, PIS_OPERAND_CONST(0, PIS_OPERAND_SIZE_8)),
            PIS_INSN(PIS_OPCODE_STORE, addr_tmp, RSP)
        )
    ));

    CHECK_RETHROW_VERBOSE(generic_test_lift(
        CODE(0x4d, 0x89, 0x74, 0x4d, 0x00),
        PIS_X86_CPUMODE_64_BIT,
        EXPECTED_INSNS(
            PIS_INSN(PIS_OPCODE_MOVE, addr_tmp, R13),
            PIS_INSN(PIS_OPCODE_MOVE, sib_tmp, RCX),
            PIS_INSN(PIS_OPCODE_MUL, sib_tmp, PIS_OPERAND_CONST(2, PIS_OPERAND_SIZE_8)),
            PIS_INSN(PIS_OPCODE_ADD, addr_tmp, sib_tmp),
            PIS_INSN(PIS_OPCODE_ADD, addr_tmp, PIS_OPERAND_CONST(0, PIS_OPERAND_SIZE_8)),
            PIS_INSN(PIS_OPCODE_STORE, addr_tmp, R14)
        )
    ));

    CHECK_RETHROW_VERBOSE(generic_test_lift(
        CODE(0x4f, 0x89, 0x64, 0xfa, 0xfd),
        PIS_X86_CPUMODE_64_BIT,
        EXPECTED_INSNS(
            PIS_INSN(PIS_OPCODE_MOVE, addr_tmp, R10),
            PIS_INSN(PIS_OPCODE_MOVE, sib_tmp, R15),
            PIS_INSN(PIS_OPCODE_MUL, sib_tmp, PIS_OPERAND_CONST(8, PIS_OPERAND_SIZE_8)),
            PIS_INSN(PIS_OPCODE_ADD, addr_tmp, sib_tmp),
            PIS_INSN(
                PIS_OPCODE_ADD,
                addr_tmp,
                PIS_OPERAND_CONST(0xfffffffffffffffd, PIS_OPERAND_SIZE_8)
            ),
            PIS_INSN(PIS_OPCODE_STORE, addr_tmp, R12)
        )
    ));

    CHECK_RETHROW_VERBOSE(generic_test_lift(
        CODE(0x4e, 0x89, 0xa4, 0x06, 0xcc, 0xed, 0xcb, 0xed),
        PIS_X86_CPUMODE_64_BIT,
        EXPECTED_INSNS(
            PIS_INSN(PIS_OPCODE_MOVE, addr_tmp, RSI),
            PIS_INSN(PIS_OPCODE_MOVE, sib_tmp, R8),
            PIS_INSN(PIS_OPCODE_MUL, sib_tmp, PIS_OPERAND_CONST(1, PIS_OPERAND_SIZE_8)),
            PIS_INSN(PIS_OPCODE_ADD, addr_tmp, sib_tmp),
            PIS_INSN(
                PIS_OPCODE_ADD,
                addr_tmp,
                PIS_OPERAND_CONST_NEG(0x12341234, PIS_OPERAND_SIZE_8)
            ),
            PIS_INSN(PIS_OPCODE_STORE, addr_tmp, R12)
        )
    ));

cleanup:
    return err;
}

DEFINE_TEST(test_mov_32_bit_mode) {
    err_t err = SUCCESS;
    pis_operand_t addr_tmp = PIS_OPERAND(g_modrm_rm_tmp_addr, PIS_OPERAND_SIZE_4);
    pis_operand_t addr16_tmp = PIS_OPERAND(g_modrm_rm_tmp_addr, PIS_OPERAND_SIZE_2);
    pis_operand_t sib_tmp = PIS_OPERAND(g_sib_index_tmp_addr, PIS_OPERAND_SIZE_4);

    CHECK_RETHROW_VERBOSE(generic_test_lift(
        CODE(0x89, 0xe5),
        PIS_X86_CPUMODE_32_BIT,
        EXPECTED_INSNS(PIS_INSN(PIS_OPCODE_MOVE, EBP, ESP))
    ));

    CHECK_RETHROW_VERBOSE(generic_test_lift(
        CODE(0x89, 0xce),
        PIS_X86_CPUMODE_32_BIT,
        EXPECTED_INSNS(PIS_INSN(PIS_OPCODE_MOVE, ESI, ECX))
    ));

    CHECK_RETHROW_VERBOSE(generic_test_lift(
        CODE(0x89, 0x35, 0x78, 0x56, 0x34, 0x12),
        PIS_X86_CPUMODE_32_BIT,
        EXPECTED_INSNS(
            PIS_INSN(PIS_OPCODE_MOVE, addr_tmp, PIS_OPERAND_CONST(0x12345678, PIS_OPERAND_SIZE_4)),
            PIS_INSN(PIS_OPCODE_STORE, addr_tmp, ESI)
        )
    ));

    CHECK_RETHROW_VERBOSE(generic_test_lift(
        CODE(0x89, 0x43, 0x03),
        PIS_X86_CPUMODE_32_BIT,
        EXPECTED_INSNS(
            PIS_INSN(PIS_OPCODE_MOVE, addr_tmp, EBX),
            PIS_INSN(PIS_OPCODE_ADD, addr_tmp, PIS_OPERAND_CONST(0x3, PIS_OPERAND_SIZE_4)),
            PIS_INSN(PIS_OPCODE_STORE, addr_tmp, EAX)
        )
    ));

    CHECK_RETHROW_VERBOSE(generic_test_lift(
        CODE(0x89, 0x67, 0xfe),
        PIS_X86_CPUMODE_32_BIT,
        EXPECTED_INSNS(
            PIS_INSN(PIS_OPCODE_MOVE, addr_tmp, EDI),
            PIS_INSN(PIS_OPCODE_ADD, addr_tmp, PIS_OPERAND_CONST(0xfffffffe, PIS_OPERAND_SIZE_4)),
            PIS_INSN(PIS_OPCODE_STORE, addr_tmp, ESP)
        )
    ));

    CHECK_RETHROW_VERBOSE(generic_test_lift(
        CODE(0x89, 0x55, 0x7f),
        PIS_X86_CPUMODE_32_BIT,
        EXPECTED_INSNS(
            PIS_INSN(PIS_OPCODE_MOVE, addr_tmp, EBP),
            PIS_INSN(PIS_OPCODE_ADD, addr_tmp, PIS_OPERAND_CONST(0x7f, PIS_OPERAND_SIZE_4)),
            PIS_INSN(PIS_OPCODE_STORE, addr_tmp, EDX)
        )
    ));

    CHECK_RETHROW_VERBOSE(generic_test_lift(
        CODE(0x89, 0xa8, 0x44, 0x33, 0x22, 0x11),
        PIS_X86_CPUMODE_32_BIT,
        EXPECTED_INSNS(
            PIS_INSN(PIS_OPCODE_MOVE, addr_tmp, EAX),
            PIS_INSN(PIS_OPCODE_ADD, addr_tmp, PIS_OPERAND_CONST(0x11223344, PIS_OPERAND_SIZE_4)),
            PIS_INSN(PIS_OPCODE_STORE, addr_tmp, EBP)
        )
    ));

    CHECK_RETHROW_VERBOSE(generic_test_lift(
        CODE(0x89, 0x9d, 0xbc, 0xbc, 0xbd, 0xbe),
        PIS_X86_CPUMODE_32_BIT,
        EXPECTED_INSNS(
            PIS_INSN(PIS_OPCODE_MOVE, addr_tmp, EBP),
            PIS_INSN(
                PIS_OPCODE_ADD,
                addr_tmp,
                PIS_OPERAND_CONST_NEG(0x41424344, PIS_OPERAND_SIZE_4)
            ),
            PIS_INSN(PIS_OPCODE_STORE, addr_tmp, EBX)
        )
    ));

    CHECK_RETHROW_VERBOSE(generic_test_lift(
        CODE(0x89, 0x1c, 0x06),
        PIS_X86_CPUMODE_32_BIT,
        EXPECTED_INSNS(
            PIS_INSN(PIS_OPCODE_MOVE, addr_tmp, ESI),
            PIS_INSN(PIS_OPCODE_MOVE, sib_tmp, EAX),
            PIS_INSN(PIS_OPCODE_MUL, sib_tmp, PIS_OPERAND_CONST(1, PIS_OPERAND_SIZE_4)),
            PIS_INSN(PIS_OPCODE_ADD, addr_tmp, sib_tmp),
            PIS_INSN(PIS_OPCODE_STORE, addr_tmp, EBX)
        )
    ));

    CHECK_RETHROW_VERBOSE(generic_test_lift(
        CODE(0x89, 0x0c, 0x24),
        PIS_X86_CPUMODE_32_BIT,
        EXPECTED_INSNS(
            PIS_INSN(PIS_OPCODE_MOVE, addr_tmp, ESP),
            PIS_INSN(PIS_OPCODE_STORE, addr_tmp, ECX)
        )
    ));

    CHECK_RETHROW_VERBOSE(generic_test_lift(
        CODE(0x89, 0x2c, 0x95, 0x78, 0x56, 0x34, 0x12),
        PIS_X86_CPUMODE_32_BIT,
        EXPECTED_INSNS(
            PIS_INSN(PIS_OPCODE_MOVE, addr_tmp, PIS_OPERAND_CONST(0x12345678, PIS_OPERAND_SIZE_4)),
            PIS_INSN(PIS_OPCODE_MOVE, sib_tmp, EDX),
            PIS_INSN(PIS_OPCODE_MUL, sib_tmp, PIS_OPERAND_CONST(4, PIS_OPERAND_SIZE_4)),
            PIS_INSN(PIS_OPCODE_ADD, addr_tmp, sib_tmp),
            PIS_INSN(PIS_OPCODE_STORE, addr_tmp, EBP)
        )
    ));

    CHECK_RETHROW_VERBOSE(generic_test_lift(
        CODE(0x89, 0x2c, 0x25, 0x78, 0x56, 0x34, 0x12),
        PIS_X86_CPUMODE_32_BIT,
        EXPECTED_INSNS(
            PIS_INSN(PIS_OPCODE_MOVE, addr_tmp, PIS_OPERAND_CONST(0x12345678, PIS_OPERAND_SIZE_4)),
            PIS_INSN(PIS_OPCODE_STORE, addr_tmp, EBP)
        )
    ));

    CHECK_RETHROW_VERBOSE(generic_test_lift(
        CODE(0x89, 0x7c, 0xed, 0x01),
        PIS_X86_CPUMODE_32_BIT,
        EXPECTED_INSNS(
            PIS_INSN(PIS_OPCODE_MOVE, addr_tmp, EBP),
            PIS_INSN(PIS_OPCODE_MOVE, sib_tmp, EBP),
            PIS_INSN(PIS_OPCODE_MUL, sib_tmp, PIS_OPERAND_CONST(8, PIS_OPERAND_SIZE_4)),
            PIS_INSN(PIS_OPCODE_ADD, addr_tmp, sib_tmp),
            PIS_INSN(PIS_OPCODE_ADD, addr_tmp, PIS_OPERAND_CONST(1, PIS_OPERAND_SIZE_4)),
            PIS_INSN(PIS_OPCODE_STORE, addr_tmp, EDI)
        )
    ));

    CHECK_RETHROW_VERBOSE(generic_test_lift(
        CODE(0x89, 0x4c, 0x5d, 0xfc),
        PIS_X86_CPUMODE_32_BIT,
        EXPECTED_INSNS(
            PIS_INSN(PIS_OPCODE_MOVE, addr_tmp, EBP),
            PIS_INSN(PIS_OPCODE_MOVE, sib_tmp, EBX),
            PIS_INSN(PIS_OPCODE_MUL, sib_tmp, PIS_OPERAND_CONST(2, PIS_OPERAND_SIZE_4)),
            PIS_INSN(PIS_OPCODE_ADD, addr_tmp, sib_tmp),
            PIS_INSN(PIS_OPCODE_ADD, addr_tmp, PIS_OPERAND_CONST(0xfffffffc, PIS_OPERAND_SIZE_4)),
            PIS_INSN(PIS_OPCODE_STORE, addr_tmp, ECX)
        )
    ));

    CHECK_RETHROW_VERBOSE(generic_test_lift(
        CODE(0x89, 0xb4, 0x05, 0x44, 0x33, 0x22, 0x11),
        PIS_X86_CPUMODE_32_BIT,
        EXPECTED_INSNS(
            PIS_INSN(PIS_OPCODE_MOVE, addr_tmp, EBP),
            PIS_INSN(PIS_OPCODE_MOVE, sib_tmp, EAX),
            PIS_INSN(PIS_OPCODE_MUL, sib_tmp, PIS_OPERAND_CONST(1, PIS_OPERAND_SIZE_4)),
            PIS_INSN(PIS_OPCODE_ADD, addr_tmp, sib_tmp),
            PIS_INSN(PIS_OPCODE_ADD, addr_tmp, PIS_OPERAND_CONST(0x11223344, PIS_OPERAND_SIZE_4)),
            PIS_INSN(PIS_OPCODE_STORE, addr_tmp, ESI)
        )
    ));

    CHECK_RETHROW_VERBOSE(generic_test_lift(
        CODE(0x89, 0xa4, 0x55, 0xbc, 0xbc, 0xbd, 0xbe),
        PIS_X86_CPUMODE_32_BIT,
        EXPECTED_INSNS(
            PIS_INSN(PIS_OPCODE_MOVE, addr_tmp, EBP),
            PIS_INSN(PIS_OPCODE_MOVE, sib_tmp, EDX),
            PIS_INSN(PIS_OPCODE_MUL, sib_tmp, PIS_OPERAND_CONST(2, PIS_OPERAND_SIZE_4)),
            PIS_INSN(PIS_OPCODE_ADD, addr_tmp, sib_tmp),
            PIS_INSN(
                PIS_OPCODE_ADD,
                addr_tmp,
                PIS_OPERAND_CONST_NEG(0x41424344, PIS_OPERAND_SIZE_4)
            ),
            PIS_INSN(PIS_OPCODE_STORE, addr_tmp, ESP)
        )
    ));

    CHECK_RETHROW_VERBOSE(generic_test_lift(
        CODE(0x89, 0x7c, 0xf1, 0x01),
        PIS_X86_CPUMODE_32_BIT,
        EXPECTED_INSNS(
            PIS_INSN(PIS_OPCODE_MOVE, addr_tmp, ECX),
            PIS_INSN(PIS_OPCODE_MOVE, sib_tmp, ESI),
            PIS_INSN(PIS_OPCODE_MUL, sib_tmp, PIS_OPERAND_CONST(8, PIS_OPERAND_SIZE_4)),
            PIS_INSN(PIS_OPCODE_ADD, addr_tmp, sib_tmp),
            PIS_INSN(PIS_OPCODE_ADD, addr_tmp, PIS_OPERAND_CONST(1, PIS_OPERAND_SIZE_4)),
            PIS_INSN(PIS_OPCODE_STORE, addr_tmp, EDI)
        )
    ));

    CHECK_RETHROW_VERBOSE(generic_test_lift(
        CODE(0x89, 0x6c, 0x58, 0xfd),
        PIS_X86_CPUMODE_32_BIT,
        EXPECTED_INSNS(
            PIS_INSN(PIS_OPCODE_MOVE, addr_tmp, EAX),
            PIS_INSN(PIS_OPCODE_MOVE, sib_tmp, EBX),
            PIS_INSN(PIS_OPCODE_MUL, sib_tmp, PIS_OPERAND_CONST(2, PIS_OPERAND_SIZE_4)),
            PIS_INSN(PIS_OPCODE_ADD, addr_tmp, sib_tmp),
            PIS_INSN(PIS_OPCODE_ADD, addr_tmp, PIS_OPERAND_CONST(0xfffffffd, PIS_OPERAND_SIZE_4)),
            PIS_INSN(PIS_OPCODE_STORE, addr_tmp, EBP)
        )
    ));

    CHECK_RETHROW_VERBOSE(generic_test_lift(
        CODE(0x89, 0xa4, 0x8c, 0x44, 0x33, 0x22, 0x11),
        PIS_X86_CPUMODE_32_BIT,
        EXPECTED_INSNS(
            PIS_INSN(PIS_OPCODE_MOVE, addr_tmp, ESP),
            PIS_INSN(PIS_OPCODE_MOVE, sib_tmp, ECX),
            PIS_INSN(PIS_OPCODE_MUL, sib_tmp, PIS_OPERAND_CONST(4, PIS_OPERAND_SIZE_4)),
            PIS_INSN(PIS_OPCODE_ADD, addr_tmp, sib_tmp),
            PIS_INSN(PIS_OPCODE_ADD, addr_tmp, PIS_OPERAND_CONST(0x11223344, PIS_OPERAND_SIZE_4)),
            PIS_INSN(PIS_OPCODE_STORE, addr_tmp, ESP)
        )
    ));

    CHECK_RETHROW_VERBOSE(generic_test_lift(
        CODE(0x67, 0x89, 0x82, 0x34, 0x12),
        PIS_X86_CPUMODE_32_BIT,
        EXPECTED_INSNS(
            PIS_INSN(PIS_OPCODE_MOVE, addr16_tmp, BP),
            PIS_INSN(PIS_OPCODE_ADD, addr16_tmp, SI),
            PIS_INSN(PIS_OPCODE_ADD, addr16_tmp, PIS_OPERAND_CONST(0x1234, PIS_OPERAND_SIZE_2)),
            PIS_INSN(PIS_OPCODE_STORE, addr16_tmp, EAX)
        )
    ));

    CHECK_RETHROW_VERBOSE(generic_test_lift(
        CODE(0x66, 0x89, 0x44, 0x58, 0xfd),
        PIS_X86_CPUMODE_32_BIT,
        EXPECTED_INSNS(
            PIS_INSN(PIS_OPCODE_MOVE, addr_tmp, EAX),
            PIS_INSN(PIS_OPCODE_MOVE, sib_tmp, EBX),
            PIS_INSN(PIS_OPCODE_MUL, sib_tmp, PIS_OPERAND_CONST(2, PIS_OPERAND_SIZE_4)),
            PIS_INSN(PIS_OPCODE_ADD, addr_tmp, sib_tmp),
            PIS_INSN(PIS_OPCODE_ADD, addr_tmp, PIS_OPERAND_CONST(0xfffffffd, PIS_OPERAND_SIZE_4)),
            PIS_INSN(PIS_OPCODE_STORE, addr_tmp, AX)
        )
    ));

    CHECK_RETHROW_VERBOSE(generic_test_lift(
        CODE(0x66, 0x67, 0x89, 0x88, 0x34, 0x12),
        PIS_X86_CPUMODE_32_BIT,
        EXPECTED_INSNS(
            PIS_INSN(PIS_OPCODE_MOVE, addr16_tmp, BX),
            PIS_INSN(PIS_OPCODE_ADD, addr16_tmp, SI),
            PIS_INSN(PIS_OPCODE_ADD, addr16_tmp, PIS_OPERAND_CONST(0x1234, PIS_OPERAND_SIZE_2)),
            PIS_INSN(PIS_OPCODE_STORE, addr16_tmp, CX)
        )
    ));

cleanup:
    return err;
}

DEFINE_TEST(test_mov_16_bit_mode) {
    err_t err = SUCCESS;
    pis_operand_t addr_tmp = PIS_OPERAND(g_modrm_rm_tmp_addr, PIS_OPERAND_SIZE_2);
    pis_operand_t addr32_tmp = PIS_OPERAND(g_modrm_rm_tmp_addr, PIS_OPERAND_SIZE_4);
    pis_operand_t sib_tmp = PIS_OPERAND(g_sib_index_tmp_addr, PIS_OPERAND_SIZE_4);

    CHECK_RETHROW_VERBOSE(generic_test_lift(
        CODE(0x89, 0xe5),
        PIS_X86_CPUMODE_16_BIT,
        EXPECTED_INSNS(PIS_INSN(PIS_OPCODE_MOVE, BP, SP))
    ));

    CHECK_RETHROW_VERBOSE(generic_test_lift(
        CODE(0x89, 0xce),
        PIS_X86_CPUMODE_16_BIT,
        EXPECTED_INSNS(PIS_INSN(PIS_OPCODE_MOVE, SI, CX))
    ));

    CHECK_RETHROW_VERBOSE(generic_test_lift(
        CODE(0x89, 0x0f),
        PIS_X86_CPUMODE_16_BIT,
        EXPECTED_INSNS(
            PIS_INSN(PIS_OPCODE_MOVE, addr_tmp, BX),
            PIS_INSN(PIS_OPCODE_STORE, addr_tmp, CX)
        )
    ));
    CHECK_RETHROW_VERBOSE(generic_test_lift(
        CODE(0x89, 0x12),
        PIS_X86_CPUMODE_16_BIT,
        EXPECTED_INSNS(
            PIS_INSN(PIS_OPCODE_MOVE, addr_tmp, BP),
            PIS_INSN(PIS_OPCODE_ADD, addr_tmp, SI),
            PIS_INSN(PIS_OPCODE_STORE, addr_tmp, DX)
        )
    ));

    CHECK_RETHROW_VERBOSE(generic_test_lift(
        CODE(0x89, 0x3e, 0x34, 0x12),
        PIS_X86_CPUMODE_16_BIT,
        EXPECTED_INSNS(
            PIS_INSN(PIS_OPCODE_MOVE, addr_tmp, PIS_OPERAND_CONST(0x1234, PIS_OPERAND_SIZE_2)),
            PIS_INSN(PIS_OPCODE_STORE, addr_tmp, DI)
        )
    ));

    CHECK_RETHROW_VERBOSE(generic_test_lift(
        CODE(0x89, 0x44, 0x05),
        PIS_X86_CPUMODE_16_BIT,
        EXPECTED_INSNS(
            PIS_INSN(PIS_OPCODE_MOVE, addr_tmp, SI),
            PIS_INSN(PIS_OPCODE_ADD, addr_tmp, PIS_OPERAND_CONST(0x5, PIS_OPERAND_SIZE_2)),
            PIS_INSN(PIS_OPCODE_STORE, addr_tmp, AX)
        )
    ));

    CHECK_RETHROW_VERBOSE(generic_test_lift(
        CODE(0x89, 0x59, 0xff),
        PIS_X86_CPUMODE_16_BIT,
        EXPECTED_INSNS(
            PIS_INSN(PIS_OPCODE_MOVE, addr_tmp, BX),
            PIS_INSN(PIS_OPCODE_ADD, addr_tmp, DI),
            PIS_INSN(PIS_OPCODE_ADD, addr_tmp, PIS_OPERAND_CONST(0xffff, PIS_OPERAND_SIZE_2)),
            PIS_INSN(PIS_OPCODE_STORE, addr_tmp, BX)
        )
    ));

    CHECK_RETHROW_VERBOSE(generic_test_lift(
        CODE(0x89, 0x76, 0x7f),
        PIS_X86_CPUMODE_16_BIT,
        EXPECTED_INSNS(
            PIS_INSN(PIS_OPCODE_MOVE, addr_tmp, BP),
            PIS_INSN(PIS_OPCODE_ADD, addr_tmp, PIS_OPERAND_CONST(0x7f, PIS_OPERAND_SIZE_2)),
            PIS_INSN(PIS_OPCODE_STORE, addr_tmp, SI)
        )
    ));

    CHECK_RETHROW_VERBOSE(generic_test_lift(
        CODE(0x89, 0x88, 0x34, 0x12),
        PIS_X86_CPUMODE_16_BIT,
        EXPECTED_INSNS(
            PIS_INSN(PIS_OPCODE_MOVE, addr_tmp, BX),
            PIS_INSN(PIS_OPCODE_ADD, addr_tmp, SI),
            PIS_INSN(PIS_OPCODE_ADD, addr_tmp, PIS_OPERAND_CONST(0x1234, PIS_OPERAND_SIZE_2)),
            PIS_INSN(PIS_OPCODE_STORE, addr_tmp, CX)
        )
    ));

    CHECK_RETHROW_VERBOSE(generic_test_lift(
        CODE(0x89, 0x96, 0xcc, 0xed),
        PIS_X86_CPUMODE_16_BIT,
        EXPECTED_INSNS(
            PIS_INSN(PIS_OPCODE_MOVE, addr_tmp, BP),
            PIS_INSN(PIS_OPCODE_ADD, addr_tmp, PIS_OPERAND_CONST_NEG(0x1234, PIS_OPERAND_SIZE_2)),
            PIS_INSN(PIS_OPCODE_STORE, addr_tmp, DX)
        )
    ));

    CHECK_RETHROW_VERBOSE(generic_test_lift(
        CODE(0x66, 0x89, 0x82, 0x34, 0x12),
        PIS_X86_CPUMODE_16_BIT,
        EXPECTED_INSNS(
            PIS_INSN(PIS_OPCODE_MOVE, addr_tmp, BP),
            PIS_INSN(PIS_OPCODE_ADD, addr_tmp, SI),
            PIS_INSN(PIS_OPCODE_ADD, addr_tmp, PIS_OPERAND_CONST(0x1234, PIS_OPERAND_SIZE_2)),
            PIS_INSN(PIS_OPCODE_STORE, addr_tmp, EAX)
        )
    ));

    CHECK_RETHROW_VERBOSE(generic_test_lift(
        CODE(0x67, 0x89, 0x44, 0x58, 0xfd),
        PIS_X86_CPUMODE_16_BIT,
        EXPECTED_INSNS(
            PIS_INSN(PIS_OPCODE_MOVE, addr32_tmp, EAX),
            PIS_INSN(PIS_OPCODE_MOVE, sib_tmp, EBX),
            PIS_INSN(PIS_OPCODE_MUL, sib_tmp, PIS_OPERAND_CONST(2, PIS_OPERAND_SIZE_4)),
            PIS_INSN(PIS_OPCODE_ADD, addr32_tmp, sib_tmp),
            PIS_INSN(PIS_OPCODE_ADD, addr32_tmp, PIS_OPERAND_CONST(0xfffffffd, PIS_OPERAND_SIZE_4)),
            PIS_INSN(PIS_OPCODE_STORE, addr32_tmp, AX)
        )
    ));

    CHECK_RETHROW_VERBOSE(generic_test_lift(
        CODE(0x66, 0x67, 0x89, 0x64, 0x58, 0xfd),
        PIS_X86_CPUMODE_16_BIT,
        EXPECTED_INSNS(
            PIS_INSN(PIS_OPCODE_MOVE, addr32_tmp, EAX),
            PIS_INSN(PIS_OPCODE_MOVE, sib_tmp, EBX),
            PIS_INSN(PIS_OPCODE_MUL, sib_tmp, PIS_OPERAND_CONST(2, PIS_OPERAND_SIZE_4)),
            PIS_INSN(PIS_OPCODE_ADD, addr32_tmp, sib_tmp),
            PIS_INSN(PIS_OPCODE_ADD, addr32_tmp, PIS_OPERAND_CONST_NEG(3, PIS_OPERAND_SIZE_4)),
            PIS_INSN(PIS_OPCODE_STORE, addr32_tmp, ESP)
        )
    ));

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
