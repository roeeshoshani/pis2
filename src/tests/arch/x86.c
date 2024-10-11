#include "../test_utils.h"
#include "arch/x86/ctx.h"
#include "arch/x86/regs.h"
#include "emu.h"
#include "errors.h"
#include "except.h"
#include "pis.h"
#include "utils.h"
#include <stdarg.h>
#include <stdio.h>


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
            TRACE("instruction mismatch at index %lu", i);
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

static err_t generic_test_lift_at_addr(
    code_t code, pis_x86_cpumode_t cpumode, expected_insns_t expected, u64 addr
) {
    err_t err = SUCCESS;

    pis_lift_result_t result = {};

    pis_x86_ctx_t ctx = {
        .cpumode = cpumode,
    };

    CHECK_RETHROW_VERBOSE(pis_x86_lift(&ctx, code.code, code.len, addr, &result));

    CHECK_RETHROW_VERBOSE(assert_pis_lift_result_equals(&result, expected));

    CHECK_TRACE(
        result.machine_insn_len == code.len,
        "expected the instruction to be %lu bytes, instead it was %lu bytes",
        code.len,
        result.machine_insn_len
    );

cleanup:
    return err;
}

static err_t generic_test_lift(code_t code, pis_x86_cpumode_t cpumode, expected_insns_t expected) {
    err_t err = SUCCESS;

    CHECK_RETHROW_VERBOSE(generic_test_lift_at_addr(code, cpumode, expected, 0));

cleanup:
    return err;
}

static err_t emulate_insn(pis_emu_t* emu, code_t code, pis_x86_cpumode_t cpumode, u64 addr) {
    err_t err = SUCCESS;

    pis_lift_result_t result = {};

    pis_x86_ctx_t ctx = {
        .cpumode = cpumode,
    };

    CHECK_RETHROW_VERBOSE(pis_x86_lift(&ctx, code.code, code.len, addr, &result));

    CHECK_TRACE(
        result.machine_insn_len == code.len,
        "expected the instruction to be %lu bytes, instead it was %lu bytes",
        code.len,
        result.machine_insn_len
    );

    CHECK_RETHROW_VERBOSE(pis_emu_run(emu, &result));

cleanup:
    return err;
}

static err_t emu_assert_operand_equals(
    const pis_emu_t* emu, const pis_operand_t* operand, u64 desired_value
) {
    err_t err = SUCCESS;
    u64 actual_value = 0;
    CHECK_RETHROW_VERBOSE(pis_emu_read_operand(emu, operand, &actual_value));

    CHECK(actual_value == desired_value);

cleanup:
    return err;
}

static err_t emu_assert_mem_value_equals(
    const pis_emu_t* emu, u64 addr, pis_operand_size_t value_size, u64 desired_value
) {
    err_t err = SUCCESS;
    u64 actual_value = 0;
    CHECK_RETHROW_VERBOSE(pis_emu_read_mem_value(emu, addr, value_size, &actual_value));

    CHECK_TRACE(
        actual_value == desired_value,
        "expected mem value 0x%lx instead got value 0x%lx at addr 0x%lx",
        desired_value,
        actual_value,
        addr
    );

cleanup:
    return err;
}

static err_t generic_test_mov_reg_reg(
    code_t code,
    pis_x86_cpumode_t cpumode,
    const pis_operand_t* dst_reg,
    const pis_operand_t* src_reg
) {
    err_t err = SUCCESS;

    CHECK(dst_reg->size == src_reg->size);
    pis_operand_size_t operand_size = dst_reg->size;

    u64 src_reg_val = MAGIC64_1 & pis_operand_size_max_unsigned_value(operand_size);

    pis_emu_init(&g_emu, PIS_ENDIANNESS_LITTLE);
    CHECK_RETHROW_VERBOSE(pis_emu_write_operand(&g_emu, src_reg, src_reg_val));
    CHECK_RETHROW_VERBOSE(emulate_insn(&g_emu, code, cpumode, 0));

    // make sure that the dst reg was written
    CHECK_RETHROW_VERBOSE(emu_assert_operand_equals(&g_emu, dst_reg, src_reg_val));

    // make sure that the src reg wasn't modified
    CHECK_RETHROW_VERBOSE(emu_assert_operand_equals(&g_emu, src_reg, src_reg_val));

cleanup:
    return err;
}

static err_t generic_test_mov_modrm_reg_at_addr(
    code_t code,
    u64 addr,
    pis_x86_cpumode_t cpumode,
    pis_operand_size_t addr_size,
    const pis_operand_t* addr_base_reg,
    const pis_operand_t* addr_index_reg,
    u8 addr_scale_multiplier,
    u64 addr_imm,
    const pis_operand_t* src_reg
) {
    err_t err = SUCCESS;

    if (addr_base_reg != NULL) {
        CHECK(addr_base_reg->size == addr_size);
    }
    if (addr_index_reg != NULL) {
        CHECK(addr_index_reg->size == addr_size);
    }

    u64 addr_max = pis_operand_size_max_unsigned_value(addr_size);
    CHECK(addr_imm <= addr_max);

    u64 src_reg_val = MAGIC64_1 & pis_operand_size_max_unsigned_value(src_reg->size);
    u64 base_reg_val = 0;
    if (addr_base_reg != NULL) {
        base_reg_val = MAGIC64_2 & pis_operand_size_max_unsigned_value(addr_base_reg->size);
    }
    u64 index_reg_val = 0;
    if (addr_index_reg != NULL) {
        index_reg_val = MAGIC64_2 & pis_operand_size_max_unsigned_value(addr_index_reg->size);
    }

    pis_emu_init(&g_emu, PIS_ENDIANNESS_LITTLE);

    // prepare regs with magic values
    CHECK_RETHROW_VERBOSE(pis_emu_write_operand(&g_emu, src_reg, src_reg_val));
    if (addr_base_reg != NULL) {
        CHECK_RETHROW_VERBOSE(pis_emu_write_operand(&g_emu, addr_base_reg, base_reg_val));
    }
    if (addr_index_reg != NULL) {
        CHECK_RETHROW_VERBOSE(pis_emu_write_operand(&g_emu, addr_index_reg, index_reg_val));
    }

    // read back the values after writing to account for the case where the same register is used
    // for multiple purposes, in which case later writes will overwrite the value written in the
    // previous ones.
    CHECK_RETHROW_VERBOSE(pis_emu_read_operand(&g_emu, src_reg, &src_reg_val));
    if (addr_base_reg != NULL) {
        CHECK_RETHROW_VERBOSE(pis_emu_read_operand(&g_emu, addr_base_reg, &base_reg_val));
    }
    if (addr_index_reg != NULL) {
        CHECK_RETHROW_VERBOSE(pis_emu_read_operand(&g_emu, addr_index_reg, &index_reg_val));
    }

    CHECK_RETHROW_VERBOSE(emulate_insn(&g_emu, code, cpumode, addr));

    // calculate the address where we wrote to
    u64 written_addr = base_reg_val + addr_imm;
    if (addr_index_reg != NULL) {
        written_addr += addr_scale_multiplier * index_reg_val;
    }
    written_addr &= addr_max;

    // check the written value
    CHECK_RETHROW_VERBOSE(
        emu_assert_mem_value_equals(&g_emu, written_addr, src_reg->size, src_reg_val)
    );

    // make sure the original regs weren't modified
    CHECK_RETHROW_VERBOSE(emu_assert_operand_equals(&g_emu, src_reg, src_reg_val));
    if (addr_base_reg != NULL) {
        CHECK_RETHROW_VERBOSE(emu_assert_operand_equals(&g_emu, addr_base_reg, base_reg_val));
    }
    if (addr_index_reg) {
        CHECK_RETHROW_VERBOSE(emu_assert_operand_equals(&g_emu, addr_index_reg, index_reg_val));
    }

cleanup:
    return err;
}

static err_t generic_test_mov_modrm_reg(
    code_t code,
    pis_x86_cpumode_t cpumode,
    pis_operand_size_t addr_size,
    const pis_operand_t* addr_base_reg,
    const pis_operand_t* addr_index_reg,
    u8 addr_scale_multiplier,
    u64 addr_imm,
    const pis_operand_t* src_reg
) {
    err_t err = SUCCESS;
    CHECK_RETHROW_VERBOSE(generic_test_mov_modrm_reg_at_addr(
        code,
        0,
        cpumode,
        addr_size,
        addr_base_reg,
        addr_index_reg,
        addr_scale_multiplier,
        addr_imm,
        src_reg
    ));
cleanup:
    return err;
}

DEFINE_TEST(test_modrm_64_bit_mode) {
    err_t err = SUCCESS;

    CHECK_RETHROW_VERBOSE(
        generic_test_mov_reg_reg(CODE(0x89, 0xe5), PIS_X86_CPUMODE_64_BIT, &EBP, &ESP)
    );

    CHECK_RETHROW_VERBOSE(
        generic_test_mov_reg_reg(CODE(0x48, 0x89, 0xe5), PIS_X86_CPUMODE_64_BIT, &RBP, &RSP)
    );

    CHECK_RETHROW_VERBOSE(
        generic_test_mov_reg_reg(CODE(0x4d, 0x89, 0xc8), PIS_X86_CPUMODE_64_BIT, &R8, &R9)
    );

    CHECK_RETHROW_VERBOSE(
        generic_test_mov_reg_reg(CODE(0x45, 0x89, 0xf4), PIS_X86_CPUMODE_64_BIT, &R12D, &R14D)
    );

    CHECK_RETHROW_VERBOSE(
        generic_test_mov_reg_reg(CODE(0x66, 0x41, 0x89, 0xe5), PIS_X86_CPUMODE_64_BIT, &R13W, &SP)
    );

    CHECK_RETHROW_VERBOSE(
        generic_test_mov_reg_reg(CODE(0x44, 0x89, 0xfe), PIS_X86_CPUMODE_64_BIT, &ESI, &R15D)
    );

    CHECK_RETHROW_VERBOSE(generic_test_mov_modrm_reg(
        CODE(0x4c, 0x89, 0x26),
        PIS_X86_CPUMODE_64_BIT,
        PIS_OPERAND_SIZE_8,
        &RSI,
        NULL,
        0,
        0,
        &R12
    ));

    CHECK_RETHROW_VERBOSE(generic_test_mov_modrm_reg(
        CODE(0x49, 0x89, 0x6d, 0x07),
        PIS_X86_CPUMODE_64_BIT,
        PIS_OPERAND_SIZE_8,
        &R13,
        NULL,
        0,
        0x7,
        &RBP
    ));

    CHECK_RETHROW_VERBOSE(generic_test_mov_modrm_reg(
        CODE(0x48, 0x89, 0x48, 0x02),
        PIS_X86_CPUMODE_64_BIT,
        PIS_OPERAND_SIZE_8,
        &RAX,
        NULL,
        0,
        0x2,
        &RCX
    ));

    CHECK_RETHROW_VERBOSE(generic_test_mov_modrm_reg(
        CODE(0x4d, 0x89, 0x48, 0xfa),
        PIS_X86_CPUMODE_64_BIT,
        PIS_OPERAND_SIZE_8,
        &R8,
        NULL,
        0,
        0xfffffffffffffffa,
        &R9
    ));

    CHECK_RETHROW_VERBOSE(generic_test_mov_modrm_reg(
        CODE(0x49, 0x89, 0x9a, 0x44, 0x33, 0x22, 0x11),
        PIS_X86_CPUMODE_64_BIT,
        PIS_OPERAND_SIZE_8,
        &R10,
        NULL,
        0,
        0x11223344,
        &RBX
    ));

    CHECK_RETHROW_VERBOSE(generic_test_mov_modrm_reg(
        CODE(0x4c, 0x89, 0x9a, 0xbc, 0xbc, 0xbd, 0xbe),
        PIS_X86_CPUMODE_64_BIT,
        PIS_OPERAND_SIZE_8,
        &RDX,
        NULL,
        0,
        0xffffffffbebdbcbc,
        &R11
    ));

    CHECK_RETHROW_VERBOSE(generic_test_mov_modrm_reg(
        CODE(0x4a, 0x89, 0x1c, 0xa0),
        PIS_X86_CPUMODE_64_BIT,
        PIS_OPERAND_SIZE_8,
        &RAX,
        &R12,
        4,
        0,
        &RBX
    ));

    CHECK_RETHROW_VERBOSE(generic_test_mov_modrm_reg(
        CODE(0x48, 0x89, 0x14, 0x24),
        PIS_X86_CPUMODE_64_BIT,
        PIS_OPERAND_SIZE_8,
        &RSP,
        NULL,
        0,
        0,
        &RDX
    ));

    CHECK_RETHROW_VERBOSE(generic_test_mov_modrm_reg(
        CODE(0x4c, 0x89, 0x04, 0xbd, 0x00, 0x00, 0x00, 0x00),
        PIS_X86_CPUMODE_64_BIT,
        PIS_OPERAND_SIZE_8,
        NULL,
        &RDI,
        4,
        0,
        &R8
    ));

    CHECK_RETHROW_VERBOSE(generic_test_mov_modrm_reg(
        CODE(0x4a, 0x89, 0x64, 0x4d, 0x00),
        PIS_X86_CPUMODE_64_BIT,
        PIS_OPERAND_SIZE_8,
        &RBP,
        &R9,
        2,
        0,
        &RSP
    ));

    CHECK_RETHROW_VERBOSE(generic_test_mov_modrm_reg(
        CODE(0x4d, 0x89, 0x74, 0x4d, 0x00),
        PIS_X86_CPUMODE_64_BIT,
        PIS_OPERAND_SIZE_8,
        &R13,
        &RCX,
        2,
        0,
        &R14
    ));

    CHECK_RETHROW_VERBOSE(generic_test_mov_modrm_reg(
        CODE(0x4f, 0x89, 0x64, 0xfa, 0xfd),
        PIS_X86_CPUMODE_64_BIT,
        PIS_OPERAND_SIZE_8,
        &R10,
        &R15,
        8,
        0xfffffffffffffffd,
        &R12
    ));

    CHECK_RETHROW_VERBOSE(generic_test_mov_modrm_reg(
        CODE(0x4e, 0x89, 0xa4, 0x06, 0xcc, 0xed, 0xcb, 0xed),
        PIS_X86_CPUMODE_64_BIT,
        PIS_OPERAND_SIZE_8,
        &RSI,
        &R8,
        1,
        0xffffffffedcbedcc,
        &R12
    ));

    CHECK_RETHROW_VERBOSE(generic_test_mov_modrm_reg(
        CODE(0x67, 0x89, 0xa4, 0x55, 0xbc, 0xbc, 0xbd, 0xbe),
        PIS_X86_CPUMODE_64_BIT,
        PIS_OPERAND_SIZE_4,
        &EBP,
        &EDX,
        2,
        0xbebdbcbc,
        &ESP
    ));

    CHECK_RETHROW_VERBOSE(generic_test_mov_modrm_reg(
        CODE(0x67, 0x4f, 0x89, 0x44, 0xf9, 0x05),
        PIS_X86_CPUMODE_64_BIT,
        PIS_OPERAND_SIZE_4,
        &R9D,
        &R15D,
        8,
        5,
        &R8
    ));

    CHECK_RETHROW_VERBOSE(generic_test_mov_modrm_reg(
        CODE(0x66, 0x42, 0x89, 0x44, 0xac, 0xff),
        PIS_X86_CPUMODE_64_BIT,
        PIS_OPERAND_SIZE_8,
        &RSP,
        &R13,
        4,
        0xffffffffffffffff,
        &AX
    ));

    CHECK_RETHROW_VERBOSE(generic_test_mov_modrm_reg(
        CODE(0x66, 0x67, 0x42, 0x89, 0x74, 0x65, 0x00),
        PIS_X86_CPUMODE_64_BIT,
        PIS_OPERAND_SIZE_4,
        &EBP,
        &R12D,
        2,
        0,
        &SI
    ));

    CHECK_RETHROW_VERBOSE(generic_test_mov_modrm_reg_at_addr(
        CODE(0x89, 0x05, 0x01, 0x00, 0x00, 0x00),
        0,
        PIS_X86_CPUMODE_64_BIT,
        PIS_OPERAND_SIZE_8,
        NULL,
        NULL,
        0,
        7,
        &EAX
    ));

    CHECK_RETHROW_VERBOSE(generic_test_mov_modrm_reg_at_addr(
        CODE(0x89, 0x05, 0x01, 0x00, 0x00, 0x00),
        1,
        PIS_X86_CPUMODE_64_BIT,
        PIS_OPERAND_SIZE_8,
        NULL,
        NULL,
        0,
        8,
        &EAX
    ));

    CHECK_RETHROW_VERBOSE(generic_test_mov_modrm_reg_at_addr(
        CODE(0x89, 0x05, 0xf6, 0xff, 0xff, 0xff),
        6,
        PIS_X86_CPUMODE_64_BIT,
        PIS_OPERAND_SIZE_8,
        NULL,
        NULL,
        0,
        2,
        &EAX
    ));

cleanup:
    return err;
}

DEFINE_TEST(test_modrm_32_bit_mode) {
    err_t err = SUCCESS;

    CHECK_RETHROW_VERBOSE(
        generic_test_mov_reg_reg(CODE(0x89, 0xe5), PIS_X86_CPUMODE_32_BIT, &EBP, &ESP)
    );

    CHECK_RETHROW_VERBOSE(
        generic_test_mov_reg_reg(CODE(0x89, 0xce), PIS_X86_CPUMODE_32_BIT, &ESI, &ECX)
    );

    CHECK_RETHROW_VERBOSE(generic_test_mov_modrm_reg(
        CODE(0x89, 0x35, 0x78, 0x56, 0x34, 0x12),
        PIS_X86_CPUMODE_32_BIT,
        PIS_OPERAND_SIZE_4,
        NULL,
        NULL,
        0,
        0x12345678,
        &ESI
    ));

    CHECK_RETHROW_VERBOSE(generic_test_mov_modrm_reg(
        CODE(0x89, 0x43, 0x03),
        PIS_X86_CPUMODE_32_BIT,
        PIS_OPERAND_SIZE_4,
        &EBX,
        NULL,
        0,
        3,
        &EAX
    ));

    CHECK_RETHROW_VERBOSE(generic_test_mov_modrm_reg(
        CODE(0x89, 0x67, 0xfe),
        PIS_X86_CPUMODE_32_BIT,
        PIS_OPERAND_SIZE_4,
        &EDI,
        NULL,
        0,
        0xfffffffe,
        &ESP
    ));

    CHECK_RETHROW_VERBOSE(generic_test_mov_modrm_reg(
        CODE(0x89, 0x55, 0x7f),
        PIS_X86_CPUMODE_32_BIT,
        PIS_OPERAND_SIZE_4,
        &EBP,
        NULL,
        0,
        0x7f,
        &EDX
    ));

    CHECK_RETHROW_VERBOSE(generic_test_mov_modrm_reg(
        CODE(0x89, 0xa8, 0x44, 0x33, 0x22, 0x11),
        PIS_X86_CPUMODE_32_BIT,
        PIS_OPERAND_SIZE_4,
        &EAX,
        NULL,
        0,
        0x11223344,
        &EBP
    ));

    CHECK_RETHROW_VERBOSE(generic_test_mov_modrm_reg(
        CODE(0x89, 0x9d, 0xbc, 0xbc, 0xbd, 0xbe),
        PIS_X86_CPUMODE_32_BIT,
        PIS_OPERAND_SIZE_4,
        &EBP,
        NULL,
        0,
        0xbebdbcbc,
        &EBX
    ));

    CHECK_RETHROW_VERBOSE(generic_test_mov_modrm_reg(
        CODE(0x89, 0x1c, 0x06),
        PIS_X86_CPUMODE_32_BIT,
        PIS_OPERAND_SIZE_4,
        &ESI,
        &EAX,
        1,
        0,
        &EBX
    ));

    CHECK_RETHROW_VERBOSE(generic_test_mov_modrm_reg(
        CODE(0x89, 0x0c, 0x24),
        PIS_X86_CPUMODE_32_BIT,
        PIS_OPERAND_SIZE_4,
        &ESP,
        NULL,
        0,
        0,
        &ECX
    ));

    CHECK_RETHROW_VERBOSE(generic_test_mov_modrm_reg(
        CODE(0x89, 0x2c, 0x95, 0x78, 0x56, 0x34, 0x12),
        PIS_X86_CPUMODE_32_BIT,
        PIS_OPERAND_SIZE_4,
        NULL,
        &EDX,
        4,
        0x12345678,
        &EBP
    ));

    CHECK_RETHROW_VERBOSE(generic_test_mov_modrm_reg(
        CODE(0x89, 0x2c, 0x25, 0x78, 0x56, 0x34, 0x12),
        PIS_X86_CPUMODE_32_BIT,
        PIS_OPERAND_SIZE_4,
        NULL,
        NULL,
        0,
        0x12345678,
        &EBP
    ));

    CHECK_RETHROW_VERBOSE(generic_test_mov_modrm_reg(
        CODE(0x89, 0x7c, 0xed, 0x01),
        PIS_X86_CPUMODE_32_BIT,
        PIS_OPERAND_SIZE_4,
        &EBP,
        &EBP,
        8,
        1,
        &EDI
    ));

    CHECK_RETHROW_VERBOSE(generic_test_mov_modrm_reg(
        CODE(0x89, 0x4c, 0x5d, 0xfc),
        PIS_X86_CPUMODE_32_BIT,
        PIS_OPERAND_SIZE_4,
        &EBP,
        &EBX,
        2,
        0xfffffffc,
        &ECX
    ));

    CHECK_RETHROW_VERBOSE(generic_test_mov_modrm_reg(
        CODE(0x89, 0xb4, 0x05, 0x44, 0x33, 0x22, 0x11),
        PIS_X86_CPUMODE_32_BIT,
        PIS_OPERAND_SIZE_4,
        &EBP,
        &EAX,
        1,
        0x11223344,
        &ESI
    ));

    CHECK_RETHROW_VERBOSE(generic_test_mov_modrm_reg(
        CODE(0x89, 0xa4, 0x55, 0xbc, 0xbc, 0xbd, 0xbe),
        PIS_X86_CPUMODE_32_BIT,
        PIS_OPERAND_SIZE_4,
        &EBP,
        &EDX,
        2,
        0xbebdbcbc,
        &ESP
    ));

    CHECK_RETHROW_VERBOSE(generic_test_mov_modrm_reg(
        CODE(0x89, 0x7c, 0xf1, 0x01),
        PIS_X86_CPUMODE_32_BIT,
        PIS_OPERAND_SIZE_4,
        &ECX,
        &ESI,
        8,
        1,
        &EDI
    ));

    CHECK_RETHROW_VERBOSE(generic_test_mov_modrm_reg(
        CODE(0x89, 0x6c, 0x58, 0xfd),
        PIS_X86_CPUMODE_32_BIT,
        PIS_OPERAND_SIZE_4,
        &EAX,
        &EBX,
        2,
        0xfffffffd,
        &EBP
    ));

    CHECK_RETHROW_VERBOSE(generic_test_mov_modrm_reg(
        CODE(0x89, 0xa4, 0x8c, 0x44, 0x33, 0x22, 0x11),
        PIS_X86_CPUMODE_32_BIT,
        PIS_OPERAND_SIZE_4,
        &ESP,
        &ECX,
        4,
        0x11223344,
        &ESP
    ));

    CHECK_RETHROW_VERBOSE(generic_test_mov_modrm_reg(
        CODE(0x67, 0x89, 0x82, 0x34, 0x12),
        PIS_X86_CPUMODE_32_BIT,
        PIS_OPERAND_SIZE_2,
        &BP,
        &SI,
        1,
        0x1234,
        &EAX
    ));

    CHECK_RETHROW_VERBOSE(generic_test_mov_modrm_reg(
        CODE(0x66, 0x89, 0x44, 0x58, 0xfd),
        PIS_X86_CPUMODE_32_BIT,
        PIS_OPERAND_SIZE_4,
        &EAX,
        &EBX,
        2,
        0xfffffffd,
        &AX
    ));

    CHECK_RETHROW_VERBOSE(generic_test_mov_modrm_reg(
        CODE(0x66, 0x67, 0x89, 0x88, 0x34, 0x12),
        PIS_X86_CPUMODE_32_BIT,
        PIS_OPERAND_SIZE_2,
        &BX,
        &SI,
        1,
        0x1234,
        &CX
    ));

cleanup:
    return err;
}

DEFINE_TEST(test_modrm_16_bit_mode) {
    err_t err = SUCCESS;
    pis_operand_t addr_tmp = PIS_OPERAND_TMP(0, PIS_OPERAND_SIZE_2);
    pis_operand_t addr32_tmp = PIS_OPERAND_TMP(0, PIS_OPERAND_SIZE_4);
    pis_operand_t sib_tmp = PIS_OPERAND_TMP(4, PIS_OPERAND_SIZE_4);

    CHECK_RETHROW_VERBOSE(generic_test_lift(
        CODE(0x89, 0xe5),
        PIS_X86_CPUMODE_16_BIT,
        EXPECTED_INSNS(PIS_INSN2(PIS_OPCODE_MOVE, BP, SP))
    ));

    CHECK_RETHROW_VERBOSE(generic_test_lift(
        CODE(0x89, 0xce),
        PIS_X86_CPUMODE_16_BIT,
        EXPECTED_INSNS(PIS_INSN2(PIS_OPCODE_MOVE, SI, CX))
    ));

    CHECK_RETHROW_VERBOSE(generic_test_lift(
        CODE(0x89, 0x0f),
        PIS_X86_CPUMODE_16_BIT,
        EXPECTED_INSNS(
            PIS_INSN2(PIS_OPCODE_MOVE, addr_tmp, BX),
            PIS_INSN2(PIS_OPCODE_STORE, addr_tmp, CX)
        )
    ));
    CHECK_RETHROW_VERBOSE(generic_test_lift(
        CODE(0x89, 0x12),
        PIS_X86_CPUMODE_16_BIT,
        EXPECTED_INSNS(
            PIS_INSN2(PIS_OPCODE_MOVE, addr_tmp, BP),
            PIS_INSN_ADD2(addr_tmp, SI),
            PIS_INSN2(PIS_OPCODE_STORE, addr_tmp, DX)
        )
    ));

    CHECK_RETHROW_VERBOSE(generic_test_lift(
        CODE(0x89, 0x3e, 0x34, 0x12),
        PIS_X86_CPUMODE_16_BIT,
        EXPECTED_INSNS(
            PIS_INSN2(PIS_OPCODE_MOVE, addr_tmp, PIS_OPERAND_CONST(0x1234, PIS_OPERAND_SIZE_2)),
            PIS_INSN2(PIS_OPCODE_STORE, addr_tmp, DI)
        )
    ));

    CHECK_RETHROW_VERBOSE(generic_test_lift(
        CODE(0x89, 0x44, 0x05),
        PIS_X86_CPUMODE_16_BIT,
        EXPECTED_INSNS(
            PIS_INSN2(PIS_OPCODE_MOVE, addr_tmp, SI),
            PIS_INSN_ADD2(addr_tmp, PIS_OPERAND_CONST(0x5, PIS_OPERAND_SIZE_2)),
            PIS_INSN2(PIS_OPCODE_STORE, addr_tmp, AX)
        )
    ));

    CHECK_RETHROW_VERBOSE(generic_test_lift(
        CODE(0x89, 0x59, 0xff),
        PIS_X86_CPUMODE_16_BIT,
        EXPECTED_INSNS(
            PIS_INSN2(PIS_OPCODE_MOVE, addr_tmp, BX),
            PIS_INSN_ADD2(addr_tmp, DI),
            PIS_INSN_ADD2(addr_tmp, PIS_OPERAND_CONST(0xffff, PIS_OPERAND_SIZE_2)),
            PIS_INSN2(PIS_OPCODE_STORE, addr_tmp, BX)
        )
    ));

    CHECK_RETHROW_VERBOSE(generic_test_lift(
        CODE(0x89, 0x76, 0x7f),
        PIS_X86_CPUMODE_16_BIT,
        EXPECTED_INSNS(
            PIS_INSN2(PIS_OPCODE_MOVE, addr_tmp, BP),
            PIS_INSN_ADD2(addr_tmp, PIS_OPERAND_CONST(0x7f, PIS_OPERAND_SIZE_2)),
            PIS_INSN2(PIS_OPCODE_STORE, addr_tmp, SI)
        )
    ));

    CHECK_RETHROW_VERBOSE(generic_test_lift(
        CODE(0x89, 0x88, 0x34, 0x12),
        PIS_X86_CPUMODE_16_BIT,
        EXPECTED_INSNS(
            PIS_INSN2(PIS_OPCODE_MOVE, addr_tmp, BX),
            PIS_INSN_ADD2(addr_tmp, SI),
            PIS_INSN_ADD2(addr_tmp, PIS_OPERAND_CONST(0x1234, PIS_OPERAND_SIZE_2)),
            PIS_INSN2(PIS_OPCODE_STORE, addr_tmp, CX)
        )
    ));

    CHECK_RETHROW_VERBOSE(generic_test_lift(
        CODE(0x89, 0x96, 0xcc, 0xed),
        PIS_X86_CPUMODE_16_BIT,
        EXPECTED_INSNS(
            PIS_INSN2(PIS_OPCODE_MOVE, addr_tmp, BP),
            PIS_INSN_ADD2(addr_tmp, PIS_OPERAND_CONST_NEG(0x1234, PIS_OPERAND_SIZE_2)),
            PIS_INSN2(PIS_OPCODE_STORE, addr_tmp, DX)
        )
    ));

    CHECK_RETHROW_VERBOSE(generic_test_lift(
        CODE(0x66, 0x89, 0x82, 0x34, 0x12),
        PIS_X86_CPUMODE_16_BIT,
        EXPECTED_INSNS(
            PIS_INSN2(PIS_OPCODE_MOVE, addr_tmp, BP),
            PIS_INSN_ADD2(addr_tmp, SI),
            PIS_INSN_ADD2(addr_tmp, PIS_OPERAND_CONST(0x1234, PIS_OPERAND_SIZE_2)),
            PIS_INSN2(PIS_OPCODE_STORE, addr_tmp, EAX)
        )
    ));

    CHECK_RETHROW_VERBOSE(generic_test_lift(
        CODE(0x67, 0x89, 0x44, 0x58, 0xfd),
        PIS_X86_CPUMODE_16_BIT,
        EXPECTED_INSNS(
            PIS_INSN2(PIS_OPCODE_MOVE, addr32_tmp, EAX),
            PIS_INSN2(PIS_OPCODE_MOVE, sib_tmp, EBX),
            PIS_INSN_UMUL2(sib_tmp, PIS_OPERAND_CONST(2, PIS_OPERAND_SIZE_4)),
            PIS_INSN_ADD2(addr32_tmp, sib_tmp),
            PIS_INSN_ADD2(addr32_tmp, PIS_OPERAND_CONST(0xfffffffd, PIS_OPERAND_SIZE_4)),
            PIS_INSN2(PIS_OPCODE_STORE, addr32_tmp, AX)
        )
    ));

    CHECK_RETHROW_VERBOSE(generic_test_lift(
        CODE(0x66, 0x67, 0x89, 0x64, 0x58, 0xfd),
        PIS_X86_CPUMODE_16_BIT,
        EXPECTED_INSNS(
            PIS_INSN2(PIS_OPCODE_MOVE, addr32_tmp, EAX),
            PIS_INSN2(PIS_OPCODE_MOVE, sib_tmp, EBX),
            PIS_INSN_UMUL2(sib_tmp, PIS_OPERAND_CONST(2, PIS_OPERAND_SIZE_4)),
            PIS_INSN_ADD2(addr32_tmp, sib_tmp),
            PIS_INSN_ADD2(addr32_tmp, PIS_OPERAND_CONST_NEG(3, PIS_OPERAND_SIZE_4)),
            PIS_INSN2(PIS_OPCODE_STORE, addr32_tmp, ESP)
        )
    ));

cleanup:
    return err;
}

DEFINE_TEST(test_rel_operand_16_bit_mode) {
    err_t err = SUCCESS;

    CHECK_RETHROW_VERBOSE(generic_test_lift_at_addr(
        CODE(0xe9, 0x09, 0x00),
        PIS_X86_CPUMODE_16_BIT,
        EXPECTED_INSNS(PIS_INSN1(PIS_OPCODE_JMP, PIS_OPERAND_RAM(7, PIS_OPERAND_SIZE_1))),
        (0xffff + 1) - 3 - 2
    ));

    CHECK_RETHROW_VERBOSE(generic_test_lift_at_addr(
        CODE(0x66, 0xe9, 0x09, 0x00, 0x00, 0x00),
        PIS_X86_CPUMODE_16_BIT,
        EXPECTED_INSNS(PIS_INSN1(PIS_OPCODE_JMP, PIS_OPERAND_RAM(7, PIS_OPERAND_SIZE_1))),
        (0xffffffffULL + 1) - 6 - 2
    ));

    CHECK_RETHROW_VERBOSE(generic_test_lift_at_addr(
        CODE(0xe8, 0x09, 0x00),
        PIS_X86_CPUMODE_16_BIT,
        EXPECTED_INSNS(
            PIS_INSN_ADD2(SP, PIS_OPERAND_CONST_NEG(2, PIS_OPERAND_SIZE_2)),
            PIS_INSN2(
                PIS_OPCODE_STORE,
                SP,
                PIS_OPERAND_CONST((0xffff + 1) - 2, PIS_OPERAND_SIZE_2)
            ),
            PIS_INSN1(PIS_OPCODE_JMP, PIS_OPERAND_RAM(7, PIS_OPERAND_SIZE_1))
        ),
        (0xffff + 1) - 3 - 2
    ));

    CHECK_RETHROW_VERBOSE(generic_test_lift_at_addr(
        CODE(0x66, 0xe8, 0x09, 0x00, 0x00, 0x00),
        PIS_X86_CPUMODE_16_BIT,
        EXPECTED_INSNS(
            PIS_INSN_ADD2(SP, PIS_OPERAND_CONST_NEG(4, PIS_OPERAND_SIZE_2)),
            PIS_INSN2(
                PIS_OPCODE_STORE,
                SP,
                PIS_OPERAND_CONST((0xffffffffULL + 1) - 2, PIS_OPERAND_SIZE_4)
            ),
            PIS_INSN1(PIS_OPCODE_JMP, PIS_OPERAND_RAM(7, PIS_OPERAND_SIZE_1))
        ),
        (0xffffffffULL + 1) - 6 - 2
    ));

cleanup:
    return err;
}

DEFINE_TEST(test_rel_operand_32_bit_mode) {
    err_t err = SUCCESS;

    CHECK_RETHROW_VERBOSE(generic_test_lift_at_addr(
        CODE(0xe9, 0x09, 0x00, 0x00, 0x00),
        PIS_X86_CPUMODE_32_BIT,
        EXPECTED_INSNS(PIS_INSN1(PIS_OPCODE_JMP, PIS_OPERAND_RAM(7, PIS_OPERAND_SIZE_1))),
        (0xffffffffULL + 1) - 5 - 2
    ));

    CHECK_RETHROW_VERBOSE(generic_test_lift_at_addr(
        CODE(0x66, 0xe9, 0x09, 0x00),
        PIS_X86_CPUMODE_32_BIT,
        EXPECTED_INSNS(PIS_INSN1(PIS_OPCODE_JMP, PIS_OPERAND_RAM(7, PIS_OPERAND_SIZE_1))),
        (0xffff + 1) - 4 - 2
    ));

    CHECK_RETHROW_VERBOSE(generic_test_lift_at_addr(
        CODE(0xe8, 0x09, 0x00, 0x00, 0x00),
        PIS_X86_CPUMODE_32_BIT,
        EXPECTED_INSNS(
            PIS_INSN_ADD2(ESP, PIS_OPERAND_CONST_NEG(4, PIS_OPERAND_SIZE_4)),
            PIS_INSN2(
                PIS_OPCODE_STORE,
                ESP,
                PIS_OPERAND_CONST((0xffffffffULL + 1) - 2, PIS_OPERAND_SIZE_4)
            ),
            PIS_INSN1(PIS_OPCODE_JMP, PIS_OPERAND_RAM(7, PIS_OPERAND_SIZE_1))
        ),
        (0xffffffffULL + 1) - 5 - 2
    ));

    CHECK_RETHROW_VERBOSE(generic_test_lift_at_addr(
        CODE(0x66, 0xe8, 0x09, 0x00),
        PIS_X86_CPUMODE_32_BIT,
        EXPECTED_INSNS(
            PIS_INSN_ADD2(ESP, PIS_OPERAND_CONST_NEG(2, PIS_OPERAND_SIZE_4)),
            PIS_INSN2(
                PIS_OPCODE_STORE,
                ESP,
                PIS_OPERAND_CONST((0xffff + 1) - 2, PIS_OPERAND_SIZE_2)
            ),
            PIS_INSN1(PIS_OPCODE_JMP, PIS_OPERAND_RAM(7, PIS_OPERAND_SIZE_1))
        ),
        (0xffff + 1) - 4 - 2
    ));

cleanup:
    return err;
}

DEFINE_TEST(test_rel_operand_64_bit_mode) {
    err_t err = SUCCESS;

    CHECK_RETHROW_VERBOSE(generic_test_lift_at_addr(
        CODE(0xe9, 0x09, 0x00, 0x00, 0x00),
        PIS_X86_CPUMODE_64_BIT,
        EXPECTED_INSNS(PIS_INSN1(PIS_OPCODE_JMP, PIS_OPERAND_RAM(7, PIS_OPERAND_SIZE_1))),
        0ULL - 5 - 2
    ));

    CHECK_RETHROW_VERBOSE(generic_test_lift_at_addr(
        CODE(0x66, 0xe9, 0x09, 0x00, 0x00, 0x00),
        PIS_X86_CPUMODE_64_BIT,
        EXPECTED_INSNS(PIS_INSN1(PIS_OPCODE_JMP, PIS_OPERAND_RAM(7, PIS_OPERAND_SIZE_1))),
        0ULL - 6 - 2
    ));

    CHECK_RETHROW_VERBOSE(generic_test_lift_at_addr(
        CODE(0xe8, 0x09, 0x00, 0x00, 0x00),
        PIS_X86_CPUMODE_64_BIT,
        EXPECTED_INSNS(
            PIS_INSN_ADD2(RSP, PIS_OPERAND_CONST_NEG(8, PIS_OPERAND_SIZE_8)),
            PIS_INSN2(PIS_OPCODE_STORE, RSP, PIS_OPERAND_CONST(0ULL - 2, PIS_OPERAND_SIZE_8)),
            PIS_INSN1(PIS_OPCODE_JMP, PIS_OPERAND_RAM(7, PIS_OPERAND_SIZE_1))
        ),
        0ULL - 5 - 2
    ));

    CHECK_RETHROW_VERBOSE(generic_test_lift_at_addr(
        CODE(0x66, 0xe8, 0x09, 0x00, 0x00, 0x00),
        PIS_X86_CPUMODE_64_BIT,
        EXPECTED_INSNS(
            PIS_INSN_ADD2(RSP, PIS_OPERAND_CONST_NEG(8, PIS_OPERAND_SIZE_8)),
            PIS_INSN2(PIS_OPCODE_STORE, RSP, PIS_OPERAND_CONST(0ULL - 2, PIS_OPERAND_SIZE_8)),
            PIS_INSN1(PIS_OPCODE_JMP, PIS_OPERAND_RAM(7, PIS_OPERAND_SIZE_1))
        ),
        0ULL - 6 - 2
    ));

cleanup:
    return err;
}

DEFINE_TEST(test_mov_r8_64_bit_mode) {
    err_t err = SUCCESS;

    CHECK_RETHROW_VERBOSE(generic_test_lift(
        CODE(0xb7, 0xe4),
        PIS_X86_CPUMODE_64_BIT,
        EXPECTED_INSNS(PIS_INSN2(PIS_OPCODE_MOVE, BH, PIS_OPERAND_CONST(0xe4, PIS_OPERAND_SIZE_1)))
    ));

    CHECK_RETHROW_VERBOSE(generic_test_lift(
        CODE(0x48, 0xb7, 0xe4),
        PIS_X86_CPUMODE_64_BIT,
        EXPECTED_INSNS(PIS_INSN2(PIS_OPCODE_MOVE, DIL, PIS_OPERAND_CONST(0xe4, PIS_OPERAND_SIZE_1)))
    ));

    CHECK_RETHROW_VERBOSE(generic_test_lift(
        CODE(0x49, 0xb7, 0xe4),
        PIS_X86_CPUMODE_64_BIT,
        EXPECTED_INSNS(PIS_INSN2(PIS_OPCODE_MOVE, R15B, PIS_OPERAND_CONST(0xe4, PIS_OPERAND_SIZE_1))
        )
    ));

    CHECK_RETHROW_VERBOSE(generic_test_lift(
        CODE(0x41, 0xb0, 0x12),
        PIS_X86_CPUMODE_64_BIT,
        EXPECTED_INSNS(PIS_INSN2(PIS_OPCODE_MOVE, R8B, PIS_OPERAND_CONST(0x12, PIS_OPERAND_SIZE_1)))
    ));

    CHECK_RETHROW_VERBOSE(generic_test_lift(
        CODE(0x40, 0xb4, 0x55),
        PIS_X86_CPUMODE_64_BIT,
        EXPECTED_INSNS(PIS_INSN2(PIS_OPCODE_MOVE, SPL, PIS_OPERAND_CONST(0x55, PIS_OPERAND_SIZE_1)))
    ));

cleanup:
    return err;
}

DEFINE_TEST(test_mov_r8_32_bit_mode) {
    err_t err = SUCCESS;

    CHECK_RETHROW_VERBOSE(generic_test_lift(
        CODE(0xb7, 0xe4),
        PIS_X86_CPUMODE_32_BIT,
        EXPECTED_INSNS(PIS_INSN2(PIS_OPCODE_MOVE, BH, PIS_OPERAND_CONST(0xe4, PIS_OPERAND_SIZE_1)))
    ));

    CHECK_RETHROW_VERBOSE(generic_test_lift(
        CODE(0xb0, 0x12),
        PIS_X86_CPUMODE_32_BIT,
        EXPECTED_INSNS(PIS_INSN2(PIS_OPCODE_MOVE, AL, PIS_OPERAND_CONST(0x12, PIS_OPERAND_SIZE_1)))
    ));

cleanup:
    return err;
}

DEFINE_TEST(test_mov_r8_16_bit_mode) {
    err_t err = SUCCESS;

    CHECK_RETHROW_VERBOSE(generic_test_lift(
        CODE(0xb7, 0xe4),
        PIS_X86_CPUMODE_16_BIT,
        EXPECTED_INSNS(PIS_INSN2(PIS_OPCODE_MOVE, BH, PIS_OPERAND_CONST(0xe4, PIS_OPERAND_SIZE_1)))
    ));

    CHECK_RETHROW_VERBOSE(generic_test_lift(
        CODE(0xb0, 0x12),
        PIS_X86_CPUMODE_16_BIT,
        EXPECTED_INSNS(PIS_INSN2(PIS_OPCODE_MOVE, AL, PIS_OPERAND_CONST(0x12, PIS_OPERAND_SIZE_1)))
    ));

cleanup:
    return err;
}

DEFINE_TEST(test_nop_modrm) {
    err_t err = SUCCESS;

    pis_operand_t addr_tmp = PIS_OPERAND_TMP(0, PIS_OPERAND_SIZE_8);
    pis_operand_t sib_tmp = PIS_OPERAND_TMP(8, PIS_OPERAND_SIZE_8);

    CHECK_RETHROW_VERBOSE(generic_test_lift(
        CODE(0x66, 0x2e, 0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00),
        PIS_X86_CPUMODE_64_BIT,

        EXPECTED_INSNS(
            PIS_INSN2(PIS_OPCODE_MOVE, addr_tmp, RAX),
            PIS_INSN2(PIS_OPCODE_MOVE, sib_tmp, RAX),
            PIS_INSN_UMUL2(sib_tmp, PIS_OPERAND_CONST(1, PIS_OPERAND_SIZE_8)),
            PIS_INSN_ADD2(addr_tmp, sib_tmp),
            PIS_INSN_ADD2(addr_tmp, PIS_OPERAND_CONST(0, PIS_OPERAND_SIZE_8)),
        )
    ));

cleanup:
    return err;
}

DEFINE_TEST(test_movsxd) {
    err_t err = SUCCESS;

    pis_operand_t addr_tmp = PIS_OPERAND_TMP(0, PIS_OPERAND_SIZE_8);
    pis_operand_t tmp32 = PIS_OPERAND_TMP(8, PIS_OPERAND_SIZE_4);

    CHECK_RETHROW_VERBOSE(generic_test_lift(
        CODE(0x48, 0x63, 0x00),
        PIS_X86_CPUMODE_64_BIT,
        EXPECTED_INSNS(
            PIS_INSN2(PIS_OPCODE_MOVE, addr_tmp, RAX),
            PIS_INSN2(PIS_OPCODE_LOAD, tmp32, addr_tmp),
            PIS_INSN2(PIS_OPCODE_SIGN_EXTEND, RAX, tmp32)
        )
    ));

    CHECK_RETHROW_VERBOSE(generic_test_lift(
        CODE(0x63, 0x00),
        PIS_X86_CPUMODE_64_BIT,
        EXPECTED_INSNS(
            PIS_INSN2(PIS_OPCODE_MOVE, addr_tmp, RAX),
            PIS_INSN2(PIS_OPCODE_LOAD, EAX, addr_tmp)
        )
    ));

    CHECK_RETHROW_VERBOSE(generic_test_lift(
        CODE(0x66, 0x63, 0x00),
        PIS_X86_CPUMODE_64_BIT,
        EXPECTED_INSNS(
            PIS_INSN2(PIS_OPCODE_MOVE, addr_tmp, RAX),
            PIS_INSN2(PIS_OPCODE_LOAD, AX, addr_tmp)
        )
    ));

cleanup:
    return err;
}

DEFINE_TEST(test_movzx_16_bit_mode) {
    err_t err = SUCCESS;

    pis_operand_t addr_tmp = PIS_OPERAND_TMP(0, PIS_OPERAND_SIZE_2);
    pis_operand_t tmp8 = PIS_OPERAND_TMP(2, PIS_OPERAND_SIZE_1);

    CHECK_RETHROW_VERBOSE(generic_test_lift(
        CODE(0x0f, 0xb6, 0x00),
        PIS_X86_CPUMODE_16_BIT,
        EXPECTED_INSNS(
            PIS_INSN2(PIS_OPCODE_MOVE, addr_tmp, BX),
            PIS_INSN_ADD2(addr_tmp, SI),
            PIS_INSN2(PIS_OPCODE_LOAD, tmp8, addr_tmp),
            PIS_INSN2(PIS_OPCODE_ZERO_EXTEND, AX, tmp8)
        )
    ));

    CHECK_RETHROW_VERBOSE(generic_test_lift(
        CODE(0x66, 0x0f, 0xb6, 0x00),
        PIS_X86_CPUMODE_16_BIT,
        EXPECTED_INSNS(
            PIS_INSN2(PIS_OPCODE_MOVE, addr_tmp, BX),
            PIS_INSN_ADD2(addr_tmp, SI),
            PIS_INSN2(PIS_OPCODE_LOAD, tmp8, addr_tmp),
            PIS_INSN2(PIS_OPCODE_ZERO_EXTEND, EAX, tmp8)
        )
    ));

cleanup:
    return err;
}

DEFINE_TEST(test_movzx_32_bit_mode) {
    err_t err = SUCCESS;

    pis_operand_t addr_tmp = PIS_OPERAND_TMP(0, PIS_OPERAND_SIZE_4);
    pis_operand_t tmp8 = PIS_OPERAND_TMP(4, PIS_OPERAND_SIZE_1);

    CHECK_RETHROW_VERBOSE(generic_test_lift(
        CODE(0x0f, 0xb6, 0x00),
        PIS_X86_CPUMODE_32_BIT,
        EXPECTED_INSNS(
            PIS_INSN2(PIS_OPCODE_MOVE, addr_tmp, EAX),
            PIS_INSN2(PIS_OPCODE_LOAD, tmp8, addr_tmp),
            PIS_INSN2(PIS_OPCODE_ZERO_EXTEND, EAX, tmp8)
        )
    ));

    CHECK_RETHROW_VERBOSE(generic_test_lift(
        CODE(0x66, 0x0f, 0xb6, 0x00),
        PIS_X86_CPUMODE_32_BIT,
        EXPECTED_INSNS(
            PIS_INSN2(PIS_OPCODE_MOVE, addr_tmp, EAX),
            PIS_INSN2(PIS_OPCODE_LOAD, tmp8, addr_tmp),
            PIS_INSN2(PIS_OPCODE_ZERO_EXTEND, AX, tmp8)
        )
    ));

cleanup:
    return err;
}

DEFINE_TEST(test_movzx_64_bit_mode) {
    err_t err = SUCCESS;

    pis_operand_t addr_tmp = PIS_OPERAND_TMP(0, PIS_OPERAND_SIZE_8);
    pis_operand_t tmp8 = PIS_OPERAND_TMP(8, PIS_OPERAND_SIZE_1);

    CHECK_RETHROW_VERBOSE(generic_test_lift(
        CODE(0x0f, 0xb6, 0x00),
        PIS_X86_CPUMODE_64_BIT,
        EXPECTED_INSNS(
            PIS_INSN2(PIS_OPCODE_MOVE, addr_tmp, RAX),
            PIS_INSN2(PIS_OPCODE_LOAD, tmp8, addr_tmp),
            PIS_INSN2(PIS_OPCODE_ZERO_EXTEND, EAX, tmp8)
        )
    ));

    CHECK_RETHROW_VERBOSE(generic_test_lift(
        CODE(0x66, 0x0f, 0xb6, 0x00),
        PIS_X86_CPUMODE_64_BIT,
        EXPECTED_INSNS(
            PIS_INSN2(PIS_OPCODE_MOVE, addr_tmp, RAX),
            PIS_INSN2(PIS_OPCODE_LOAD, tmp8, addr_tmp),
            PIS_INSN2(PIS_OPCODE_ZERO_EXTEND, AX, tmp8)
        )
    ));

    CHECK_RETHROW_VERBOSE(generic_test_lift(
        CODE(0x48, 0x0f, 0xb6, 0x00),
        PIS_X86_CPUMODE_64_BIT,
        EXPECTED_INSNS(
            PIS_INSN2(PIS_OPCODE_MOVE, addr_tmp, RAX),
            PIS_INSN2(PIS_OPCODE_LOAD, tmp8, addr_tmp),
            PIS_INSN2(PIS_OPCODE_ZERO_EXTEND, RAX, tmp8)
        )
    ));

cleanup:
    return err;
}

static err_t generic_test_push(
    pis_emu_t* emu,
    code_t code,
    pis_x86_cpumode_t cpumode,
    const pis_operand_t* sp,
    u64 expected_pushed_value,
    pis_operand_size_t expected_pushed_value_size
) {
    err_t err = SUCCESS;

    u64 orig_sp = 0;
    CHECK_RETHROW_VERBOSE(pis_emu_read_operand(emu, sp, &orig_sp));

    CHECK_RETHROW_VERBOSE(emulate_insn(&g_emu, code, cpumode, 0));

    // check the new sp value
    u64 new_sp = 0;
    CHECK_RETHROW_VERBOSE(pis_emu_read_operand(emu, sp, &new_sp));
    CHECK(new_sp == orig_sp - pis_operand_size_to_bytes(expected_pushed_value_size));

    // check the written memory value
    u64 written_mem_value = 0;
    CHECK_RETHROW_VERBOSE(
        pis_emu_read_mem_value(&g_emu, new_sp, expected_pushed_value_size, &written_mem_value)
    );
    CHECK(written_mem_value == expected_pushed_value);

cleanup:
    return err;
}

static err_t generic_test_push_reg(
    pis_emu_t* emu,
    code_t code,
    pis_x86_cpumode_t cpumode,
    const pis_operand_t* sp,
    const pis_operand_t* pushed_reg
) {
    err_t err = SUCCESS;

    u64 sp_addr = MAGIC64_1 & pis_operand_size_max_unsigned_value(sp->size);
    u64 pushed_value = MAGIC64_2 & pis_operand_size_max_unsigned_value(pushed_reg->size);

    pis_emu_init(&g_emu, PIS_ENDIANNESS_LITTLE);
    CHECK_RETHROW_VERBOSE(pis_emu_write_operand(&g_emu, sp, sp_addr));
    CHECK_RETHROW_VERBOSE(pis_emu_write_operand(&g_emu, pushed_reg, pushed_value));
    CHECK_RETHROW_VERBOSE(
        generic_test_push(&g_emu, code, cpumode, sp, pushed_value, pushed_reg->size)
    );

    u64 reg_value_after_push = 0;
    CHECK_RETHROW_VERBOSE(pis_emu_read_operand(emu, pushed_reg, &reg_value_after_push));
    CHECK(reg_value_after_push == pushed_value);

cleanup:
    return err;
}

DEFINE_TEST(test_push_reg_64_bit_mode) {
    err_t err = SUCCESS;

    CHECK_RETHROW_VERBOSE(
        generic_test_push_reg(&g_emu, CODE(0x55), PIS_X86_CPUMODE_64_BIT, &RSP, &RBP)
    );

    CHECK_RETHROW_VERBOSE(
        generic_test_push_reg(&g_emu, CODE(0x41, 0x51), PIS_X86_CPUMODE_64_BIT, &RSP, &R9)
    );

    CHECK_RETHROW_VERBOSE(
        generic_test_push_reg(&g_emu, CODE(0x66, 0x52), PIS_X86_CPUMODE_64_BIT, &RSP, &DX)
    );

    CHECK_RETHROW_VERBOSE(
        generic_test_push_reg(&g_emu, CODE(0x66, 0x41, 0x53), PIS_X86_CPUMODE_64_BIT, &RSP, &R11W)
    );

    CHECK_RETHROW_VERBOSE(
        generic_test_push_reg(&g_emu, CODE(0x66, 0x48, 0x55), PIS_X86_CPUMODE_64_BIT, &RSP, &RBP)
    );

    CHECK_RETHROW_VERBOSE(
        generic_test_push_reg(&g_emu, CODE(0x66, 0x49, 0x50), PIS_X86_CPUMODE_64_BIT, &RSP, &R8)
    );

    // push rsp
    pis_emu_init(&g_emu, PIS_ENDIANNESS_LITTLE);
    CHECK_RETHROW_VERBOSE(pis_emu_write_operand(&g_emu, &RSP, MAGIC64_1));
    CHECK_RETHROW_VERBOSE(generic_test_push(
        &g_emu,
        CODE(0x54),
        PIS_X86_CPUMODE_64_BIT,
        &RSP,
        MAGIC64_1,
        PIS_OPERAND_SIZE_8
    ));

cleanup:
    return err;
}

DEFINE_TEST(test_push_reg_32_bit_mode) {
    err_t err = SUCCESS;

    CHECK_RETHROW_VERBOSE(
        generic_test_push_reg(&g_emu, CODE(0x50), PIS_X86_CPUMODE_32_BIT, &ESP, &EAX)
    );

    CHECK_RETHROW_VERBOSE(
        generic_test_push_reg(&g_emu, CODE(0x66, 0x50), PIS_X86_CPUMODE_32_BIT, &ESP, &BP)
    );

cleanup:
    return err;
}

DEFINE_TEST(test_push_reg_16_bit_mode) {
    err_t err = SUCCESS;


    CHECK_RETHROW_VERBOSE(
        generic_test_push_reg(&g_emu, CODE(0x50), PIS_X86_CPUMODE_16_BIT, &ESP, &AX)
    );

    CHECK_RETHROW_VERBOSE(
        generic_test_push_reg(&g_emu, CODE(0x66, 0x50), PIS_X86_CPUMODE_16_BIT, &ESP, &EAX)
    );

cleanup:
    return err;
}
