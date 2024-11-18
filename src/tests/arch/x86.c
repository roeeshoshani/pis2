#include "../../lib/arch/x86/lift.h"
#include "../../lib/arch/x86/regs.h"
#include "../../lib/emu.h"
#include "../../lib/errors.h"
#include "../../lib/except.h"
#include "../../lib/pis.h"
#include "../../lib/utils.h"
#include "../test_utils.h"
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>

static err_t emulate_insn(pis_emu_t* emu, code_t code, pis_x86_cpumode_t cpumode, u64 addr) {
    err_t err = SUCCESS;

    pis_lift_args_t args = {
        .machine_code = CURSOR_INIT(code.code, code.len),
        .machine_code_addr = addr,
    };
    CHECK_RETHROW_VERBOSE(pis_x86_lift(&args, cpumode));

    CHECK_TRACE(
        args.result.machine_insn_len == code.len,
        "expected the instruction to be %lu bytes, instead it was %lu bytes",
        code.len,
        args.result.machine_insn_len
    );

    CHECK_RETHROW_VERBOSE(pis_emu_run(emu, &args.result));

cleanup:
    return err;
}

static err_t emu_assert_operand_equals(
    const pis_emu_t* emu, const pis_operand_t* operand, u64 desired_value
) {
    err_t err = SUCCESS;
    u64 actual_value = 0;
    CHECK_RETHROW_VERBOSE(pis_emu_read_operand(emu, operand, &actual_value));

    CHECK_TRACE(
        actual_value == desired_value,
        "expected value %lx, instead got %lx",
        desired_value,
        actual_value
    );

cleanup:
    return err;
}

static err_t emu_assert_mem_value_equals(
    const pis_emu_t* emu, u64 addr, pis_size_t value_size, u64 desired_value
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
    pis_size_t operand_size = dst_reg->size;

    u64 src_reg_val = MAGIC64_1 & pis_size_max_unsigned_value(operand_size);

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
    pis_size_t addr_size,
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

    u64 addr_max = pis_size_max_unsigned_value(addr_size);
    CHECK(addr_imm <= addr_max);

    u64 src_reg_val = MAGIC64_1 & pis_size_max_unsigned_value(src_reg->size);
    u64 base_reg_val = 0;
    if (addr_base_reg != NULL) {
        base_reg_val = MAGIC64_2 & pis_size_max_unsigned_value(addr_base_reg->size);
    }
    u64 index_reg_val = 0;
    if (addr_index_reg != NULL) {
        index_reg_val = MAGIC64_2 & pis_size_max_unsigned_value(addr_index_reg->size);
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
    pis_size_t addr_size,
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
        generic_test_mov_reg_reg(CODE(0x89, 0xe5), PIS_X86_CPUMODE_64_BIT, &X86_EBP, &X86_ESP)
    );

    CHECK_RETHROW_VERBOSE(
        generic_test_mov_reg_reg(CODE(0x48, 0x89, 0xe5), PIS_X86_CPUMODE_64_BIT, &X86_RBP, &X86_RSP)
    );

    CHECK_RETHROW_VERBOSE(
        generic_test_mov_reg_reg(CODE(0x4d, 0x89, 0xc8), PIS_X86_CPUMODE_64_BIT, &X86_R8, &X86_R9)
    );

    CHECK_RETHROW_VERBOSE(generic_test_mov_reg_reg(
        CODE(0x45, 0x89, 0xf4),
        PIS_X86_CPUMODE_64_BIT,
        &X86_R12D,
        &X86_R14D
    ));

    CHECK_RETHROW_VERBOSE(generic_test_mov_reg_reg(
        CODE(0x66, 0x41, 0x89, 0xe5),
        PIS_X86_CPUMODE_64_BIT,
        &X86_R13W,
        &X86_SP
    ));

    CHECK_RETHROW_VERBOSE(generic_test_mov_reg_reg(
        CODE(0x44, 0x89, 0xfe),
        PIS_X86_CPUMODE_64_BIT,
        &X86_ESI,
        &X86_R15D
    ));

    CHECK_RETHROW_VERBOSE(generic_test_mov_modrm_reg(
        CODE(0x4c, 0x89, 0x26),
        PIS_X86_CPUMODE_64_BIT,
        PIS_SIZE_8,
        &X86_RSI,
        NULL,
        0,
        0,
        &X86_R12
    ));

    CHECK_RETHROW_VERBOSE(generic_test_mov_modrm_reg(
        CODE(0x49, 0x89, 0x6d, 0x07),
        PIS_X86_CPUMODE_64_BIT,
        PIS_SIZE_8,
        &X86_R13,
        NULL,
        0,
        0x7,
        &X86_RBP
    ));

    CHECK_RETHROW_VERBOSE(generic_test_mov_modrm_reg(
        CODE(0x48, 0x89, 0x48, 0x02),
        PIS_X86_CPUMODE_64_BIT,
        PIS_SIZE_8,
        &X86_RAX,
        NULL,
        0,
        0x2,
        &X86_RCX
    ));

    CHECK_RETHROW_VERBOSE(generic_test_mov_modrm_reg(
        CODE(0x4d, 0x89, 0x48, 0xfa),
        PIS_X86_CPUMODE_64_BIT,
        PIS_SIZE_8,
        &X86_R8,
        NULL,
        0,
        0xfffffffffffffffa,
        &X86_R9
    ));

    CHECK_RETHROW_VERBOSE(generic_test_mov_modrm_reg(
        CODE(0x49, 0x89, 0x9a, 0x44, 0x33, 0x22, 0x11),
        PIS_X86_CPUMODE_64_BIT,
        PIS_SIZE_8,
        &X86_R10,
        NULL,
        0,
        0x11223344,
        &X86_RBX
    ));

    CHECK_RETHROW_VERBOSE(generic_test_mov_modrm_reg(
        CODE(0x4c, 0x89, 0x9a, 0xbc, 0xbc, 0xbd, 0xbe),
        PIS_X86_CPUMODE_64_BIT,
        PIS_SIZE_8,
        &X86_RDX,
        NULL,
        0,
        0xffffffffbebdbcbc,
        &X86_R11
    ));

    CHECK_RETHROW_VERBOSE(generic_test_mov_modrm_reg(
        CODE(0x4a, 0x89, 0x1c, 0xa0),
        PIS_X86_CPUMODE_64_BIT,
        PIS_SIZE_8,
        &X86_RAX,
        &X86_R12,
        4,
        0,
        &X86_RBX
    ));

    CHECK_RETHROW_VERBOSE(generic_test_mov_modrm_reg(
        CODE(0x48, 0x89, 0x14, 0x24),
        PIS_X86_CPUMODE_64_BIT,
        PIS_SIZE_8,
        &X86_RSP,
        NULL,
        0,
        0,
        &X86_RDX
    ));

    CHECK_RETHROW_VERBOSE(generic_test_mov_modrm_reg(
        CODE(0x4c, 0x89, 0x04, 0xbd, 0x00, 0x00, 0x00, 0x00),
        PIS_X86_CPUMODE_64_BIT,
        PIS_SIZE_8,
        NULL,
        &X86_RDI,
        4,
        0,
        &X86_R8
    ));

    CHECK_RETHROW_VERBOSE(generic_test_mov_modrm_reg(
        CODE(0x4a, 0x89, 0x64, 0x4d, 0x00),
        PIS_X86_CPUMODE_64_BIT,
        PIS_SIZE_8,
        &X86_RBP,
        &X86_R9,
        2,
        0,
        &X86_RSP
    ));

    CHECK_RETHROW_VERBOSE(generic_test_mov_modrm_reg(
        CODE(0x4d, 0x89, 0x74, 0x4d, 0x00),
        PIS_X86_CPUMODE_64_BIT,
        PIS_SIZE_8,
        &X86_R13,
        &X86_RCX,
        2,
        0,
        &X86_R14
    ));

    CHECK_RETHROW_VERBOSE(generic_test_mov_modrm_reg(
        CODE(0x4f, 0x89, 0x64, 0xfa, 0xfd),
        PIS_X86_CPUMODE_64_BIT,
        PIS_SIZE_8,
        &X86_R10,
        &X86_R15,
        8,
        0xfffffffffffffffd,
        &X86_R12
    ));

    CHECK_RETHROW_VERBOSE(generic_test_mov_modrm_reg(
        CODE(0x4e, 0x89, 0xa4, 0x06, 0xcc, 0xed, 0xcb, 0xed),
        PIS_X86_CPUMODE_64_BIT,
        PIS_SIZE_8,
        &X86_RSI,
        &X86_R8,
        1,
        0xffffffffedcbedcc,
        &X86_R12
    ));

    CHECK_RETHROW_VERBOSE(generic_test_mov_modrm_reg(
        CODE(0x67, 0x89, 0xa4, 0x55, 0xbc, 0xbc, 0xbd, 0xbe),
        PIS_X86_CPUMODE_64_BIT,
        PIS_SIZE_4,
        &X86_EBP,
        &X86_EDX,
        2,
        0xbebdbcbc,
        &X86_ESP
    ));

    CHECK_RETHROW_VERBOSE(generic_test_mov_modrm_reg(
        CODE(0x67, 0x4f, 0x89, 0x44, 0xf9, 0x05),
        PIS_X86_CPUMODE_64_BIT,
        PIS_SIZE_4,
        &X86_R9D,
        &X86_R15D,
        8,
        5,
        &X86_R8
    ));

    CHECK_RETHROW_VERBOSE(generic_test_mov_modrm_reg(
        CODE(0x66, 0x42, 0x89, 0x44, 0xac, 0xff),
        PIS_X86_CPUMODE_64_BIT,
        PIS_SIZE_8,
        &X86_RSP,
        &X86_R13,
        4,
        0xffffffffffffffff,
        &X86_AX
    ));

    CHECK_RETHROW_VERBOSE(generic_test_mov_modrm_reg(
        CODE(0x66, 0x67, 0x42, 0x89, 0x74, 0x65, 0x00),
        PIS_X86_CPUMODE_64_BIT,
        PIS_SIZE_4,
        &X86_EBP,
        &X86_R12D,
        2,
        0,
        &X86_SI
    ));

    CHECK_RETHROW_VERBOSE(generic_test_mov_modrm_reg_at_addr(
        CODE(0x89, 0x05, 0x01, 0x00, 0x00, 0x00),
        0,
        PIS_X86_CPUMODE_64_BIT,
        PIS_SIZE_8,
        NULL,
        NULL,
        0,
        7,
        &X86_EAX
    ));

    CHECK_RETHROW_VERBOSE(generic_test_mov_modrm_reg_at_addr(
        CODE(0x89, 0x05, 0x01, 0x00, 0x00, 0x00),
        1,
        PIS_X86_CPUMODE_64_BIT,
        PIS_SIZE_8,
        NULL,
        NULL,
        0,
        8,
        &X86_EAX
    ));

    CHECK_RETHROW_VERBOSE(generic_test_mov_modrm_reg_at_addr(
        CODE(0x89, 0x05, 0xf6, 0xff, 0xff, 0xff),
        6,
        PIS_X86_CPUMODE_64_BIT,
        PIS_SIZE_8,
        NULL,
        NULL,
        0,
        2,
        &X86_EAX
    ));

cleanup:
    return err;
}

DEFINE_TEST(test_modrm_32_bit_mode) {
    err_t err = SUCCESS;

    CHECK_RETHROW_VERBOSE(
        generic_test_mov_reg_reg(CODE(0x89, 0xe5), PIS_X86_CPUMODE_32_BIT, &X86_EBP, &X86_ESP)
    );

    CHECK_RETHROW_VERBOSE(
        generic_test_mov_reg_reg(CODE(0x89, 0xce), PIS_X86_CPUMODE_32_BIT, &X86_ESI, &X86_ECX)
    );

    CHECK_RETHROW_VERBOSE(generic_test_mov_modrm_reg(
        CODE(0x89, 0x35, 0x78, 0x56, 0x34, 0x12),
        PIS_X86_CPUMODE_32_BIT,
        PIS_SIZE_4,
        NULL,
        NULL,
        0,
        0x12345678,
        &X86_ESI
    ));

    CHECK_RETHROW_VERBOSE(generic_test_mov_modrm_reg(
        CODE(0x89, 0x43, 0x03),
        PIS_X86_CPUMODE_32_BIT,
        PIS_SIZE_4,
        &X86_EBX,
        NULL,
        0,
        3,
        &X86_EAX
    ));

    CHECK_RETHROW_VERBOSE(generic_test_mov_modrm_reg(
        CODE(0x89, 0x67, 0xfe),
        PIS_X86_CPUMODE_32_BIT,
        PIS_SIZE_4,
        &X86_EDI,
        NULL,
        0,
        0xfffffffe,
        &X86_ESP
    ));

    CHECK_RETHROW_VERBOSE(generic_test_mov_modrm_reg(
        CODE(0x89, 0x55, 0x7f),
        PIS_X86_CPUMODE_32_BIT,
        PIS_SIZE_4,
        &X86_EBP,
        NULL,
        0,
        0x7f,
        &X86_EDX
    ));

    CHECK_RETHROW_VERBOSE(generic_test_mov_modrm_reg(
        CODE(0x89, 0xa8, 0x44, 0x33, 0x22, 0x11),
        PIS_X86_CPUMODE_32_BIT,
        PIS_SIZE_4,
        &X86_EAX,
        NULL,
        0,
        0x11223344,
        &X86_EBP
    ));

    CHECK_RETHROW_VERBOSE(generic_test_mov_modrm_reg(
        CODE(0x89, 0x9d, 0xbc, 0xbc, 0xbd, 0xbe),
        PIS_X86_CPUMODE_32_BIT,
        PIS_SIZE_4,
        &X86_EBP,
        NULL,
        0,
        0xbebdbcbc,
        &X86_EBX
    ));

    CHECK_RETHROW_VERBOSE(generic_test_mov_modrm_reg(
        CODE(0x89, 0x1c, 0x06),
        PIS_X86_CPUMODE_32_BIT,
        PIS_SIZE_4,
        &X86_ESI,
        &X86_EAX,
        1,
        0,
        &X86_EBX
    ));

    CHECK_RETHROW_VERBOSE(generic_test_mov_modrm_reg(
        CODE(0x89, 0x0c, 0x24),
        PIS_X86_CPUMODE_32_BIT,
        PIS_SIZE_4,
        &X86_ESP,
        NULL,
        0,
        0,
        &X86_ECX
    ));

    CHECK_RETHROW_VERBOSE(generic_test_mov_modrm_reg(
        CODE(0x89, 0x2c, 0x95, 0x78, 0x56, 0x34, 0x12),
        PIS_X86_CPUMODE_32_BIT,
        PIS_SIZE_4,
        NULL,
        &X86_EDX,
        4,
        0x12345678,
        &X86_EBP
    ));

    CHECK_RETHROW_VERBOSE(generic_test_mov_modrm_reg(
        CODE(0x89, 0x2c, 0x25, 0x78, 0x56, 0x34, 0x12),
        PIS_X86_CPUMODE_32_BIT,
        PIS_SIZE_4,
        NULL,
        NULL,
        0,
        0x12345678,
        &X86_EBP
    ));

    CHECK_RETHROW_VERBOSE(generic_test_mov_modrm_reg(
        CODE(0x89, 0x7c, 0xed, 0x01),
        PIS_X86_CPUMODE_32_BIT,
        PIS_SIZE_4,
        &X86_EBP,
        &X86_EBP,
        8,
        1,
        &X86_EDI
    ));

    CHECK_RETHROW_VERBOSE(generic_test_mov_modrm_reg(
        CODE(0x89, 0x4c, 0x5d, 0xfc),
        PIS_X86_CPUMODE_32_BIT,
        PIS_SIZE_4,
        &X86_EBP,
        &X86_EBX,
        2,
        0xfffffffc,
        &X86_ECX
    ));

    CHECK_RETHROW_VERBOSE(generic_test_mov_modrm_reg(
        CODE(0x89, 0xb4, 0x05, 0x44, 0x33, 0x22, 0x11),
        PIS_X86_CPUMODE_32_BIT,
        PIS_SIZE_4,
        &X86_EBP,
        &X86_EAX,
        1,
        0x11223344,
        &X86_ESI
    ));

    CHECK_RETHROW_VERBOSE(generic_test_mov_modrm_reg(
        CODE(0x89, 0xa4, 0x55, 0xbc, 0xbc, 0xbd, 0xbe),
        PIS_X86_CPUMODE_32_BIT,
        PIS_SIZE_4,
        &X86_EBP,
        &X86_EDX,
        2,
        0xbebdbcbc,
        &X86_ESP
    ));

    CHECK_RETHROW_VERBOSE(generic_test_mov_modrm_reg(
        CODE(0x89, 0x7c, 0xf1, 0x01),
        PIS_X86_CPUMODE_32_BIT,
        PIS_SIZE_4,
        &X86_ECX,
        &X86_ESI,
        8,
        1,
        &X86_EDI
    ));

    CHECK_RETHROW_VERBOSE(generic_test_mov_modrm_reg(
        CODE(0x89, 0x6c, 0x58, 0xfd),
        PIS_X86_CPUMODE_32_BIT,
        PIS_SIZE_4,
        &X86_EAX,
        &X86_EBX,
        2,
        0xfffffffd,
        &X86_EBP
    ));

    CHECK_RETHROW_VERBOSE(generic_test_mov_modrm_reg(
        CODE(0x89, 0xa4, 0x8c, 0x44, 0x33, 0x22, 0x11),
        PIS_X86_CPUMODE_32_BIT,
        PIS_SIZE_4,
        &X86_ESP,
        &X86_ECX,
        4,
        0x11223344,
        &X86_ESP
    ));

    CHECK_RETHROW_VERBOSE(generic_test_mov_modrm_reg(
        CODE(0x67, 0x89, 0x82, 0x34, 0x12),
        PIS_X86_CPUMODE_32_BIT,
        PIS_SIZE_2,
        &X86_BP,
        &X86_SI,
        1,
        0x1234,
        &X86_EAX
    ));

    CHECK_RETHROW_VERBOSE(generic_test_mov_modrm_reg(
        CODE(0x66, 0x89, 0x44, 0x58, 0xfd),
        PIS_X86_CPUMODE_32_BIT,
        PIS_SIZE_4,
        &X86_EAX,
        &X86_EBX,
        2,
        0xfffffffd,
        &X86_AX
    ));

    CHECK_RETHROW_VERBOSE(generic_test_mov_modrm_reg(
        CODE(0x66, 0x67, 0x89, 0x88, 0x34, 0x12),
        PIS_X86_CPUMODE_32_BIT,
        PIS_SIZE_2,
        &X86_BX,
        &X86_SI,
        1,
        0x1234,
        &X86_CX
    ));

cleanup:
    return err;
}

static err_t generic_test_jmp(
    code_t code, pis_x86_cpumode_t cpumode, u64 addr, u64 expected_jump_target_addr
) {
    err_t err = SUCCESS;

    pis_emu_init(&g_emu, PIS_ENDIANNESS_LITTLE);
    CHECK_RETHROW_VERBOSE(emulate_insn(&g_emu, code, cpumode, addr));
    CHECK(g_emu.did_jump);
    CHECK(g_emu.jump_addr == expected_jump_target_addr);
cleanup:
    return err;
}

static err_t generic_test_call(
    code_t code,
    pis_x86_cpumode_t cpumode,
    const pis_operand_t* sp,
    pis_size_t pushed_value_size,
    u64 addr,
    u64 expected_jump_target_addr
) {
    err_t err = SUCCESS;

    pis_emu_init(&g_emu, PIS_ENDIANNESS_LITTLE);

    u64 sp_value = MAGIC64_1 & pis_size_max_unsigned_value(sp->size);

    CHECK_RETHROW_VERBOSE(pis_emu_write_operand(&g_emu, sp, sp_value));

    CHECK_RETHROW_VERBOSE(emulate_insn(&g_emu, code, cpumode, addr));

    u64 new_sp = sp_value - pis_size_to_bytes(pushed_value_size);
    CHECK_RETHROW_VERBOSE(emu_assert_operand_equals(&g_emu, sp, new_sp));

    u64 pushed_value = (addr + code.len) & pis_size_max_unsigned_value(pushed_value_size);
    CHECK_RETHROW_VERBOSE(
        emu_assert_mem_value_equals(&g_emu, new_sp, pushed_value_size, pushed_value)
    );

    CHECK(g_emu.did_jump);
    CHECK(g_emu.jump_addr == expected_jump_target_addr);
cleanup:
    return err;
}

DEFINE_TEST(test_rel_operand_32_bit_mode) {
    err_t err = SUCCESS;

    CHECK_RETHROW_VERBOSE(generic_test_jmp(
        CODE(0xe9, 0x09, 0x00, 0x00, 0x00),
        PIS_X86_CPUMODE_32_BIT,
        (0xffffffffULL + 1) - 5 - 2,
        7
    ));

    CHECK_RETHROW_VERBOSE(generic_test_call(
        CODE(0xe8, 0x09, 0x00, 0x00, 0x00),
        PIS_X86_CPUMODE_32_BIT,
        &X86_ESP,
        PIS_SIZE_4,
        (0xffffffffULL + 1) - 5 - 2,
        7
    ));

cleanup:
    return err;
}

DEFINE_TEST(test_rel_operand_64_bit_mode) {
    err_t err = SUCCESS;

    CHECK_RETHROW_VERBOSE(generic_test_jmp(
        CODE(0xe9, 0x09, 0x00, 0x00, 0x00),
        PIS_X86_CPUMODE_64_BIT,
        0ULL - 5 - 2,
        7
    ));

    CHECK_RETHROW_VERBOSE(generic_test_call(
        CODE(0xe8, 0x09, 0x00, 0x00, 0x00),
        PIS_X86_CPUMODE_64_BIT,
        &X86_RSP,
        PIS_SIZE_8,
        0ULL - 5 - 2,
        7
    ));

cleanup:
    return err;
}

static err_t generic_test_mov_r8_imm8(
    code_t code, pis_x86_cpumode_t cpumode, const pis_operand_t* reg, u8 value
) {
    err_t err = SUCCESS;

    pis_emu_init(&g_emu, PIS_ENDIANNESS_LITTLE);
    CHECK_RETHROW_VERBOSE(emulate_insn(&g_emu, code, cpumode, 0));

    CHECK_RETHROW_VERBOSE(emu_assert_operand_equals(&g_emu, reg, value));

cleanup:
    return err;
}

DEFINE_TEST(test_mov_r8_imm8_64_bit_mode) {
    err_t err = SUCCESS;

    CHECK_RETHROW_VERBOSE(
        generic_test_mov_r8_imm8(CODE(0xb7, 0xe4), PIS_X86_CPUMODE_64_BIT, &X86_BH, 0xe4)
    );

    CHECK_RETHROW_VERBOSE(
        generic_test_mov_r8_imm8(CODE(0x48, 0xb7, 0xe4), PIS_X86_CPUMODE_64_BIT, &X86_DIL, 0xe4)
    );

    CHECK_RETHROW_VERBOSE(
        generic_test_mov_r8_imm8(CODE(0x49, 0xb7, 0xe4), PIS_X86_CPUMODE_64_BIT, &X86_R15B, 0xe4)
    );

    CHECK_RETHROW_VERBOSE(
        generic_test_mov_r8_imm8(CODE(0x41, 0xb0, 0x12), PIS_X86_CPUMODE_64_BIT, &X86_R8B, 0x12)
    );

    CHECK_RETHROW_VERBOSE(
        generic_test_mov_r8_imm8(CODE(0x40, 0xb4, 0x55), PIS_X86_CPUMODE_64_BIT, &X86_SPL, 0x55)
    );

cleanup:
    return err;
}

DEFINE_TEST(test_mov_r8_32_bit_mode) {
    err_t err = SUCCESS;

    CHECK_RETHROW_VERBOSE(
        generic_test_mov_r8_imm8(CODE(0xb7, 0xe4), PIS_X86_CPUMODE_32_BIT, &X86_BH, 0xe4)
    );

    CHECK_RETHROW_VERBOSE(
        generic_test_mov_r8_imm8(CODE(0xb0, 0x12), PIS_X86_CPUMODE_32_BIT, &X86_AL, 0x12)
    );

cleanup:
    return err;
}

DEFINE_TEST(test_nop_modrm) {
    err_t err = SUCCESS;

    pis_emu_init(&g_emu, PIS_ENDIANNESS_LITTLE);
    CHECK_RETHROW_VERBOSE(pis_emu_write_operand(&g_emu, &X86_RAX, 0));
    CHECK_RETHROW_VERBOSE(pis_emu_write_operand(&g_emu, &X86_CS_BASE, 0));
    CHECK_RETHROW_VERBOSE(emulate_insn(
        &g_emu,
        CODE(0x66, 0x2e, 0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00),
        PIS_X86_CPUMODE_64_BIT,
        0
    ));

    // make sure that no memowry was written
    CHECK(g_emu.mem_storage.used_slots_amount == 0);


cleanup:
    return err;
}

static err_t generic_test_mov_sign_extend_reg_modrm(
    code_t code,
    pis_x86_cpumode_t cpumode,
    const pis_operand_t* dst_reg,
    const pis_operand_t* addr_reg,
    u64 mem_value,
    pis_size_t mem_value_size
) {
    err_t err = SUCCESS;

    CHECK(dst_reg->size >= mem_value_size);

    pis_emu_init(&g_emu, PIS_ENDIANNESS_LITTLE);

    u64 addr = MAGIC64_1 & pis_size_max_unsigned_value(addr_reg->size);
    CHECK_RETHROW_VERBOSE(pis_emu_write_operand(&g_emu, addr_reg, addr));

    CHECK_RETHROW_VERBOSE(pis_emu_write_mem_value(&g_emu, addr, mem_value, mem_value_size));

    CHECK_RETHROW_VERBOSE(emulate_insn(&g_emu, code, cpumode, 0));

    u32 mem_value_size_in_bits = pis_size_to_bits(mem_value_size);
    u64 sign_bit = mem_value >> (mem_value_size_in_bits - 1);

    u64 sign_extended_mem_value = mem_value;
    if (sign_bit) {
        // value is signed, sign extend it
        u64 sign_extension_bits =
            ((pis_size_max_unsigned_value(dst_reg->size) >> mem_value_size_in_bits)
             << mem_value_size_in_bits);
        sign_extended_mem_value |= sign_extension_bits;
    }

    CHECK_RETHROW_VERBOSE(emu_assert_operand_equals(&g_emu, dst_reg, sign_extended_mem_value));

cleanup:
    return err;
}

DEFINE_TEST(test_movsxd) {
    err_t err = SUCCESS;

    CHECK_RETHROW_VERBOSE(generic_test_mov_sign_extend_reg_modrm(
        CODE(0x48, 0x63, 0x00),
        PIS_X86_CPUMODE_64_BIT,
        &X86_RAX,
        &X86_RAX,
        0x12345678,
        PIS_SIZE_4
    ));
    CHECK_RETHROW_VERBOSE(generic_test_mov_sign_extend_reg_modrm(
        CODE(0x48, 0x63, 0x00),
        PIS_X86_CPUMODE_64_BIT,
        &X86_RAX,
        &X86_RAX,
        0x87654321,
        PIS_SIZE_4
    ));

    CHECK_RETHROW_VERBOSE(generic_test_mov_sign_extend_reg_modrm(
        CODE(0x63, 0x00),
        PIS_X86_CPUMODE_64_BIT,
        &X86_EAX,
        &X86_RAX,
        0x12345678,
        PIS_SIZE_4
    ));
    CHECK_RETHROW_VERBOSE(generic_test_mov_sign_extend_reg_modrm(
        CODE(0x63, 0x00),
        PIS_X86_CPUMODE_64_BIT,
        &X86_EAX,
        &X86_RAX,
        0x87654321,
        PIS_SIZE_4
    ));

    CHECK_RETHROW_VERBOSE(generic_test_mov_sign_extend_reg_modrm(
        CODE(0x66, 0x63, 0x00),
        PIS_X86_CPUMODE_64_BIT,
        &X86_AX,
        &X86_RAX,
        0x1234,
        PIS_SIZE_2
    ));
    CHECK_RETHROW_VERBOSE(generic_test_mov_sign_extend_reg_modrm(
        CODE(0x66, 0x63, 0x00),
        PIS_X86_CPUMODE_64_BIT,
        &X86_AX,
        &X86_RAX,
        0x8765,
        PIS_SIZE_2
    ));

cleanup:
    return err;
}

static err_t generic_test_mov_zero_extend_reg_modrm(
    code_t code,
    pis_x86_cpumode_t cpumode,
    const pis_operand_t* dst_reg,
    const pis_operand_t* addr_reg,
    pis_size_t mem_value_size
) {
    err_t err = SUCCESS;

    CHECK(dst_reg->size >= mem_value_size);

    pis_emu_init(&g_emu, PIS_ENDIANNESS_LITTLE);

    u64 addr = MAGIC64_1 & pis_size_max_unsigned_value(addr_reg->size);
    CHECK_RETHROW_VERBOSE(pis_emu_write_operand(&g_emu, addr_reg, addr));

    u64 mem_value = MAGIC64_2 & pis_size_max_unsigned_value(mem_value_size);
    CHECK_RETHROW_VERBOSE(pis_emu_write_mem_value(&g_emu, addr, mem_value, mem_value_size));

    CHECK_RETHROW_VERBOSE(emulate_insn(&g_emu, code, cpumode, 0));

    CHECK_RETHROW_VERBOSE(emu_assert_operand_equals(&g_emu, dst_reg, mem_value));

cleanup:
    return err;
}

DEFINE_TEST(test_movzx_32_bit_mode) {
    err_t err = SUCCESS;

    CHECK_RETHROW_VERBOSE(generic_test_mov_zero_extend_reg_modrm(
        CODE(0x0f, 0xb6, 0x00),
        PIS_X86_CPUMODE_32_BIT,
        &X86_EAX,
        &X86_EAX,
        PIS_SIZE_1
    ));

    CHECK_RETHROW_VERBOSE(generic_test_mov_zero_extend_reg_modrm(
        CODE(0x66, 0x0f, 0xb6, 0x00),
        PIS_X86_CPUMODE_32_BIT,
        &X86_AX,
        &X86_EAX,
        PIS_SIZE_1
    ));

cleanup:
    return err;
}

DEFINE_TEST(test_movzx_64_bit_mode) {
    err_t err = SUCCESS;

    CHECK_RETHROW_VERBOSE(generic_test_mov_zero_extend_reg_modrm(
        CODE(0x0f, 0xb6, 0x00),
        PIS_X86_CPUMODE_64_BIT,
        &X86_EAX,
        &X86_RAX,
        PIS_SIZE_1
    ));

    CHECK_RETHROW_VERBOSE(generic_test_mov_zero_extend_reg_modrm(
        CODE(0x66, 0x0f, 0xb6, 0x00),
        PIS_X86_CPUMODE_64_BIT,
        &X86_AX,
        &X86_RAX,
        PIS_SIZE_1
    ));

    CHECK_RETHROW_VERBOSE(generic_test_mov_zero_extend_reg_modrm(
        CODE(0x48, 0x0f, 0xb6, 0x00),
        PIS_X86_CPUMODE_64_BIT,
        &X86_RAX,
        &X86_RAX,
        PIS_SIZE_1
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
    pis_size_t expected_pushed_value_size
) {
    err_t err = SUCCESS;

    u64 orig_sp = 0;
    CHECK_RETHROW_VERBOSE(pis_emu_read_operand(emu, sp, &orig_sp));

    CHECK_RETHROW_VERBOSE(emulate_insn(&g_emu, code, cpumode, 0));

    // check the new sp value
    u64 new_sp = orig_sp - pis_size_to_bytes(expected_pushed_value_size);
    CHECK_RETHROW_VERBOSE(emu_assert_operand_equals(emu, sp, new_sp));

    // check the written memory value
    CHECK_RETHROW_VERBOSE(emu_assert_mem_value_equals(
        &g_emu,
        new_sp,
        expected_pushed_value_size,
        expected_pushed_value
    ));

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

    u64 sp_addr = MAGIC64_1 & pis_size_max_unsigned_value(sp->size);
    u64 pushed_value = MAGIC64_2 & pis_size_max_unsigned_value(pushed_reg->size);

    pis_emu_init(&g_emu, PIS_ENDIANNESS_LITTLE);
    CHECK_RETHROW_VERBOSE(pis_emu_write_operand(&g_emu, sp, sp_addr));
    CHECK_RETHROW_VERBOSE(pis_emu_write_operand(&g_emu, pushed_reg, pushed_value));
    CHECK_RETHROW_VERBOSE(
        generic_test_push(&g_emu, code, cpumode, sp, pushed_value, pushed_reg->size)
    );

    CHECK_RETHROW_VERBOSE(emu_assert_operand_equals(emu, pushed_reg, pushed_value));

cleanup:
    return err;
}

DEFINE_TEST(test_push_reg_64_bit_mode) {
    err_t err = SUCCESS;

    CHECK_RETHROW_VERBOSE(
        generic_test_push_reg(&g_emu, CODE(0x55), PIS_X86_CPUMODE_64_BIT, &X86_RSP, &X86_RBP)
    );

    CHECK_RETHROW_VERBOSE(
        generic_test_push_reg(&g_emu, CODE(0x41, 0x51), PIS_X86_CPUMODE_64_BIT, &X86_RSP, &X86_R9)
    );

    CHECK_RETHROW_VERBOSE(
        generic_test_push_reg(&g_emu, CODE(0x66, 0x52), PIS_X86_CPUMODE_64_BIT, &X86_RSP, &X86_DX)
    );

    CHECK_RETHROW_VERBOSE(generic_test_push_reg(
        &g_emu,
        CODE(0x66, 0x41, 0x53),
        PIS_X86_CPUMODE_64_BIT,
        &X86_RSP,
        &X86_R11W
    ));

    CHECK_RETHROW_VERBOSE(generic_test_push_reg(
        &g_emu,
        CODE(0x66, 0x48, 0x55),
        PIS_X86_CPUMODE_64_BIT,
        &X86_RSP,
        &X86_RBP
    ));

    CHECK_RETHROW_VERBOSE(generic_test_push_reg(
        &g_emu,
        CODE(0x66, 0x49, 0x50),
        PIS_X86_CPUMODE_64_BIT,
        &X86_RSP,
        &X86_R8
    ));

    // push rsp
    pis_emu_init(&g_emu, PIS_ENDIANNESS_LITTLE);
    CHECK_RETHROW_VERBOSE(pis_emu_write_operand(&g_emu, &X86_RSP, MAGIC64_1));
    CHECK_RETHROW_VERBOSE(generic_test_push(
        &g_emu,
        CODE(0x54),
        PIS_X86_CPUMODE_64_BIT,
        &X86_RSP,
        MAGIC64_1,
        PIS_SIZE_8
    ));

cleanup:
    return err;
}

DEFINE_TEST(test_push_reg_32_bit_mode) {
    err_t err = SUCCESS;

    CHECK_RETHROW_VERBOSE(
        generic_test_push_reg(&g_emu, CODE(0x50), PIS_X86_CPUMODE_32_BIT, &X86_ESP, &X86_EAX)
    );

    CHECK_RETHROW_VERBOSE(
        generic_test_push_reg(&g_emu, CODE(0x66, 0x55), PIS_X86_CPUMODE_32_BIT, &X86_ESP, &X86_BP)
    );

cleanup:
    return err;
}

static bool calc_parity_bit(u64 value) {
    return !__builtin_parity(value & UINT8_MAX);
}

static err_t verify_parity_sign_zero_flags(u64 calculation_result) {
    err_t err = SUCCESS;
    CHECK_RETHROW_VERBOSE(emu_assert_operand_equals(&g_emu, &X86_FLAGS_ZF, calculation_result == 0)
    );
    CHECK_RETHROW_VERBOSE(
        emu_assert_operand_equals(&g_emu, &X86_FLAGS_SF, ((i64) calculation_result < 0))
    );
    CHECK_RETHROW_VERBOSE(
        emu_assert_operand_equals(&g_emu, &X86_FLAGS_PF, calc_parity_bit(calculation_result))
    );
cleanup:
    return err;
}

static err_t generic_test_add_flags(u64 lhs, u64 rhs, bool carry_flag, bool overflow_flag) {
    err_t err = SUCCESS;

    pis_emu_init(&g_emu, PIS_ENDIANNESS_LITTLE);

    CHECK_RETHROW_VERBOSE(pis_emu_write_operand(&g_emu, &X86_RAX, lhs));
    CHECK_RETHROW_VERBOSE(pis_emu_write_operand(&g_emu, &X86_RBX, rhs));

    CHECK_RETHROW_VERBOSE(emulate_insn(&g_emu, CODE(0x48, 0x01, 0xd8), PIS_X86_CPUMODE_64_BIT, 0));

    // make sure that rax now contains the sum
    u64 sum = lhs + rhs;
    CHECK_RETHROW_VERBOSE(emu_assert_operand_equals(&g_emu, &X86_RAX, sum));

    // make sure that rbx is unchanged
    CHECK_RETHROW_VERBOSE(emu_assert_operand_equals(&g_emu, &X86_RBX, rhs));

    // verify flags
    CHECK_RETHROW_VERBOSE(verify_parity_sign_zero_flags(sum));
    CHECK_RETHROW_VERBOSE(emu_assert_operand_equals(&g_emu, &X86_FLAGS_CF, carry_flag));
    CHECK_RETHROW_VERBOSE(emu_assert_operand_equals(&g_emu, &X86_FLAGS_OF, overflow_flag));

cleanup:
    return err;
}

static err_t generic_test_add_flags_commutative(u64 a, u64 b, bool carry_flag, bool overflow_flag) {
    err_t err = SUCCESS;

    CHECK_RETHROW_VERBOSE(generic_test_add_flags(a, b, carry_flag, overflow_flag));
    if (a != b) {
        // try swapping the lhs and the rhs, it should behave the same.
        CHECK_RETHROW_VERBOSE(generic_test_add_flags(b, a, carry_flag, overflow_flag));
    }

cleanup:
    return err;
}

DEFINE_TEST(test_add_flags) {
    err_t err = SUCCESS;

    CHECK_RETHROW_VERBOSE(generic_test_add_flags_commutative(1ULL, 1ULL, false, false));

    CHECK_RETHROW_VERBOSE(generic_test_add_flags_commutative(UINT64_MAX, 1ULL, true, false));

    CHECK_RETHROW_VERBOSE(generic_test_add_flags_commutative(1ULL, INT64_MAX, false, true));

    CHECK_RETHROW_VERBOSE(generic_test_add_flags_commutative(INT64_MIN, INT64_MIN, true, true));

cleanup:
    return err;
}

static err_t generic_test_sub_flags(u64 lhs, u64 rhs, bool carry_flag, bool overflow_flag) {
    err_t err = SUCCESS;

    pis_emu_init(&g_emu, PIS_ENDIANNESS_LITTLE);

    CHECK_RETHROW_VERBOSE(pis_emu_write_operand(&g_emu, &X86_RAX, lhs));
    CHECK_RETHROW_VERBOSE(pis_emu_write_operand(&g_emu, &X86_RBX, rhs));

    CHECK_RETHROW_VERBOSE(emulate_insn(&g_emu, CODE(0x48, 0x29, 0xd8), PIS_X86_CPUMODE_64_BIT, 0));

    // make sure that rax now contains the result
    u64 res = lhs - rhs;
    CHECK_RETHROW_VERBOSE(emu_assert_operand_equals(&g_emu, &X86_RAX, res));

    // make sure that rbx is unchanged
    CHECK_RETHROW_VERBOSE(emu_assert_operand_equals(&g_emu, &X86_RBX, rhs));

    // verify flags
    CHECK_RETHROW_VERBOSE(verify_parity_sign_zero_flags(res));
    CHECK_RETHROW_VERBOSE(emu_assert_operand_equals(&g_emu, &X86_FLAGS_CF, carry_flag));
    CHECK_RETHROW_VERBOSE(emu_assert_operand_equals(&g_emu, &X86_FLAGS_OF, overflow_flag));

cleanup:
    return err;
}

DEFINE_TEST(test_sub_flags) {
    err_t err = SUCCESS;

    CHECK_RETHROW_VERBOSE(generic_test_sub_flags(1ULL, 1ULL, false, false));

    CHECK_RETHROW_VERBOSE(generic_test_sub_flags(0, 1ULL, true, false));

    CHECK_RETHROW_VERBOSE(generic_test_sub_flags(INT64_MIN, 1ULL, false, true));

    CHECK_RETHROW_VERBOSE(generic_test_sub_flags(INT64_MAX, INT64_MIN, true, true));

cleanup:
    return err;
}

static err_t generic_prepare_shift_rax(
    u64 lhs,
    bool orig_carry_flag,
    bool orig_overflow_flag,
    bool orig_parity_flag,
    bool orig_sign_flag,
    bool orig_zero_flag
) {
    err_t err = SUCCESS;

    pis_emu_init(&g_emu, PIS_ENDIANNESS_LITTLE);

    CHECK_RETHROW_VERBOSE(pis_emu_write_operand(&g_emu, &X86_RAX, lhs));
    CHECK_RETHROW_VERBOSE(pis_emu_write_operand(&g_emu, &X86_FLAGS_CF, orig_carry_flag));
    CHECK_RETHROW_VERBOSE(pis_emu_write_operand(&g_emu, &X86_FLAGS_OF, orig_overflow_flag));

    CHECK_RETHROW_VERBOSE(pis_emu_write_operand(&g_emu, &X86_FLAGS_PF, orig_parity_flag));
    CHECK_RETHROW_VERBOSE(pis_emu_write_operand(&g_emu, &X86_FLAGS_SF, orig_sign_flag));
    CHECK_RETHROW_VERBOSE(pis_emu_write_operand(&g_emu, &X86_FLAGS_ZF, orig_zero_flag));

cleanup:
    return err;
}

static err_t generic_check_shift_result(
    u8 shift_amount,
    u64 expected_result,
    bool orig_parity_flag,
    bool orig_sign_flag,
    bool orig_zero_flag,
    bool new_carry_flag,
    bool new_overflow_flag
) {
    err_t err = SUCCESS;

    // make sure that rax now contains the result
    u64 masked_shift_amount = shift_amount & 0b111111;
    CHECK_RETHROW_VERBOSE(emu_assert_operand_equals(&g_emu, &X86_RAX, expected_result));

    // verify flags
    if (masked_shift_amount != 0) {
        CHECK_RETHROW_VERBOSE(verify_parity_sign_zero_flags(expected_result));
    } else {
        CHECK_RETHROW_VERBOSE(emu_assert_operand_equals(&g_emu, &X86_FLAGS_ZF, orig_zero_flag));
        CHECK_RETHROW_VERBOSE(emu_assert_operand_equals(&g_emu, &X86_FLAGS_SF, orig_sign_flag));
        CHECK_RETHROW_VERBOSE(emu_assert_operand_equals(&g_emu, &X86_FLAGS_PF, orig_parity_flag));
    }
    CHECK_RETHROW_VERBOSE(emu_assert_operand_equals(&g_emu, &X86_FLAGS_CF, new_carry_flag));
    CHECK_RETHROW_VERBOSE(emu_assert_operand_equals(&g_emu, &X86_FLAGS_OF, new_overflow_flag));

cleanup:
    return err;
}

static err_t generic_test_shl_imm(
    u64 lhs,
    u8 shift_amount,
    bool orig_carry_flag,
    bool orig_overflow_flag,
    bool orig_parity_flag,
    bool orig_sign_flag,
    bool orig_zero_flag,
    bool new_carry_flag,
    bool new_overflow_flag
) {
    err_t err = SUCCESS;

    CHECK_RETHROW_VERBOSE(generic_prepare_shift_rax(
        lhs,
        orig_carry_flag,
        orig_overflow_flag,
        orig_parity_flag,
        orig_sign_flag,
        orig_zero_flag
    ));

    u8 code[] = {0x48, 0xc1, 0xe0, shift_amount};
    CHECK_RETHROW_VERBOSE(emulate_insn(
        &g_emu,
        (code_t) {
            .code = code,
            .len = ARRAY_SIZE(code),
        },
        PIS_X86_CPUMODE_64_BIT,
        0
    ));

    CHECK_RETHROW_VERBOSE(generic_check_shift_result(
        shift_amount,
        lhs << shift_amount,
        orig_parity_flag,
        orig_sign_flag,
        orig_zero_flag,
        new_carry_flag,
        new_overflow_flag
    ));

cleanup:
    return err;
}

static err_t generic_test_shl_cl(
    u64 lhs,
    u8 shift_amount,
    bool orig_carry_flag,
    bool orig_overflow_flag,
    bool orig_parity_flag,
    bool orig_sign_flag,
    bool orig_zero_flag,
    bool new_carry_flag,
    bool new_overflow_flag
) {
    err_t err = SUCCESS;

    CHECK_RETHROW_VERBOSE(generic_prepare_shift_rax(
        lhs,
        orig_carry_flag,
        orig_overflow_flag,
        orig_parity_flag,
        orig_sign_flag,
        orig_zero_flag
    ));
    CHECK_RETHROW_VERBOSE(pis_emu_write_operand(&g_emu, &X86_CL, shift_amount));

    CHECK_RETHROW_VERBOSE(emulate_insn(&g_emu, CODE(0x48, 0xd3, 0xe0), PIS_X86_CPUMODE_64_BIT, 0));

    CHECK_RETHROW_VERBOSE(generic_check_shift_result(
        shift_amount,
        lhs << shift_amount,
        orig_parity_flag,
        orig_sign_flag,
        orig_zero_flag,
        new_carry_flag,
        new_overflow_flag
    ));

cleanup:
    return err;
}
static err_t generic_test_shl_full(
    u64 lhs,
    u8 shift_amount,
    bool orig_carry_flag,
    bool orig_overflow_flag,
    bool orig_parity_flag,
    bool orig_sign_flag,
    bool orig_zero_flag,
    bool new_carry_flag,
    bool new_overflow_flag
) {
    err_t err = SUCCESS;
    CHECK_RETHROW_VERBOSE(generic_test_shl_imm(
        lhs,
        shift_amount,
        orig_carry_flag,
        orig_overflow_flag,
        orig_parity_flag,
        orig_sign_flag,
        orig_zero_flag,
        new_carry_flag,
        new_overflow_flag
    ));
    CHECK_RETHROW_VERBOSE(generic_test_shl_cl(
        lhs,
        shift_amount,
        orig_carry_flag,
        orig_overflow_flag,
        orig_parity_flag,
        orig_sign_flag,
        orig_zero_flag,
        new_carry_flag,
        new_overflow_flag
    ));
cleanup:
    return err;
}

static err_t generic_test_shl(
    u64 lhs,
    u8 shift_amount,
    bool orig_carry_flag,
    bool orig_overflow_flag,
    bool new_carry_flag,
    bool new_overflow_flag
) {
    err_t err = SUCCESS;

    // test with both possible initial values for the easily calculatable flags
    CHECK_RETHROW_VERBOSE(generic_test_shl_full(
        lhs,
        shift_amount,
        orig_carry_flag,
        orig_overflow_flag,
        false,
        false,
        false,
        new_carry_flag,
        new_overflow_flag
    ));
    CHECK_RETHROW_VERBOSE(generic_test_shl_full(
        lhs,
        shift_amount,
        orig_carry_flag,
        orig_overflow_flag,
        true,
        true,
        true,
        new_carry_flag,
        new_overflow_flag
    ));

cleanup:
    return err;
}

DEFINE_TEST(test_shl) {
    err_t err = SUCCESS;

    // make sure that no flags are affected with a zero shift count
    CHECK_RETHROW_VERBOSE(generic_test_shl(UINT64_MAX, 0, false, false, false, false));
    CHECK_RETHROW_VERBOSE(generic_test_shl(UINT64_MAX, 0, true, true, true, true));

    // make sure that no flags are affected with a shift count that results in zero after masking it
    CHECK_RETHROW_VERBOSE(generic_test_shl(UINT64_MAX, 1 << 7, false, false, false, false));
    CHECK_RETHROW_VERBOSE(generic_test_shl(UINT64_MAX, 1 << 7, true, true, true, true));

    // make sure that the carry flag is overwritten by last shifted bit
    CHECK_RETHROW_VERBOSE(generic_test_shl(~(1ULL << 62), 2, true, false, false, false));
    CHECK_RETHROW_VERBOSE(generic_test_shl(~(1ULL << 62), 2, false, false, false, false));
    CHECK_RETHROW_VERBOSE(generic_test_shl(1ULL << 62, 2, false, false, true, false));
    CHECK_RETHROW_VERBOSE(generic_test_shl(1ULL << 62, 2, true, false, true, false));
    CHECK_RETHROW_VERBOSE(generic_test_shl(1ULL << 1, 63, true, false, true, false));

    // make sure that the overflow flag is set accordingly
    CHECK_RETHROW_VERBOSE(generic_test_shl((1ULL << 63) | (1ULL << 62), 1, false, true, true, false)
    );
    CHECK_RETHROW_VERBOSE(generic_test_shl(1ULL << 62, 1, true, false, false, true));

    // make sure that the overflow flag is only set if the shift count is 1
    CHECK_RETHROW_VERBOSE(generic_test_shl((1ULL << 62) | (1ULL << 61), 2, false, true, true, true)
    );
    CHECK_RETHROW_VERBOSE(generic_test_shl(1ULL << 61, 2, true, false, false, false));

cleanup:
    return err;
}

DEFINE_TEST(test_movsx_r_rm8) {
    err_t err = SUCCESS;

    pis_emu_init(&g_emu, PIS_ENDIANNESS_LITTLE);

    u64 addr = MAGIC64_1;
    CHECK_RETHROW_VERBOSE(pis_emu_write_operand(&g_emu, &X86_RBP, addr));

    u8 mem_value = MAGIC64_2 & UINT8_MAX;
    CHECK_RETHROW_VERBOSE(pis_emu_write_mem_value(&g_emu, addr, mem_value, PIS_SIZE_1));

    CHECK_RETHROW_VERBOSE(
        emulate_insn(&g_emu, CODE(0x48, 0x0f, 0xbe, 0x45, 0x00), PIS_X86_CPUMODE_64_BIT, 0)
    );

    u64 sign_extended_mem_value = (u64) ((i64) ((i8) mem_value));

    CHECK_RETHROW_VERBOSE(emu_assert_operand_equals(&g_emu, &X86_RAX, sign_extended_mem_value));

cleanup:
    return err;
}

DEFINE_TEST(test_movsx_r_rm16) {
    err_t err = SUCCESS;

    pis_emu_init(&g_emu, PIS_ENDIANNESS_LITTLE);

    u16 value = MAGIC64_1 & UINT16_MAX;
    CHECK_RETHROW_VERBOSE(pis_emu_write_operand(&g_emu, &X86_AX, value));

    CHECK_RETHROW_VERBOSE(
        emulate_insn(&g_emu, CODE(0x48, 0x0f, 0xbf, 0xc0), PIS_X86_CPUMODE_64_BIT, 0)
    );

    u64 sign_extended_value = (u64) ((i64) ((i16) value));

    CHECK_RETHROW_VERBOSE(emu_assert_operand_equals(&g_emu, &X86_RAX, sign_extended_value));

cleanup:
    return err;
}

static err_t generic_test_cbw_cwde_cdqe(
    code_t code,
    u64 value,
    u64 sign_extended_value,
    const pis_operand_t* src_reg,
    const pis_operand_t* dst_reg
) {
    err_t err = SUCCESS;

    pis_emu_init(&g_emu, PIS_ENDIANNESS_LITTLE);

    CHECK_RETHROW_VERBOSE(pis_emu_write_operand(&g_emu, src_reg, value));

    CHECK_RETHROW_VERBOSE(emulate_insn(&g_emu, code, PIS_X86_CPUMODE_64_BIT, 0));

    CHECK_RETHROW_VERBOSE(emu_assert_operand_equals(&g_emu, dst_reg, sign_extended_value));

cleanup:
    return err;
}

DEFINE_TEST(test_cbw_cwde_cdqe) {
    err_t err = SUCCESS;

    u64 value = 0;
    u64 sign_extended_value = 0;

    value = MAGIC64_1 & UINT8_MAX;
    sign_extended_value = (u16) ((i16) ((i8) value));
    CHECK_RETHROW_VERBOSE(
        generic_test_cbw_cwde_cdqe(CODE(0x66, 0x98), value, sign_extended_value, &X86_AL, &X86_AX)
    );

    value = MAGIC64_1 & UINT16_MAX;
    sign_extended_value = (u32) ((i32) ((i16) value));
    CHECK_RETHROW_VERBOSE(
        generic_test_cbw_cwde_cdqe(CODE(0x98), value, sign_extended_value, &X86_AX, &X86_EAX)
    );

    value = MAGIC64_1 & UINT32_MAX;
    sign_extended_value = (u64) ((i64) ((i32) value));
    CHECK_RETHROW_VERBOSE(
        generic_test_cbw_cwde_cdqe(CODE(0x48, 0x98), value, sign_extended_value, &X86_EAX, &X86_RAX)
    );

cleanup:
    return err;
}

DEFINE_TEST(test_mov_32_bit_gpr) {
    err_t err = SUCCESS;

    pis_emu_init(&g_emu, PIS_ENDIANNESS_LITTLE);

    CHECK_RETHROW_VERBOSE(pis_emu_write_operand(&g_emu, &X86_RAX, UINT64_MAX));

    CHECK_RETHROW_VERBOSE(emulate_insn(&g_emu, CODE(0x31, 0xc0), PIS_X86_CPUMODE_64_BIT, 0));

    CHECK_RETHROW_VERBOSE(emu_assert_operand_equals(&g_emu, &X86_RAX, 0));

cleanup:
    return err;
}

static err_t generic_test_dec(u64 value, bool is_overflow) {
    err_t err = SUCCESS;

    pis_emu_init(&g_emu, PIS_ENDIANNESS_LITTLE);

    CHECK_RETHROW_VERBOSE(pis_emu_write_operand(&g_emu, &X86_RAX, value));

    CHECK_RETHROW_VERBOSE(emulate_insn(&g_emu, CODE(0x48, 0xff, 0xc8), PIS_X86_CPUMODE_64_BIT, 0));

    u64 res = value - 1;
    CHECK_RETHROW_VERBOSE(emu_assert_operand_equals(&g_emu, &X86_RAX, res));
    CHECK_RETHROW_VERBOSE(verify_parity_sign_zero_flags(res));
    CHECK_RETHROW_VERBOSE(emu_assert_operand_equals(&g_emu, &X86_FLAGS_OF, is_overflow));

cleanup:
    return err;
}

DEFINE_TEST(test_dec) {
    err_t err = SUCCESS;

    CHECK_RETHROW_VERBOSE(generic_test_dec(0, false));
    CHECK_RETHROW_VERBOSE(generic_test_dec(INT64_MIN, true));

cleanup:
    return err;
}

static err_t generic_test_shr_imm(
    u64 lhs,
    u8 shift_amount,
    bool orig_carry_flag,
    bool orig_overflow_flag,
    bool orig_parity_flag,
    bool orig_sign_flag,
    bool orig_zero_flag,
    bool new_carry_flag,
    bool new_overflow_flag
) {
    err_t err = SUCCESS;

    CHECK_RETHROW_VERBOSE(generic_prepare_shift_rax(
        lhs,
        orig_carry_flag,
        orig_overflow_flag,
        orig_parity_flag,
        orig_sign_flag,
        orig_zero_flag
    ));

    u8 code[] = {0x48, 0xc1, 0xe8, shift_amount};
    CHECK_RETHROW_VERBOSE(emulate_insn(
        &g_emu,
        (code_t) {
            .code = code,
            .len = ARRAY_SIZE(code),
        },
        PIS_X86_CPUMODE_64_BIT,
        0
    ));

    CHECK_RETHROW_VERBOSE(generic_check_shift_result(
        shift_amount,
        lhs >> shift_amount,
        orig_parity_flag,
        orig_sign_flag,
        orig_zero_flag,
        new_carry_flag,
        new_overflow_flag
    ));

cleanup:
    return err;
}

static err_t generic_test_shr_cl(
    u64 lhs,
    u8 shift_amount,
    bool orig_carry_flag,
    bool orig_overflow_flag,
    bool orig_parity_flag,
    bool orig_sign_flag,
    bool orig_zero_flag,
    bool new_carry_flag,
    bool new_overflow_flag
) {
    err_t err = SUCCESS;

    CHECK_RETHROW_VERBOSE(generic_prepare_shift_rax(
        lhs,
        orig_carry_flag,
        orig_overflow_flag,
        orig_parity_flag,
        orig_sign_flag,
        orig_zero_flag
    ));
    CHECK_RETHROW_VERBOSE(pis_emu_write_operand(&g_emu, &X86_CL, shift_amount));

    CHECK_RETHROW_VERBOSE(emulate_insn(&g_emu, CODE(0x48, 0xd3, 0xe8), PIS_X86_CPUMODE_64_BIT, 0));

    CHECK_RETHROW_VERBOSE(generic_check_shift_result(
        shift_amount,
        lhs >> shift_amount,
        orig_parity_flag,
        orig_sign_flag,
        orig_zero_flag,
        new_carry_flag,
        new_overflow_flag
    ));

cleanup:
    return err;
}
static err_t generic_test_shr_full(
    u64 lhs,
    u8 shift_amount,
    bool orig_carry_flag,
    bool orig_overflow_flag,
    bool orig_parity_flag,
    bool orig_sign_flag,
    bool orig_zero_flag,
    bool new_carry_flag,
    bool new_overflow_flag
) {
    err_t err = SUCCESS;
    CHECK_RETHROW_VERBOSE(generic_test_shr_imm(
        lhs,
        shift_amount,
        orig_carry_flag,
        orig_overflow_flag,
        orig_parity_flag,
        orig_sign_flag,
        orig_zero_flag,
        new_carry_flag,
        new_overflow_flag
    ));
    CHECK_RETHROW_VERBOSE(generic_test_shr_cl(
        lhs,
        shift_amount,
        orig_carry_flag,
        orig_overflow_flag,
        orig_parity_flag,
        orig_sign_flag,
        orig_zero_flag,
        new_carry_flag,
        new_overflow_flag
    ));
cleanup:
    return err;
}

static err_t generic_test_shr(
    u64 lhs,
    u8 shift_amount,
    bool orig_carry_flag,
    bool orig_overflow_flag,
    bool new_carry_flag,
    bool new_overflow_flag
) {
    err_t err = SUCCESS;

    // test with both possible initial values for the easily calculatable flags
    CHECK_RETHROW_VERBOSE(generic_test_shr_full(
        lhs,
        shift_amount,
        orig_carry_flag,
        orig_overflow_flag,
        false,
        false,
        false,
        new_carry_flag,
        new_overflow_flag
    ));
    CHECK_RETHROW_VERBOSE(generic_test_shr_full(
        lhs,
        shift_amount,
        orig_carry_flag,
        orig_overflow_flag,
        true,
        true,
        true,
        new_carry_flag,
        new_overflow_flag
    ));

cleanup:
    return err;
}

DEFINE_TEST(test_shr) {
    err_t err = SUCCESS;

    // make sure that no flags are affected with a zero shift count
    CHECK_RETHROW_VERBOSE(generic_test_shr(UINT64_MAX, 0, false, false, false, false));
    CHECK_RETHROW_VERBOSE(generic_test_shr(UINT64_MAX, 0, true, true, true, true));

    // make sure that no flags are affected with a shift count that results in zero after masking it
    CHECK_RETHROW_VERBOSE(generic_test_shr(UINT64_MAX, 1 << 7, false, false, false, false));
    CHECK_RETHROW_VERBOSE(generic_test_shr(UINT64_MAX, 1 << 7, true, true, true, true));

    // make sure that the carry flag is overwritten by last shifted bit
    CHECK_RETHROW_VERBOSE(generic_test_shr(~(1ULL << 1), 2, true, false, false, false));
    CHECK_RETHROW_VERBOSE(generic_test_shr(~(1ULL << 1), 2, false, false, false, false));
    CHECK_RETHROW_VERBOSE(generic_test_shr(1ULL << 1, 2, false, false, true, false));
    CHECK_RETHROW_VERBOSE(generic_test_shr(1ULL << 1, 2, true, false, true, false));
    CHECK_RETHROW_VERBOSE(generic_test_shr(1ULL << 62, 63, true, false, true, false));

    // make sure that the overflow flag is set accordingly
    CHECK_RETHROW_VERBOSE(generic_test_shr(1ULL << 63, 1, true, false, false, true));
    CHECK_RETHROW_VERBOSE(generic_test_shr(~(1ULL << 63), 1, false, true, true, false));

    // make sure that the overflow flag is only set if the shift count is 1
    CHECK_RETHROW_VERBOSE(generic_test_shr(1ULL << 63, 2, true, false, false, false));
    CHECK_RETHROW_VERBOSE(generic_test_shr(~(1ULL << 63), 2, false, true, true, true));

cleanup:
    return err;
}

static err_t generic_test_sar_imm(
    u64 lhs,
    u8 shift_amount,
    bool orig_carry_flag,
    bool orig_overflow_flag,
    bool orig_parity_flag,
    bool orig_sign_flag,
    bool orig_zero_flag,
    bool new_carry_flag,
    bool new_overflow_flag
) {
    err_t err = SUCCESS;

    CHECK_RETHROW_VERBOSE(generic_prepare_shift_rax(
        lhs,
        orig_carry_flag,
        orig_overflow_flag,
        orig_parity_flag,
        orig_sign_flag,
        orig_zero_flag
    ));

    u8 code[] = {0x48, 0xc1, 0xf8, shift_amount};
    CHECK_RETHROW_VERBOSE(emulate_insn(
        &g_emu,
        (code_t) {
            .code = code,
            .len = ARRAY_SIZE(code),
        },
        PIS_X86_CPUMODE_64_BIT,
        0
    ));

    CHECK_RETHROW_VERBOSE(generic_check_shift_result(
        shift_amount,
        (u64) ((i64) lhs >> shift_amount),
        orig_parity_flag,
        orig_sign_flag,
        orig_zero_flag,
        new_carry_flag,
        new_overflow_flag
    ));

cleanup:
    return err;
}

static err_t generic_test_sar_cl(
    u64 lhs,
    u8 shift_amount,
    bool orig_carry_flag,
    bool orig_overflow_flag,
    bool orig_parity_flag,
    bool orig_sign_flag,
    bool orig_zero_flag,
    bool new_carry_flag,
    bool new_overflow_flag
) {
    err_t err = SUCCESS;

    CHECK_RETHROW_VERBOSE(generic_prepare_shift_rax(
        lhs,
        orig_carry_flag,
        orig_overflow_flag,
        orig_parity_flag,
        orig_sign_flag,
        orig_zero_flag
    ));
    CHECK_RETHROW_VERBOSE(pis_emu_write_operand(&g_emu, &X86_CL, shift_amount));

    CHECK_RETHROW_VERBOSE(emulate_insn(&g_emu, CODE(0x48, 0xd3, 0xf8), PIS_X86_CPUMODE_64_BIT, 0));

    CHECK_RETHROW_VERBOSE(generic_check_shift_result(
        shift_amount,
        (u64) ((i64) lhs >> shift_amount),
        orig_parity_flag,
        orig_sign_flag,
        orig_zero_flag,
        new_carry_flag,
        new_overflow_flag
    ));

cleanup:
    return err;
}
static err_t generic_test_sar_full(
    u64 lhs,
    u8 shift_amount,
    bool orig_carry_flag,
    bool orig_overflow_flag,
    bool orig_parity_flag,
    bool orig_sign_flag,
    bool orig_zero_flag,
    bool new_carry_flag,
    bool new_overflow_flag
) {
    err_t err = SUCCESS;
    CHECK_RETHROW_VERBOSE(generic_test_sar_imm(
        lhs,
        shift_amount,
        orig_carry_flag,
        orig_overflow_flag,
        orig_parity_flag,
        orig_sign_flag,
        orig_zero_flag,
        new_carry_flag,
        new_overflow_flag
    ));
    CHECK_RETHROW_VERBOSE(generic_test_sar_cl(
        lhs,
        shift_amount,
        orig_carry_flag,
        orig_overflow_flag,
        orig_parity_flag,
        orig_sign_flag,
        orig_zero_flag,
        new_carry_flag,
        new_overflow_flag
    ));
cleanup:
    return err;
}

static err_t generic_test_sar(
    u64 lhs,
    u8 shift_amount,
    bool orig_carry_flag,
    bool orig_overflow_flag,
    bool new_carry_flag,
    bool new_overflow_flag
) {
    err_t err = SUCCESS;

    // test with both possible initial values for the easily calculatable flags
    CHECK_RETHROW_VERBOSE(generic_test_sar_full(
        lhs,
        shift_amount,
        orig_carry_flag,
        orig_overflow_flag,
        false,
        false,
        false,
        new_carry_flag,
        new_overflow_flag
    ));
    CHECK_RETHROW_VERBOSE(generic_test_sar_full(
        lhs,
        shift_amount,
        orig_carry_flag,
        orig_overflow_flag,
        true,
        true,
        true,
        new_carry_flag,
        new_overflow_flag
    ));

cleanup:
    return err;
}

DEFINE_TEST(test_sar) {
    err_t err = SUCCESS;

    // make sure that no flags are affected with a zero shift count
    CHECK_RETHROW_VERBOSE(generic_test_sar(UINT64_MAX, 0, false, false, false, false));
    CHECK_RETHROW_VERBOSE(generic_test_sar(UINT64_MAX, 0, true, true, true, true));

    // make sure that no flags are affected with a shift count that results in zero after masking it
    CHECK_RETHROW_VERBOSE(generic_test_sar(UINT64_MAX, 1 << 7, false, false, false, false));
    CHECK_RETHROW_VERBOSE(generic_test_sar(UINT64_MAX, 1 << 7, true, true, true, true));

    // make sure that the carry flag is overwritten by last shifted bit
    CHECK_RETHROW_VERBOSE(generic_test_sar(~(1ULL << 1), 2, true, false, false, false));
    CHECK_RETHROW_VERBOSE(generic_test_sar(~(1ULL << 1), 2, false, false, false, false));
    CHECK_RETHROW_VERBOSE(generic_test_sar(1ULL << 1, 2, false, false, true, false));
    CHECK_RETHROW_VERBOSE(generic_test_sar(1ULL << 1, 2, true, false, true, false));
    CHECK_RETHROW_VERBOSE(generic_test_sar(1ULL << 62, 63, true, false, true, false));

    // make sure that the overflow flag is always set to 0 if the count is 1
    CHECK_RETHROW_VERBOSE(generic_test_sar(1ULL << 63, 1, true, false, false, false));
    CHECK_RETHROW_VERBOSE(generic_test_sar(~(1ULL << 63), 1, false, true, true, false));

    // make sure that the overflow flag is only set if the shift count is 1
    CHECK_RETHROW_VERBOSE(generic_test_sar(1ULL << 63, 2, true, false, false, false));
    CHECK_RETHROW_VERBOSE(generic_test_sar(~(1ULL << 63), 2, false, true, true, true));

cleanup:
    return err;
}
