#include "lift.h"
#include "cpuinfo.h"
#include "ctx.h"
#include "insn_fields.h"
#include "regs.h"

#define INSN_SIZE (sizeof(u32))

typedef err_t (*opcode_handler_t)(ctx_t* ctx);

// forward declaration
static const opcode_handler_t opcode_handlers_table[MIPS_MAX_OPCODE_VALUE + 1];

static const pis_op_t g_zero = {
    .kind = PIS_OP_KIND_IMM,
    .size = PIS_SIZE_4,
    .v =
        {
            .imm =
                {
                    .value = 0,
                },
        },
};

/// the encoding of the mips `ra` register
#define MIPS_REG_ENCODING_RA (0b11111)

typedef enum {
    REG_ACCESS_KIND_READ,
    REG_ACCESS_KIND_WRITE,
} reg_access_kind_t;

static pis_op_t reg_get_operand(u8 reg_encoding, reg_access_kind_t access_kind) {
    if (access_kind == REG_ACCESS_KIND_READ && reg_encoding == 0) {
        // reading register 0 always returns 0
        return PIS_OPERAND_IMM(0, PIS_SIZE_4);
    } else {
        return PIS_OPERAND_REG(reg_encoding * 4, PIS_SIZE_4);
    }
}

static err_t lift(ctx_t* ctx) {
    err_t err = SUCCESS;

    u8 opcode = insn_field_opcode(ctx->insn);
    opcode_handler_t opcode_handler = opcode_handlers_table[opcode];
    CHECK_TRACE_CODE(
        opcode_handler != NULL,
        PIS_ERR_UNSUPPORTED_INSN,
        "unsupported opcode 0x%2x",
        opcode
    );

    CHECK_RETHROW(opcode_handler(ctx));
cleanup:
    return err;
}

static u32 delay_slot_insn_addr(ctx_t* ctx) {
    return ctx->args->machine_code_addr + INSN_SIZE;
}

static err_t lift_delay_slot_insn(ctx_t* ctx) {
    err_t err = SUCCESS;

    // instructions in delay slot can't have delay slots
    CHECK(!ctx->is_in_delay_slot);

    // prepare context for lifting delay slot
    ctx->args->machine_code_addr += INSN_SIZE;
    ctx->is_in_delay_slot = true;
    u32 orig_insn = ctx->insn;
    CHECK_RETHROW(cursor_next_4(&ctx->args->machine_code, &ctx->insn, ctx->cpuinfo->endianness));

    CHECK_RETHROW(lift(ctx));

    // restore context
    ctx->args->machine_code_addr -= INSN_SIZE;
    ctx->is_in_delay_slot = false;
    ctx->insn = orig_insn;
cleanup:
    return err;
}

static u32 calc_pc_region_branch_target_addr(ctx_t* ctx) {
    u32 addr_upper_bits = delay_slot_insn_addr(ctx) & 0xf0000000;
    u32 addr_low_bits = insn_field_instr_index(ctx->insn) << 2;
    return addr_upper_bits | addr_low_bits;
}

static pis_op_t calc_pc_region_branch_target(ctx_t* ctx) {
    return PIS_OPERAND_RAM(calc_pc_region_branch_target_addr(ctx), PIS_SIZE_1);
}

static u32 calc_pc_rel_branch_target_addr(ctx_t* ctx) {
    u32 off = insn_field_imm_sext(ctx->insn);
    return delay_slot_insn_addr(ctx) + (off << 2);
}

static pis_op_t calc_pc_rel_branch_target(ctx_t* ctx) {
    return PIS_OPERAND_RAM(calc_pc_rel_branch_target_addr(ctx), PIS_SIZE_1);
}

static u32 calc_branch_ret_addr(ctx_t* ctx) {
    return ctx->args->machine_code_addr + 2 * INSN_SIZE;
}

static pis_op_t calc_branch_ret_addr_op(ctx_t* ctx) {
    return PIS_OPERAND_IMM(calc_branch_ret_addr(ctx), PIS_SIZE_4);
}

static err_t do_shift_imm(ctx_t* ctx, pis_opcode_t shift_opcode) {
    err_t err = SUCCESS;

    CHECK(insn_field_rs(ctx->insn) == 0);

    pis_op_t rt = reg_get_operand(insn_field_rt(ctx->insn), REG_ACCESS_KIND_READ);
    pis_op_t rd = reg_get_operand(insn_field_rd(ctx->insn), REG_ACCESS_KIND_WRITE);
    pis_op_t sa = PIS_OPERAND_IMM(insn_field_sa(ctx->insn), PIS_SIZE_4);

    PIS_EMIT(&ctx->args->result, PIS_INSN3(shift_opcode, rd, rt, sa));

cleanup:
    return err;
}

static err_t special_opcode_handler_func_00(ctx_t* ctx) {
    err_t err = SUCCESS;

    // function 0x00 is SLL

    CHECK_RETHROW(do_shift_imm(ctx, PIS_OPCODE_SHIFT_LEFT));

cleanup:
    return err;
}

static err_t special_opcode_handler_func_02(ctx_t* ctx) {
    err_t err = SUCCESS;

    // function 0x02 is SRL

    CHECK_RETHROW(do_shift_imm(ctx, PIS_OPCODE_SHIFT_RIGHT));

cleanup:
    return err;
}

static err_t special_opcode_handler_func_03(ctx_t* ctx) {
    err_t err = SUCCESS;

    // function 0x03 is SRA

    CHECK_RETHROW(do_shift_imm(ctx, PIS_OPCODE_SHIFT_RIGHT_SIGNED));

cleanup:
    return err;
}

static err_t do_shift_reg(ctx_t* ctx, pis_opcode_t shift_opcode) {
    err_t err = SUCCESS;

    CHECK(insn_field_sa(ctx->insn) == 0);

    pis_op_t rs = reg_get_operand(insn_field_rs(ctx->insn), REG_ACCESS_KIND_READ);
    pis_op_t rt = reg_get_operand(insn_field_rt(ctx->insn), REG_ACCESS_KIND_READ);
    pis_op_t rd = reg_get_operand(insn_field_rd(ctx->insn), REG_ACCESS_KIND_WRITE);

    pis_op_t shift_amount = TMP_ALLOC(&ctx->tmp_allocator, PIS_SIZE_4);
    PIS_EMIT(
        &ctx->args->result,
        PIS_INSN3(PIS_OPCODE_AND, shift_amount, rs, PIS_OPERAND_IMM(0b11111, PIS_SIZE_4))
    );

    PIS_EMIT(&ctx->args->result, PIS_INSN3(shift_opcode, rd, rt, shift_amount));

cleanup:
    return err;
}

static err_t special_opcode_handler_func_04(ctx_t* ctx) {
    err_t err = SUCCESS;

    // function 0x04 is SLLV

    CHECK_RETHROW(do_shift_reg(ctx, PIS_OPCODE_SHIFT_LEFT));

cleanup:
    return err;
}

static err_t special_opcode_handler_func_06(ctx_t* ctx) {
    err_t err = SUCCESS;

    // function 0x06 is SRLV

    CHECK_RETHROW(do_shift_reg(ctx, PIS_OPCODE_SHIFT_RIGHT));

cleanup:
    return err;
}

static err_t special_opcode_handler_func_07(ctx_t* ctx) {
    err_t err = SUCCESS;

    // function 0x07 is SRAV

    CHECK_RETHROW(do_shift_reg(ctx, PIS_OPCODE_SHIFT_RIGHT_SIGNED));

cleanup:
    return err;
}

static err_t special_opcode_handler_func_08(ctx_t* ctx) {
    err_t err = SUCCESS;

    // function 0x08 is JR

    CHECK(insn_field_rt(ctx->insn) == 0);
    CHECK(insn_field_rd(ctx->insn) == 0);
    CHECK(insn_field_sa(ctx->insn) == 0);

    u8 rs_encoding = insn_field_rs(ctx->insn);
    pis_op_t rs = reg_get_operand(rs_encoding, REG_ACCESS_KIND_READ);

    pis_op_t tmp = TMP_ALLOC(&ctx->tmp_allocator, PIS_SIZE_4);
    PIS_EMIT(&ctx->args->result, PIS_INSN2(PIS_OPCODE_MOVE, tmp, rs));

    CHECK_RETHROW(lift_delay_slot_insn(ctx));

    // if the jump is to the `ra` return address register, add a `ret` hint to it.
    pis_opcode_t opcode =
        (rs_encoding == MIPS_REG_ENCODING_RA) ? PIS_OPCODE_JMP_RET : PIS_OPCODE_JMP;
    PIS_EMIT(&ctx->args->result, PIS_INSN1(opcode, tmp));

cleanup:
    return err;
}

static err_t special_opcode_handler_func_09(ctx_t* ctx) {
    err_t err = SUCCESS;

    // function 0x09 is JALR

    CHECK(insn_field_rt(ctx->insn) == 0);
    CHECK(insn_field_sa(ctx->insn) == 0);

    pis_op_t rs = reg_get_operand(insn_field_rs(ctx->insn), REG_ACCESS_KIND_READ);
    pis_op_t rd = reg_get_operand(insn_field_rd(ctx->insn), REG_ACCESS_KIND_WRITE);

    pis_op_t tmp = TMP_ALLOC(&ctx->tmp_allocator, PIS_SIZE_4);
    PIS_EMIT(&ctx->args->result, PIS_INSN2(PIS_OPCODE_MOVE, tmp, rs));

    pis_op_t ret_addr_op = calc_branch_ret_addr_op(ctx);
    PIS_EMIT(&ctx->args->result, PIS_INSN2(PIS_OPCODE_MOVE, rd, ret_addr_op));

    CHECK_RETHROW(lift_delay_slot_insn(ctx));

    PIS_EMIT(&ctx->args->result, PIS_INSN1(PIS_OPCODE_JMP_CALL, tmp));

cleanup:
    return err;
}

static err_t special_opcode_handler_func_10(ctx_t* ctx) {
    err_t err = SUCCESS;

    // function 0x10 is MFHI

    CHECK(insn_field_rs(ctx->insn) == 0);
    CHECK(insn_field_rt(ctx->insn) == 0);
    CHECK(insn_field_sa(ctx->insn) == 0);

    pis_op_t rd = reg_get_operand(insn_field_rd(ctx->insn), REG_ACCESS_KIND_WRITE);

    PIS_EMIT(&ctx->args->result, PIS_INSN2(PIS_OPCODE_MOVE, rd, pis_reg_to_op(MIPS_REG_HI)));

cleanup:
    return err;
}

static err_t special_opcode_handler_func_11(ctx_t* ctx) {
    err_t err = SUCCESS;

    // function 0x11 is MTHI

    CHECK(insn_field_rt(ctx->insn) == 0);
    CHECK(insn_field_rd(ctx->insn) == 0);
    CHECK(insn_field_sa(ctx->insn) == 0);

    pis_op_t rs = reg_get_operand(insn_field_rs(ctx->insn), REG_ACCESS_KIND_READ);

    PIS_EMIT(&ctx->args->result, PIS_INSN2(PIS_OPCODE_MOVE, pis_reg_to_op(MIPS_REG_HI), rs));

cleanup:
    return err;
}

static err_t special_opcode_handler_func_12(ctx_t* ctx) {
    err_t err = SUCCESS;

    // function 0x12 is MFLO

    CHECK(insn_field_rs(ctx->insn) == 0);
    CHECK(insn_field_rt(ctx->insn) == 0);
    CHECK(insn_field_sa(ctx->insn) == 0);

    pis_op_t rd = reg_get_operand(insn_field_rd(ctx->insn), REG_ACCESS_KIND_WRITE);

    PIS_EMIT(&ctx->args->result, PIS_INSN2(PIS_OPCODE_MOVE, rd, pis_reg_to_op(MIPS_REG_LO)));

cleanup:
    return err;
}

static err_t special_opcode_handler_func_13(ctx_t* ctx) {
    err_t err = SUCCESS;

    // function 0x13 is MTLO

    CHECK(insn_field_rt(ctx->insn) == 0);
    CHECK(insn_field_rd(ctx->insn) == 0);
    CHECK(insn_field_sa(ctx->insn) == 0);

    pis_op_t rs = reg_get_operand(insn_field_rs(ctx->insn), REG_ACCESS_KIND_READ);

    PIS_EMIT(&ctx->args->result, PIS_INSN2(PIS_OPCODE_MOVE, pis_reg_to_op(MIPS_REG_LO), rs));

cleanup:
    return err;
}

/// zero/sign extend a register to 64 bits
static err_t reg_ext64(
    ctx_t* ctx, pis_opcode_t extend_opcode, const pis_op_t* reg, pis_op_t* extended

) {
    err_t err = SUCCESS;

    pis_op_t tmp = TMP_ALLOC(&ctx->tmp_allocator, PIS_SIZE_8);
    PIS_EMIT(&ctx->args->result, PIS_INSN2(extend_opcode, tmp, *reg));

    *extended = tmp;

cleanup:
    return err;
}

static err_t do_mul(ctx_t* ctx, pis_opcode_t reg_extend_opcode, pis_opcode_t mul_opcode) {
    err_t err = SUCCESS;

    CHECK(insn_field_rd(ctx->insn) == 0);
    CHECK(insn_field_sa(ctx->insn) == 0);

    pis_op_t rs = reg_get_operand(insn_field_rs(ctx->insn), REG_ACCESS_KIND_READ);
    pis_op_t rt = reg_get_operand(insn_field_rt(ctx->insn), REG_ACCESS_KIND_READ);

    // sign extend the operands
    pis_op_t rs_sext = {};
    CHECK_RETHROW(reg_ext64(ctx, reg_extend_opcode, &rs, &rs_sext));
    pis_op_t rt_sext = {};
    CHECK_RETHROW(reg_ext64(ctx, reg_extend_opcode, &rt, &rt_sext));

    pis_op_t mult_res = TMP_ALLOC(&ctx->tmp_allocator, PIS_SIZE_8);
    PIS_EMIT(&ctx->args->result, PIS_INSN3(mul_opcode, mult_res, rs_sext, rt_sext));

    // calculate LO
    PIS_EMIT(
        &ctx->args->result,
        PIS_INSN2(PIS_OPCODE_GET_LOW_BITS, pis_reg_to_op(MIPS_REG_LO), mult_res)
    );

    // calculate HI
    PIS_EMIT(
        &ctx->args->result,
        PIS_INSN3(PIS_OPCODE_SHIFT_RIGHT, mult_res, mult_res, PIS_OPERAND_IMM(32, PIS_SIZE_8))
    );
    PIS_EMIT(
        &ctx->args->result,
        PIS_INSN2(PIS_OPCODE_GET_LOW_BITS, pis_reg_to_op(MIPS_REG_HI), mult_res)
    );

cleanup:
    return err;
}

static err_t special_opcode_handler_func_18(ctx_t* ctx) {
    err_t err = SUCCESS;

    // function 0x18 is MULT

    CHECK_RETHROW(do_mul(ctx, PIS_OPCODE_SIGN_EXTEND, PIS_OPCODE_SIGNED_MUL));

cleanup:
    return err;
}

static err_t special_opcode_handler_func_19(ctx_t* ctx) {
    err_t err = SUCCESS;

    // function 0x19 is MULTU

    CHECK_RETHROW(do_mul(ctx, PIS_OPCODE_ZERO_EXTEND, PIS_OPCODE_UNSIGNED_MUL));

cleanup:
    return err;
}

static err_t special_opcode_handler_func_1a(ctx_t* ctx) {
    err_t err = SUCCESS;

    // function 0x1a is DIV

    CHECK(insn_field_rd(ctx->insn) == 0);
    CHECK(insn_field_sa(ctx->insn) == 0);

    pis_op_t rs = reg_get_operand(insn_field_rs(ctx->insn), REG_ACCESS_KIND_READ);
    pis_op_t rt = reg_get_operand(insn_field_rt(ctx->insn), REG_ACCESS_KIND_READ);

    // calculate LO
    PIS_EMIT(
        &ctx->args->result,
        PIS_INSN3(PIS_OPCODE_SIGNED_DIV, pis_reg_to_op(MIPS_REG_LO), rs, rt)
    );

    // calculate HI
    PIS_EMIT(
        &ctx->args->result,
        PIS_INSN3(PIS_OPCODE_SIGNED_REM, pis_reg_to_op(MIPS_REG_HI), rs, rt)
    );

cleanup:
    return err;
}

static err_t special_opcode_handler_func_1b(ctx_t* ctx) {
    err_t err = SUCCESS;

    // function 0x1b is DIVU

    CHECK(insn_field_rd(ctx->insn) == 0);
    CHECK(insn_field_sa(ctx->insn) == 0);

    pis_op_t rs = reg_get_operand(insn_field_rs(ctx->insn), REG_ACCESS_KIND_READ);
    pis_op_t rt = reg_get_operand(insn_field_rt(ctx->insn), REG_ACCESS_KIND_READ);

    // calculate LO
    PIS_EMIT(
        &ctx->args->result,
        PIS_INSN3(PIS_OPCODE_UNSIGNED_DIV, pis_reg_to_op(MIPS_REG_LO), rs, rt)
    );

    // calculate HI
    PIS_EMIT(
        &ctx->args->result,
        PIS_INSN3(PIS_OPCODE_UNSIGNED_REM, pis_reg_to_op(MIPS_REG_HI), rs, rt)
    );

cleanup:
    return err;
}

static err_t do_binop_reg(ctx_t* ctx, pis_opcode_t opcode) {
    err_t err = SUCCESS;

    CHECK(insn_field_sa(ctx->insn) == 0);

    pis_op_t rs = reg_get_operand(insn_field_rs(ctx->insn), REG_ACCESS_KIND_READ);
    pis_op_t rt = reg_get_operand(insn_field_rt(ctx->insn), REG_ACCESS_KIND_READ);
    pis_op_t rd = reg_get_operand(insn_field_rd(ctx->insn), REG_ACCESS_KIND_WRITE);

    PIS_EMIT(&ctx->args->result, PIS_INSN3(opcode, rd, rs, rt));

cleanup:
    return err;
}

static err_t special_opcode_handler_func_20(ctx_t* ctx) {
    err_t err = SUCCESS;

    // function 0x20 is ADD

    CHECK_RETHROW(do_binop_reg(ctx, PIS_OPCODE_ADD));

cleanup:
    return err;
}

static err_t special_opcode_handler_func_21(ctx_t* ctx) {
    err_t err = SUCCESS;

    // function 0x21 is ADDU

    CHECK_RETHROW(do_binop_reg(ctx, PIS_OPCODE_ADD));

cleanup:
    return err;
}

static err_t special_opcode_handler_func_22(ctx_t* ctx) {
    err_t err = SUCCESS;

    // function 0x22 is SUB

    CHECK_RETHROW(do_binop_reg(ctx, PIS_OPCODE_SUB));

cleanup:
    return err;
}

static err_t special_opcode_handler_func_23(ctx_t* ctx) {
    err_t err = SUCCESS;

    // function 0x23 is SUBU

    CHECK_RETHROW(do_binop_reg(ctx, PIS_OPCODE_SUB));

cleanup:
    return err;
}

static err_t special_opcode_handler_func_24(ctx_t* ctx) {
    err_t err = SUCCESS;

    // function 0x24 is AND

    CHECK_RETHROW(do_binop_reg(ctx, PIS_OPCODE_AND));

cleanup:
    return err;
}

static err_t special_opcode_handler_func_25(ctx_t* ctx) {
    err_t err = SUCCESS;

    // function 0x25 is OR

    CHECK_RETHROW(do_binop_reg(ctx, PIS_OPCODE_OR));

cleanup:
    return err;
}

static err_t special_opcode_handler_func_26(ctx_t* ctx) {
    err_t err = SUCCESS;

    // function 0x26 is XOR

    CHECK_RETHROW(do_binop_reg(ctx, PIS_OPCODE_XOR));

cleanup:
    return err;
}

static err_t special_opcode_handler_func_27(ctx_t* ctx) {
    err_t err = SUCCESS;

    // function 0x27 is NOR

    CHECK(insn_field_sa(ctx->insn) == 0);

    pis_op_t rs = reg_get_operand(insn_field_rs(ctx->insn), REG_ACCESS_KIND_READ);
    pis_op_t rt = reg_get_operand(insn_field_rt(ctx->insn), REG_ACCESS_KIND_READ);
    pis_op_t rd = reg_get_operand(insn_field_rd(ctx->insn), REG_ACCESS_KIND_WRITE);

    PIS_EMIT(&ctx->args->result, PIS_INSN3(PIS_OPCODE_OR, rd, rs, rt));
    PIS_EMIT(&ctx->args->result, PIS_INSN2(PIS_OPCODE_NOT, rd, rd));

cleanup:
    return err;
}

static err_t special_opcode_handler_func_2a(ctx_t* ctx) {
    err_t err = SUCCESS;

    // function 0x2a is SLT

    CHECK(insn_field_sa(ctx->insn) == 0);

    pis_op_t rs = reg_get_operand(insn_field_rs(ctx->insn), REG_ACCESS_KIND_READ);
    pis_op_t rt = reg_get_operand(insn_field_rt(ctx->insn), REG_ACCESS_KIND_READ);
    pis_op_t rd = reg_get_operand(insn_field_rd(ctx->insn), REG_ACCESS_KIND_WRITE);

    pis_op_t cond = TMP_ALLOC(&ctx->tmp_allocator, PIS_SIZE_1);
    PIS_EMIT(&ctx->args->result, PIS_INSN3(PIS_OPCODE_SIGNED_LESS_THAN, cond, rs, rt));

    PIS_EMIT(&ctx->args->result, PIS_INSN2(PIS_OPCODE_ZERO_EXTEND, rd, cond));

cleanup:
    return err;
}

static err_t special_opcode_handler_func_2b(ctx_t* ctx) {
    err_t err = SUCCESS;

    // function 0x2b is SLTU

    CHECK(insn_field_sa(ctx->insn) == 0);

    pis_op_t rs = reg_get_operand(insn_field_rs(ctx->insn), REG_ACCESS_KIND_READ);
    pis_op_t rt = reg_get_operand(insn_field_rt(ctx->insn), REG_ACCESS_KIND_READ);
    pis_op_t rd = reg_get_operand(insn_field_rd(ctx->insn), REG_ACCESS_KIND_WRITE);

    pis_op_t cond = TMP_ALLOC(&ctx->tmp_allocator, PIS_SIZE_1);
    PIS_EMIT(&ctx->args->result, PIS_INSN3(PIS_OPCODE_UNSIGNED_LESS_THAN, cond, rs, rt));

    PIS_EMIT(&ctx->args->result, PIS_INSN2(PIS_OPCODE_ZERO_EXTEND, rd, cond));

cleanup:
    return err;
}

static err_t do_branch_cond(ctx_t* ctx, const pis_op_t* cond, bool is_call) {
    err_t err = SUCCESS;

    pis_op_t target = calc_pc_rel_branch_target(ctx);

    CHECK_RETHROW(lift_delay_slot_insn(ctx));

    pis_opcode_t opcode = is_call ? PIS_OPCODE_JMP_CALL_COND : PIS_OPCODE_JMP_COND;
    PIS_EMIT(&ctx->args->result, PIS_INSN2(opcode, target, *cond));

cleanup:
    return err;
}

/// performs the "link" part of a "branch and link operation".
static err_t do_link(ctx_t* ctx) {
    err_t err = SUCCESS;

    pis_op_t ret_addr_op = calc_branch_ret_addr_op(ctx);
    PIS_EMIT(
        &ctx->args->result,
        PIS_INSN2(PIS_OPCODE_MOVE, pis_reg_to_op(MIPS_REG_RA), ret_addr_op)
    );

cleanup:
    return err;
}

static const opcode_handler_t special_opcode_func_handlers_table[MIPS_MAX_FUNCTION_VALUE + 1] = {
    [0x00] = special_opcode_handler_func_00, [0x02] = special_opcode_handler_func_02,
    [0x03] = special_opcode_handler_func_03, [0x04] = special_opcode_handler_func_04,
    [0x06] = special_opcode_handler_func_06, [0x07] = special_opcode_handler_func_07,
    [0x08] = special_opcode_handler_func_08, [0x09] = special_opcode_handler_func_09,
    [0x10] = special_opcode_handler_func_10, [0x11] = special_opcode_handler_func_11,
    [0x12] = special_opcode_handler_func_12, [0x13] = special_opcode_handler_func_13,
    [0x18] = special_opcode_handler_func_18, [0x19] = special_opcode_handler_func_19,
    [0x1a] = special_opcode_handler_func_1a, [0x1b] = special_opcode_handler_func_1b,
    [0x20] = special_opcode_handler_func_20, [0x21] = special_opcode_handler_func_21,
    [0x22] = special_opcode_handler_func_22, [0x23] = special_opcode_handler_func_23,
    [0x24] = special_opcode_handler_func_24, [0x25] = special_opcode_handler_func_25,
    [0x26] = special_opcode_handler_func_26, [0x27] = special_opcode_handler_func_27,
    [0x2a] = special_opcode_handler_func_2a, [0x2b] = special_opcode_handler_func_2b,
};

static err_t special2_opcode_handler_func_20(ctx_t* ctx) {
    err_t err = SUCCESS;

    // function 0x20 is CLZ

    CHECK(insn_field_sa(ctx->insn) == 0);
    CHECK(insn_field_rt(ctx->insn) == insn_field_rd(ctx->insn));

    pis_op_t rs = reg_get_operand(insn_field_rs(ctx->insn), REG_ACCESS_KIND_READ);
    pis_op_t rd = reg_get_operand(insn_field_rd(ctx->insn), REG_ACCESS_KIND_WRITE);

    PIS_EMIT(&ctx->args->result, PIS_INSN2(PIS_OPCODE_LEADING_ZEROES, rd, rs));

cleanup:
    return err;
}

static const opcode_handler_t special2_opcode_func_handlers_table[MIPS_MAX_FUNCTION_VALUE + 1] = {
    [0x20] = special2_opcode_handler_func_20,
};

static err_t opcode_handler_00(ctx_t* ctx) {
    err_t err = SUCCESS;

    // opcode 0x00 is the SPECIAL opcode, which is further decoded by the function field

    u8 function = insn_field_function(ctx->insn);

    opcode_handler_t handler = special_opcode_func_handlers_table[function];
    CHECK_TRACE_CODE(
        handler != NULL,
        PIS_ERR_UNSUPPORTED_INSN,
        "unsupported special function 0x%x",
        function
    );

    CHECK_RETHROW(handler(ctx));

cleanup:
    return err;
}

static err_t regimm_opcode_handler_00(ctx_t* ctx) {
    err_t err = SUCCESS;

    // rt 0x00 is BLTZ

    pis_op_t rs = reg_get_operand(insn_field_rs(ctx->insn), REG_ACCESS_KIND_READ);

    pis_op_t cond = TMP_ALLOC(&ctx->tmp_allocator, PIS_SIZE_1);
    PIS_EMIT(&ctx->args->result, PIS_INSN3(PIS_OPCODE_SIGNED_LESS_THAN, cond, rs, g_zero));

    CHECK_RETHROW(do_branch_cond(ctx, &cond, false));

cleanup:
    return err;
}

static err_t regimm_opcode_handler_01(ctx_t* ctx) {
    err_t err = SUCCESS;

    // rt 0x01 is BGEZ

    pis_op_t rs = reg_get_operand(insn_field_rs(ctx->insn), REG_ACCESS_KIND_READ);

    pis_op_t cond = TMP_ALLOC(&ctx->tmp_allocator, PIS_SIZE_1);
    PIS_EMIT(&ctx->args->result, PIS_INSN3(PIS_OPCODE_SIGNED_LESS_THAN, cond, rs, g_zero));
    PIS_EMIT(&ctx->args->result, PIS_INSN2(PIS_OPCODE_COND_NEGATE, cond, cond));

    CHECK_RETHROW(do_branch_cond(ctx, &cond, false));

cleanup:
    return err;
}

static err_t regimm_opcode_handler_10(ctx_t* ctx) {
    err_t err = SUCCESS;

    // rt 0x10 is BLTZAL

    pis_op_t rs = reg_get_operand(insn_field_rs(ctx->insn), REG_ACCESS_KIND_READ);

    pis_op_t cond = TMP_ALLOC(&ctx->tmp_allocator, PIS_SIZE_1);
    PIS_EMIT(&ctx->args->result, PIS_INSN3(PIS_OPCODE_SIGNED_LESS_THAN, cond, rs, g_zero));

    CHECK_RETHROW(do_link(ctx));

    CHECK_RETHROW(do_branch_cond(ctx, &cond, true));

cleanup:
    return err;
}

static err_t regimm_opcode_handler_11(ctx_t* ctx) {
    err_t err = SUCCESS;

    // rt 0x11 is BLTZAL

    pis_op_t rs = reg_get_operand(insn_field_rs(ctx->insn), REG_ACCESS_KIND_READ);

    pis_op_t cond = TMP_ALLOC(&ctx->tmp_allocator, PIS_SIZE_1);
    PIS_EMIT(&ctx->args->result, PIS_INSN3(PIS_OPCODE_SIGNED_LESS_THAN, cond, rs, g_zero));
    PIS_EMIT(&ctx->args->result, PIS_INSN2(PIS_OPCODE_COND_NEGATE, cond, cond));

    CHECK_RETHROW(do_link(ctx));

    CHECK_RETHROW(do_branch_cond(ctx, &cond, true));

cleanup:
    return err;
}

static const opcode_handler_t regimm_opcode_handlers_table[MIPS_GPRS_AMOUNT] = {
    [0x00] = regimm_opcode_handler_00,
    [0x01] = regimm_opcode_handler_01,
    [0x10] = regimm_opcode_handler_10,
    [0x11] = regimm_opcode_handler_11,
};

static err_t opcode_handler_01(ctx_t* ctx) {
    err_t err = SUCCESS;

    // opcode 0x01 is the REGIMM opcode, which is further decoded by the rt field

    u8 rt = insn_field_rt(ctx->insn);

    opcode_handler_t handler = regimm_opcode_handlers_table[rt];
    CHECK_TRACE_CODE(
        handler != NULL,
        PIS_ERR_UNSUPPORTED_INSN,
        "unsupported regimm rt value 0x%x",
        rt
    );

    CHECK_RETHROW(handler(ctx));

cleanup:
    return err;
}

static err_t do_jmp(ctx_t* ctx, bool is_call) {
    err_t err = SUCCESS;

    pis_op_t target = calc_pc_region_branch_target(ctx);

    // run the delay slot instruction
    CHECK_RETHROW(lift_delay_slot_insn(ctx));

    pis_opcode_t opcode = is_call ? PIS_OPCODE_JMP_CALL : PIS_OPCODE_JMP;
    PIS_EMIT(&ctx->args->result, PIS_INSN1(opcode, target));

cleanup:
    return err;
}

static err_t opcode_handler_02(ctx_t* ctx) {
    err_t err = SUCCESS;

    // opcode 0x02 is J

    CHECK_RETHROW(do_jmp(ctx, false));

cleanup:
    return err;
}

static err_t opcode_handler_03(ctx_t* ctx) {
    err_t err = SUCCESS;

    // opcode 0x03 is JAL

    CHECK_RETHROW(do_link(ctx));

    CHECK_RETHROW(do_jmp(ctx, true));

cleanup:
    return err;
}

static err_t opcode_handler_04(ctx_t* ctx) {
    err_t err = SUCCESS;

    // opcode 0x04 is BEQ

    u8 rs_value = insn_field_rs(ctx->insn);
    u8 rt_value = insn_field_rt(ctx->insn);

    if (rs_value == rt_value) {
        // comparing a register to itself always yields true, so this is basically a `B`
        // instruction.
        pis_op_t target = calc_pc_rel_branch_target(ctx);

        CHECK_RETHROW(lift_delay_slot_insn(ctx));

        PIS_EMIT(&ctx->args->result, PIS_INSN1(PIS_OPCODE_JMP, target));
    } else {
        // actual BEQ instruction.
        pis_op_t rs = reg_get_operand(rs_value, REG_ACCESS_KIND_READ);
        pis_op_t rt = reg_get_operand(rt_value, REG_ACCESS_KIND_READ);

        pis_op_t cond = TMP_ALLOC(&ctx->tmp_allocator, PIS_SIZE_1);
        PIS_EMIT(&ctx->args->result, PIS_INSN3(PIS_OPCODE_EQUALS, cond, rs, rt));

        CHECK_RETHROW(do_branch_cond(ctx, &cond, false));
    }


cleanup:
    return err;
}

static err_t opcode_handler_05(ctx_t* ctx) {
    err_t err = SUCCESS;

    // opcode 0x05 is BNE

    pis_op_t rs = reg_get_operand(insn_field_rs(ctx->insn), REG_ACCESS_KIND_READ);
    pis_op_t rt = reg_get_operand(insn_field_rt(ctx->insn), REG_ACCESS_KIND_READ);

    pis_op_t cond = TMP_ALLOC(&ctx->tmp_allocator, PIS_SIZE_1);
    PIS_EMIT(&ctx->args->result, PIS_INSN3(PIS_OPCODE_EQUALS, cond, rs, rt));
    PIS_EMIT(&ctx->args->result, PIS_INSN2(PIS_OPCODE_COND_NEGATE, cond, cond));

    CHECK_RETHROW(do_branch_cond(ctx, &cond, false));

cleanup:
    return err;
}

static err_t opcode_handler_06(ctx_t* ctx) {
    err_t err = SUCCESS;

    // opcode 0x06 is BLEZ

    pis_op_t rs = reg_get_operand(insn_field_rs(ctx->insn), REG_ACCESS_KIND_READ);
    CHECK(insn_field_rt(ctx->insn) == 0);

    pis_op_t less_than_zero = TMP_ALLOC(&ctx->tmp_allocator, PIS_SIZE_1);
    PIS_EMIT(
        &ctx->args->result,
        PIS_INSN3(PIS_OPCODE_SIGNED_LESS_THAN, less_than_zero, rs, g_zero)
    );

    pis_op_t equals_zero = TMP_ALLOC(&ctx->tmp_allocator, PIS_SIZE_1);
    PIS_EMIT(&ctx->args->result, PIS_INSN3(PIS_OPCODE_EQUALS, equals_zero, rs, g_zero));

    pis_op_t cond = TMP_ALLOC(&ctx->tmp_allocator, PIS_SIZE_1);
    PIS_EMIT(&ctx->args->result, PIS_INSN3(PIS_OPCODE_OR, cond, less_than_zero, equals_zero));

    CHECK_RETHROW(do_branch_cond(ctx, &cond, false));

cleanup:
    return err;
}

static err_t opcode_handler_07(ctx_t* ctx) {
    err_t err = SUCCESS;

    // opcode 0x07 is BGTZ

    pis_op_t rs = reg_get_operand(insn_field_rs(ctx->insn), REG_ACCESS_KIND_READ);
    CHECK(insn_field_rt(ctx->insn) == 0);

    pis_op_t less_than_zero = TMP_ALLOC(&ctx->tmp_allocator, PIS_SIZE_1);
    PIS_EMIT(
        &ctx->args->result,
        PIS_INSN3(PIS_OPCODE_SIGNED_LESS_THAN, less_than_zero, rs, g_zero)
    );

    pis_op_t equals_zero = TMP_ALLOC(&ctx->tmp_allocator, PIS_SIZE_1);
    PIS_EMIT(&ctx->args->result, PIS_INSN3(PIS_OPCODE_EQUALS, equals_zero, rs, g_zero));

    pis_op_t cond = TMP_ALLOC(&ctx->tmp_allocator, PIS_SIZE_1);
    PIS_EMIT(&ctx->args->result, PIS_INSN3(PIS_OPCODE_OR, cond, less_than_zero, equals_zero));
    PIS_EMIT(&ctx->args->result, PIS_INSN2(PIS_OPCODE_COND_NEGATE, cond, cond));

    CHECK_RETHROW(do_branch_cond(ctx, &cond, false));

cleanup:
    return err;
}

static err_t do_binop_imm(ctx_t* ctx, pis_opcode_t opcode, imm_ext_kind_t ext_kind) {
    err_t err = SUCCESS;

    pis_op_t rs = reg_get_operand(insn_field_rs(ctx->insn), REG_ACCESS_KIND_READ);
    pis_op_t rt = reg_get_operand(insn_field_rt(ctx->insn), REG_ACCESS_KIND_WRITE);
    u32 imm = insn_field_imm_ext(ctx->insn, ext_kind);

    PIS_EMIT(&ctx->args->result, PIS_INSN3(opcode, rt, rs, PIS_OPERAND_IMM(imm, PIS_SIZE_4)));

cleanup:
    return err;
}

static err_t opcode_handler_08(ctx_t* ctx) {
    err_t err = SUCCESS;

    // opcode 0x08 is ADDI

    // we ignore the addi behaviour of raising an exception if integer overflow occurs and just lift
    // it as a regular add.
    CHECK_RETHROW(do_binop_imm(ctx, PIS_OPCODE_ADD, IMM_EXT_KIND_SIGN_EXTEND));

cleanup:
    return err;
}

static err_t opcode_handler_09(ctx_t* ctx) {
    err_t err = SUCCESS;

    // opcode 0x09 is ADDIU

    CHECK_RETHROW(do_binop_imm(ctx, PIS_OPCODE_ADD, IMM_EXT_KIND_SIGN_EXTEND));

cleanup:
    return err;
}

static err_t opcode_handler_0a(ctx_t* ctx) {
    err_t err = SUCCESS;

    // opcode 0x0a is SLTI
    pis_op_t rs = reg_get_operand(insn_field_rs(ctx->insn), REG_ACCESS_KIND_READ);
    pis_op_t rt = reg_get_operand(insn_field_rt(ctx->insn), REG_ACCESS_KIND_WRITE);
    u32 imm = insn_field_imm_sext(ctx->insn);

    pis_op_t cond = TMP_ALLOC(&ctx->tmp_allocator, PIS_SIZE_1);
    PIS_EMIT(
        &ctx->args->result,
        PIS_INSN3(PIS_OPCODE_SIGNED_LESS_THAN, cond, rs, PIS_OPERAND_IMM(imm, PIS_SIZE_4))
    );

    PIS_EMIT(&ctx->args->result, PIS_INSN2(PIS_OPCODE_ZERO_EXTEND, rt, cond));

cleanup:
    return err;
}

static err_t opcode_handler_0b(ctx_t* ctx) {
    err_t err = SUCCESS;

    // opcode 0x0b is SLTIU

    pis_op_t rs = reg_get_operand(insn_field_rs(ctx->insn), REG_ACCESS_KIND_READ);
    pis_op_t rt = reg_get_operand(insn_field_rt(ctx->insn), REG_ACCESS_KIND_WRITE);
    u32 imm = insn_field_imm_sext(ctx->insn);

    pis_op_t cond = TMP_ALLOC(&ctx->tmp_allocator, PIS_SIZE_1);
    PIS_EMIT(
        &ctx->args->result,
        PIS_INSN3(PIS_OPCODE_UNSIGNED_LESS_THAN, cond, rs, PIS_OPERAND_IMM(imm, PIS_SIZE_4))
    );

    PIS_EMIT(&ctx->args->result, PIS_INSN2(PIS_OPCODE_ZERO_EXTEND, rt, cond));

cleanup:
    return err;
}

static err_t opcode_handler_0c(ctx_t* ctx) {
    err_t err = SUCCESS;

    // opcode 0x0c is ANDI

    CHECK_RETHROW(do_binop_imm(ctx, PIS_OPCODE_AND, IMM_EXT_KIND_ZERO_EXTEND));

cleanup:
    return err;
}

static err_t opcode_handler_0d(ctx_t* ctx) {
    err_t err = SUCCESS;

    // opcode 0x0d is ORI

    CHECK_RETHROW(do_binop_imm(ctx, PIS_OPCODE_OR, IMM_EXT_KIND_ZERO_EXTEND));

cleanup:
    return err;
}

static err_t opcode_handler_0e(ctx_t* ctx) {
    err_t err = SUCCESS;

    // opcode 0x0e is XORI

    CHECK_RETHROW(do_binop_imm(ctx, PIS_OPCODE_XOR, IMM_EXT_KIND_ZERO_EXTEND));

cleanup:
    return err;
}

static err_t opcode_handler_0f(ctx_t* ctx) {
    err_t err = SUCCESS;

    // opcode 0x0f is LUI

    CHECK(insn_field_rs(ctx->insn) == 0);
    pis_op_t rt = reg_get_operand(insn_field_rt(ctx->insn), REG_ACCESS_KIND_WRITE);
    u32 imm = insn_field_imm_zext(ctx->insn);
    u32 value = imm << 16;

    PIS_EMIT(
        &ctx->args->result,
        PIS_INSN2(PIS_OPCODE_MOVE, rt, PIS_OPERAND_IMM(value, PIS_SIZE_4))
    );

cleanup:
    return err;
}

static err_t opcode_handler_1c(ctx_t* ctx) {
    err_t err = SUCCESS;

    // opcode 0x1c is the SPECIAL2 opcode, which is further decoded by the function field

    u8 function = insn_field_function(ctx->insn);

    opcode_handler_t handler = special2_opcode_func_handlers_table[function];
    CHECK_TRACE_CODE(
        handler != NULL,
        PIS_ERR_UNSUPPORTED_INSN,
        "unsupported special2 function 0x%x",
        function
    );

    CHECK_RETHROW(handler(ctx));

cleanup:
    return err;
}

static err_t
    calc_load_store_addr(ctx_t* ctx, const pis_op_t* base, u32 offset, pis_op_t* calculated_addr) {
    err_t err = SUCCESS;

    pis_op_t addr = TMP_ALLOC(&ctx->tmp_allocator, PIS_SIZE_4);
    PIS_EMIT(
        &ctx->args->result,
        PIS_INSN3(PIS_OPCODE_ADD, addr, *base, PIS_OPERAND_IMM(offset, PIS_SIZE_4))
    );

    *calculated_addr = addr;

cleanup:
    return err;
}

static err_t insn_decode_load_store_addr(ctx_t* ctx, pis_op_t* addr) {
    err_t err = SUCCESS;

    pis_op_t base = reg_get_operand(insn_field_rs(ctx->insn), REG_ACCESS_KIND_READ);
    u32 offset = insn_field_imm_sext(ctx->insn);

    CHECK_RETHROW(calc_load_store_addr(ctx, &base, offset, addr));

cleanup:
    return err;
}

static err_t do_load_ext(ctx_t* ctx, pis_size_t load_size, pis_opcode_t extend_opcode) {
    err_t err = SUCCESS;

    pis_op_t rt = reg_get_operand(insn_field_rt(ctx->insn), REG_ACCESS_KIND_WRITE);

    pis_op_t addr = {};
    CHECK_RETHROW(insn_decode_load_store_addr(ctx, &addr));

    switch (load_size) {
        case PIS_SIZE_1:
        case PIS_SIZE_2: {
            pis_op_t loaded = TMP_ALLOC(&ctx->tmp_allocator, load_size);
            PIS_EMIT(&ctx->args->result, PIS_INSN2(PIS_OPCODE_LOAD, loaded, addr));

            PIS_EMIT(&ctx->args->result, PIS_INSN2(extend_opcode, rt, loaded));
            break;
        }
        case PIS_SIZE_4:
            PIS_EMIT(&ctx->args->result, PIS_INSN2(PIS_OPCODE_LOAD, rt, addr));
            break;
        default:
            UNREACHABLE();
    }

cleanup:
    return err;
}

static err_t do_store_trunc(ctx_t* ctx, pis_size_t store_size) {
    err_t err = SUCCESS;

    pis_op_t rt = reg_get_operand(insn_field_rt(ctx->insn), REG_ACCESS_KIND_READ);

    pis_op_t addr = {};
    CHECK_RETHROW(insn_decode_load_store_addr(ctx, &addr));

    switch (store_size) {
        case PIS_SIZE_1:
        case PIS_SIZE_2: {
            pis_op_t partial = TMP_ALLOC(&ctx->tmp_allocator, store_size);
            PIS_EMIT(&ctx->args->result, PIS_INSN2(PIS_OPCODE_GET_LOW_BITS, partial, rt));

            PIS_EMIT(&ctx->args->result, PIS_INSN2(PIS_OPCODE_STORE, addr, partial));
            break;
        }
        case PIS_SIZE_4:
            PIS_EMIT(&ctx->args->result, PIS_INSN2(PIS_OPCODE_STORE, addr, rt));
            break;
        default:
            UNREACHABLE();
    }

cleanup:
    return err;
}

static err_t opcode_handler_20(ctx_t* ctx) {
    err_t err = SUCCESS;

    // opcode 0x20 is LB

    CHECK_RETHROW(do_load_ext(ctx, PIS_SIZE_1, PIS_OPCODE_SIGN_EXTEND));

cleanup:
    return err;
}

static err_t opcode_handler_21(ctx_t* ctx) {
    err_t err = SUCCESS;

    // opcode 0x20 is LH

    CHECK_RETHROW(do_load_ext(ctx, PIS_SIZE_2, PIS_OPCODE_SIGN_EXTEND));

cleanup:
    return err;
}

typedef enum {
    UNALIGNED_MEM_ACCESS_PART_LEFT,
    UNALIGNED_MEM_ACCESS_PART_RIGHT,
} unaligned_mem_access_part_t;

typedef enum {
    UNALIGNED_MEM_ACCESS_KIND_STORE,
    UNALIGNED_MEM_ACCESS_KIND_LOAD,
} unaligned_mem_access_kind_t;

static err_t do_load_store_unaligned(
    ctx_t* ctx, unaligned_mem_access_kind_t mem_access_kind, unaligned_mem_access_part_t part
) {
    err_t err = SUCCESS;

    reg_access_kind_t rt_access_kind;
    switch (mem_access_kind) {
        case UNALIGNED_MEM_ACCESS_KIND_LOAD:
            // on load, we load a value from memory into `rt`, so this is a write to `rt`.
            rt_access_kind = REG_ACCESS_KIND_WRITE;
            break;
        case UNALIGNED_MEM_ACCESS_KIND_STORE:
            // on store, we store the value from `rt` into memory, so this is a read from `rt`.
            rt_access_kind = REG_ACCESS_KIND_READ;
            break;
        default:
            UNREACHABLE();
    }
    pis_op_t rt = reg_get_operand(insn_field_rt(ctx->insn), rt_access_kind);

    pis_op_t addr = {};
    CHECK_RETHROW(insn_decode_load_store_addr(ctx, &addr));

    pis_op_t aligned_addr = TMP_ALLOC(&ctx->tmp_allocator, PIS_SIZE_4);
    PIS_EMIT(
        &ctx->args->result,
        PIS_INSN3(PIS_OPCODE_AND, aligned_addr, addr, PIS_OPERAND_IMM(0xfffffffc, PIS_SIZE_4))
    );

    pis_op_t offset_in_word = TMP_ALLOC(&ctx->tmp_allocator, PIS_SIZE_4);
    PIS_EMIT(
        &ctx->args->result,
        PIS_INSN3(PIS_OPCODE_AND, offset_in_word, addr, PIS_OPERAND_IMM(0x3, PIS_SIZE_4))
    );

    pis_op_t bit_offset_in_word = TMP_ALLOC(&ctx->tmp_allocator, PIS_SIZE_4);
    PIS_EMIT(
        &ctx->args->result,
        PIS_INSN3(
            PIS_OPCODE_UNSIGNED_MUL,
            bit_offset_in_word,
            offset_in_word,
            PIS_OPERAND_IMM(8, PIS_SIZE_4)
        )
    );

    pis_op_t inverse_bit_offset_in_word = TMP_ALLOC(&ctx->tmp_allocator, PIS_SIZE_4);
    PIS_EMIT(
        &ctx->args->result,
        PIS_INSN3(
            PIS_OPCODE_SUB,
            inverse_bit_offset_in_word,
            PIS_OPERAND_IMM(32, PIS_SIZE_4),
            bit_offset_in_word
        )
    );

    pis_op_t aligned_mem_val = TMP_ALLOC(&ctx->tmp_allocator, PIS_SIZE_4);
    PIS_EMIT(&ctx->args->result, PIS_INSN2(PIS_OPCODE_LOAD, aligned_mem_val, aligned_addr));

    // decide which value we should use as the original value of the final value, and which value we
    // want to use as the "added bits" to the final value.
    pis_op_t orig_val_to_use;
    pis_op_t added_val_to_use;
    switch (mem_access_kind) {
        case UNALIGNED_MEM_ACCESS_KIND_STORE:
            // if this is a store to memory, use the original memory value as the orig value, and
            // add the register value to it.
            orig_val_to_use = aligned_mem_val;
            added_val_to_use = rt;
            break;
        case UNALIGNED_MEM_ACCESS_KIND_LOAD:
            // if this is a load from memory, use the original reg value as the orig value, and add
            // the memory value to it.
            orig_val_to_use = rt;
            added_val_to_use = aligned_mem_val;
            break;
    }

    // decide whether we want to use "regular" or "inverted" shift amounts
    bool use_inverse_shift_amounts = false;
    // inverse the shift amounts if little endian
    use_inverse_shift_amounts ^= (ctx->cpuinfo->endianness == PIS_ENDIANNESS_LITTLE);
    // inverse the shift amounts if using a "right" access, which is access to the least significant
    // bytes.
    use_inverse_shift_amounts ^= (part == UNALIGNED_MEM_ACCESS_PART_RIGHT);

    // choose the actual shift amount values
    pis_op_t added_val_shift_amount;
    pis_op_t orig_val_mask_shift_amount;
    if (use_inverse_shift_amounts) {
        added_val_shift_amount = inverse_bit_offset_in_word;
        orig_val_mask_shift_amount = bit_offset_in_word;
    } else {
        added_val_shift_amount = bit_offset_in_word;
        orig_val_mask_shift_amount = inverse_bit_offset_in_word;
    }

    // decide which opcodes we should use for creating masks for each of the values
    pis_opcode_t added_val_shift_opcode;
    pis_opcode_t orig_val_mask_shift_opcode;
    switch (part) {
        case UNALIGNED_MEM_ACCESS_PART_LEFT:
            added_val_shift_opcode = PIS_OPCODE_SHIFT_LEFT;
            orig_val_mask_shift_opcode = PIS_OPCODE_SHIFT_RIGHT;
            break;
        case UNALIGNED_MEM_ACCESS_PART_RIGHT:
            added_val_shift_opcode = PIS_OPCODE_SHIFT_RIGHT;
            orig_val_mask_shift_opcode = PIS_OPCODE_SHIFT_LEFT;
            break;
        default:
            UNREACHABLE();
    }

    pis_op_t orig_val_mask = TMP_ALLOC(&ctx->tmp_allocator, PIS_SIZE_4);
    PIS_EMIT(
        &ctx->args->result,
        PIS_INSN3(
            orig_val_mask_shift_opcode,
            orig_val_mask,
            PIS_OPERAND_IMM(0xffffffff, PIS_SIZE_4),
            orig_val_mask_shift_amount
        )
    );

    pis_op_t added_val_shifted = TMP_ALLOC(&ctx->tmp_allocator, PIS_SIZE_4);
    PIS_EMIT(
        &ctx->args->result,
        PIS_INSN3(
            added_val_shift_opcode,
            added_val_shifted,
            added_val_to_use,
            added_val_shift_amount
        )
    );

    pis_op_t masked_orig_val = TMP_ALLOC(&ctx->tmp_allocator, PIS_SIZE_4);
    PIS_EMIT(
        &ctx->args->result,
        PIS_INSN3(PIS_OPCODE_AND, masked_orig_val, orig_val_to_use, orig_val_mask)
    );

    pis_op_t final_val = TMP_ALLOC(&ctx->tmp_allocator, PIS_SIZE_4);
    PIS_EMIT(
        &ctx->args->result,
        PIS_INSN3(PIS_OPCODE_OR, final_val, masked_orig_val, added_val_shifted)
    );

    // write-back the final value
    switch (mem_access_kind) {
        case UNALIGNED_MEM_ACCESS_KIND_STORE:
            // store it to memory
            PIS_EMIT(&ctx->args->result, PIS_INSN2(PIS_OPCODE_STORE, aligned_addr, final_val));
            break;
        case UNALIGNED_MEM_ACCESS_KIND_LOAD:
            // load it into the register
            PIS_EMIT(&ctx->args->result, PIS_INSN2(PIS_OPCODE_MOVE, rt, final_val));
            break;
    }

cleanup:
    return err;
}


static err_t opcode_handler_22(ctx_t* ctx) {
    err_t err = SUCCESS;

    // opcode 0x22 is LWL

    CHECK_RETHROW(
        do_load_store_unaligned(ctx, UNALIGNED_MEM_ACCESS_KIND_LOAD, UNALIGNED_MEM_ACCESS_PART_LEFT)
    );

cleanup:
    return err;
}

static err_t opcode_handler_23(ctx_t* ctx) {
    err_t err = SUCCESS;

    // opcode 0x23 is LW

    CHECK_RETHROW(do_load_ext(ctx, PIS_SIZE_4, PIS_OPCODE_ZERO_EXTEND));

cleanup:
    return err;
}

static err_t opcode_handler_24(ctx_t* ctx) {
    err_t err = SUCCESS;

    // opcode 0x24 is LBU

    CHECK_RETHROW(do_load_ext(ctx, PIS_SIZE_1, PIS_OPCODE_ZERO_EXTEND));

cleanup:
    return err;
}

static err_t opcode_handler_25(ctx_t* ctx) {
    err_t err = SUCCESS;

    // opcode 0x25 is LHU

    CHECK_RETHROW(do_load_ext(ctx, PIS_SIZE_2, PIS_OPCODE_ZERO_EXTEND));

cleanup:
    return err;
}

static err_t opcode_handler_26(ctx_t* ctx) {
    err_t err = SUCCESS;

    // opcode 0x26 is LWR

    CHECK_RETHROW(do_load_store_unaligned(
        ctx,
        UNALIGNED_MEM_ACCESS_KIND_LOAD,
        UNALIGNED_MEM_ACCESS_PART_RIGHT
    ));

cleanup:
    return err;
}


static err_t opcode_handler_28(ctx_t* ctx) {
    err_t err = SUCCESS;

    // opcode 0x28 is SB

    CHECK_RETHROW(do_store_trunc(ctx, PIS_SIZE_1));

cleanup:
    return err;
}

static err_t opcode_handler_29(ctx_t* ctx) {
    err_t err = SUCCESS;

    // opcode 0x29 is SH

    CHECK_RETHROW(do_store_trunc(ctx, PIS_SIZE_2));

cleanup:
    return err;
}

static err_t opcode_handler_2a(ctx_t* ctx) {
    err_t err = SUCCESS;

    // opcode 0x2a is SWL

    CHECK_RETHROW(do_load_store_unaligned(
        ctx,
        UNALIGNED_MEM_ACCESS_KIND_STORE,
        UNALIGNED_MEM_ACCESS_PART_LEFT
    ));

cleanup:
    return err;
}

static err_t opcode_handler_2b(ctx_t* ctx) {
    err_t err = SUCCESS;

    // opcode 0x2b is SW

    CHECK_RETHROW(do_store_trunc(ctx, PIS_SIZE_4));

cleanup:
    return err;
}

static err_t opcode_handler_2e(ctx_t* ctx) {
    err_t err = SUCCESS;

    // opcode 0x2e is SWR

    CHECK_RETHROW(do_load_store_unaligned(
        ctx,
        UNALIGNED_MEM_ACCESS_KIND_STORE,
        UNALIGNED_MEM_ACCESS_PART_RIGHT
    ));

cleanup:
    return err;
}

static const opcode_handler_t opcode_handlers_table[MIPS_MAX_OPCODE_VALUE + 1] = {
    [0x00] = opcode_handler_00, [0x01] = opcode_handler_01, [0x02] = opcode_handler_02,
    [0x03] = opcode_handler_03, [0x04] = opcode_handler_04, [0x05] = opcode_handler_05,
    [0x06] = opcode_handler_06, [0x07] = opcode_handler_07, [0x08] = opcode_handler_08,
    [0x09] = opcode_handler_09, [0x0a] = opcode_handler_0a, [0x0b] = opcode_handler_0b,
    [0x0c] = opcode_handler_0c, [0x0d] = opcode_handler_0d, [0x0e] = opcode_handler_0e,
    [0x0f] = opcode_handler_0f, [0x1c] = opcode_handler_1c, [0x20] = opcode_handler_20,
    [0x21] = opcode_handler_21, [0x22] = opcode_handler_22, [0x23] = opcode_handler_23,
    [0x24] = opcode_handler_24, [0x25] = opcode_handler_25, [0x26] = opcode_handler_26,
    [0x28] = opcode_handler_28, [0x29] = opcode_handler_29, [0x2a] = opcode_handler_2a,
    [0x2b] = opcode_handler_2b, [0x2e] = opcode_handler_2e,
};

err_t pis_mips_lift(pis_lift_args_t* args, const pis_mips_cpuinfo_t* cpuinfo) {
    err_t err = SUCCESS;

    size_t start_index = cursor_index(&args->machine_code);

    CHECK(args->machine_code_addr % 4 == 0);

    u32 insn = 0;
    CHECK_RETHROW(cursor_next_4(&args->machine_code, &insn, cpuinfo->endianness));

    ctx_t ctx = {
        .args = args,
        .cpuinfo = cpuinfo,
        .tmp_allocator = TMP_ALLOCATOR_INIT,
        .is_in_delay_slot = false,
        .insn = insn,
    };

    CHECK_RETHROW(lift(&ctx));

    args->result.machine_insn_len = cursor_index(&args->machine_code) - start_index;

cleanup:
    return err;
}

err_t pis_lifter_mipsbe32r1(pis_lift_args_t* args) {
    err_t err = SUCCESS;
    pis_mips_cpuinfo_t cpuinfo = {
        .endianness = PIS_ENDIANNESS_BIG,
        .rev = MIPS_REVISION_1,
    };
    CHECK_RETHROW(pis_mips_lift(args, &cpuinfo));
cleanup:
    return err;
}

err_t pis_lifter_mipsel32r1(pis_lift_args_t* args) {
    err_t err = SUCCESS;
    pis_mips_cpuinfo_t cpuinfo = {
        .endianness = PIS_ENDIANNESS_LITTLE,
        .rev = MIPS_REVISION_1,
    };
    CHECK_RETHROW(pis_mips_lift(args, &cpuinfo));
cleanup:
    return err;
}

const pis_arch_def_t pis_arch_def_mipsbe32r1 = {
    .lifter = pis_lifter_mipsbe32r1,
    .endianness = PIS_ENDIANNESS_BIG,
    .return_value = &MIPS_REG_V0,
    .params =
        {
            &MIPS_REG_A0,
            &MIPS_REG_A1,
            &MIPS_REG_A2,
        },
};

const pis_arch_def_t pis_arch_def_mipsel32r1 = {
    .lifter = pis_lifter_mipsel32r1,
    .endianness = PIS_ENDIANNESS_LITTLE,
    .return_value = &MIPS_REG_V0,
    .params =
        {
            &MIPS_REG_A0,
            &MIPS_REG_A1,
            &MIPS_REG_A2,
        },
};
