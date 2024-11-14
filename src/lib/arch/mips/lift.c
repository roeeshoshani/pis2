#include "lift.h"
#include "ctx.h"
#include "insn_fields.h"
#include "regs.h"

#define INSN_SIZE (sizeof(u32))

typedef err_t (*opcode_handler_t)(ctx_t* ctx);

static const opcode_handler_t opcode_handlers_table[MIPS_MAX_OPCODE_VALUE + 1];

static pis_operand_t reg_get_operand(u8 reg_encoding) {
    return PIS_OPERAND_REG(reg_encoding * 4, PIS_OPERAND_SIZE_4);
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

static err_t opcode_handler_00(ctx_t* ctx) {
    err_t err = SUCCESS;

    // opcode 0x00 is the SPECIAL opcode, which is further decoded by the function field
    u8 function = insn_field_function(ctx->insn);

    UNUSED(function);

    TODO();

cleanup:
    return err;
}

static err_t opcode_handler_01(ctx_t* ctx) {
    err_t err = SUCCESS;

    // opcode 0x01 is the REGIMM opcode, which is further decoded by the rt field
    u8 rt = insn_field_rt(ctx->insn);

    UNUSED(rt);

    TODO();

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

static pis_operand_t calc_pc_region_branch_target(ctx_t* ctx) {
    return PIS_OPERAND_RAM(calc_pc_region_branch_target_addr(ctx), PIS_OPERAND_SIZE_1);
}

static u32 calc_pc_rel_branch_target_addr(ctx_t* ctx) {
    u16 off = insn_field_offset(ctx->insn);
    u32 sign_extended_off = (u32) (i32) (i16) off;
    return delay_slot_insn_addr(ctx) + (sign_extended_off << 2);
}

static pis_operand_t calc_pc_rel_branch_target(ctx_t* ctx) {
    return PIS_OPERAND_RAM(calc_pc_rel_branch_target_addr(ctx), PIS_OPERAND_SIZE_1);
}

static u32 calc_branch_ret_addr(ctx_t* ctx) {
    return ctx->args->machine_code_addr + 2 * INSN_SIZE;
}

static pis_operand_t calc_branch_ret_addr_op(ctx_t* ctx) {
    return PIS_OPERAND_CONST(calc_branch_ret_addr(ctx), PIS_OPERAND_SIZE_4);
}

static err_t do_jmp(ctx_t* ctx) {
    err_t err = SUCCESS;

    pis_operand_t target = calc_pc_region_branch_target(ctx);

    // run the delay slot instruction
    CHECK_RETHROW(lift_delay_slot_insn(ctx));

    PIS_EMIT(&ctx->args->result, PIS_INSN1(PIS_OPCODE_JMP, target));

cleanup:
    return err;
}

static err_t opcode_handler_02(ctx_t* ctx) {
    err_t err = SUCCESS;

    // opcode 0x02 is J

    CHECK_RETHROW(do_jmp(ctx));

cleanup:
    return err;
}

static err_t opcode_handler_03(ctx_t* ctx) {
    err_t err = SUCCESS;

    // opcode 0x03 is JAL

    pis_operand_t ret_addr_op = calc_branch_ret_addr_op(ctx);
    PIS_EMIT(&ctx->args->result, PIS_INSN2(PIS_OPCODE_MOVE, MIPS_REG_RA, ret_addr_op));

    CHECK_RETHROW(do_jmp(ctx));

cleanup:
    return err;
}

static err_t do_branch_cond(ctx_t* ctx, const pis_operand_t* cond) {
    err_t err = SUCCESS;

    pis_operand_t target = calc_pc_rel_branch_target(ctx);

    CHECK_RETHROW(lift_delay_slot_insn(ctx));

    PIS_EMIT(&ctx->args->result, PIS_INSN2(PIS_OPCODE_JMP_COND, *cond, target));

cleanup:
    return err;
}

static err_t opcode_handler_04(ctx_t* ctx) {
    err_t err = SUCCESS;

    // opcode 0x04 is BEQ

    pis_operand_t rs = reg_get_operand(insn_field_rs(ctx->insn));
    pis_operand_t rt = reg_get_operand(insn_field_rt(ctx->insn));

    pis_operand_t cond = TMP_ALLOC(&ctx->tmp_allocator, PIS_OPERAND_SIZE_1);
    PIS_EMIT(&ctx->args->result, PIS_INSN3(PIS_OPCODE_EQUALS, cond, rs, rt));

    CHECK_RETHROW(do_branch_cond(ctx, &cond));

cleanup:
    return err;
}

static err_t opcode_handler_05(ctx_t* ctx) {
    err_t err = SUCCESS;

    // opcode 0x05 is BNE

    pis_operand_t rs = reg_get_operand(insn_field_rs(ctx->insn));
    pis_operand_t rt = reg_get_operand(insn_field_rt(ctx->insn));

    pis_operand_t cond = TMP_ALLOC(&ctx->tmp_allocator, PIS_OPERAND_SIZE_1);
    PIS_EMIT(&ctx->args->result, PIS_INSN3(PIS_OPCODE_EQUALS, cond, rs, rt));
    PIS_EMIT(&ctx->args->result, PIS_INSN2(PIS_OPCODE_COND_NEGATE, cond, cond));

    CHECK_RETHROW(do_branch_cond(ctx, &cond));

cleanup:
    return err;
}

static err_t opcode_handler_06(ctx_t* ctx) {
    err_t err = SUCCESS;

    // opcode 0x06 is BLEZ

    pis_operand_t rs = reg_get_operand(insn_field_rs(ctx->insn));
    CHECK(insn_field_rt(ctx->insn) == 0);

    pis_operand_t cond = TMP_ALLOC(&ctx->tmp_allocator, PIS_OPERAND_SIZE_1);
    // TODO: how the fuck do i do >=???
    // PIS_EMIT(&ctx->args->result, PIS_INSN3(PIS_OPCODE_SIGNED_BORROW, cond, rs, rt));
    UNUSED(rs);

    CHECK_RETHROW(do_branch_cond(ctx, &cond));

cleanup:
    return err;
}

static const opcode_handler_t opcode_handlers_table[MIPS_MAX_OPCODE_VALUE + 1] = {
    opcode_handler_00,
    opcode_handler_01,
    opcode_handler_02,
    opcode_handler_03,
    opcode_handler_04,
    opcode_handler_05,
    opcode_handler_06,
};

err_t pis_mips_lift(pis_lift_args_t* args, const pis_mips_cpuinfo_t* cpuinfo) {
    err_t err = SUCCESS;

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

cleanup:
    return err;
}
