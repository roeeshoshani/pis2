#include "lift.h"
#include "ctx.h"
#include "insn_fields.h"

typedef err_t (*opcode_handler_t)(ctx_t* ctx);

static const opcode_handler_t opcode_handlers_table[MIPS_MAX_OPCODE_VALUE + 1];

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
    return ctx->args->machine_code_addr + sizeof(u32);
}

static err_t lift_delay_slot_insn(ctx_t* ctx) {
    err_t err = SUCCESS;

    // instructions in delay slot can't have delay slots
    CHECK(!ctx->is_in_delay_slot);

    // prepare context for lifting delay slot
    ctx->args->machine_code_addr += sizeof(u32);
    ctx->is_in_delay_slot = true;
    u32 orig_insn = ctx->insn;
    CHECK_RETHROW(cursor_next_4(&ctx->args->machine_code, &ctx->insn, ctx->cpuinfo->endianness));

    CHECK_RETHROW(lift(ctx));

    // restore context
    ctx->args->machine_code_addr -= sizeof(u32);
    ctx->is_in_delay_slot = false;
    ctx->insn = orig_insn;
cleanup:
    return err;
}

static err_t opcode_handler_02(ctx_t* ctx) {
    err_t err = SUCCESS;

    // opcode 0x02 is J
    u32 addr_upper_bits = delay_slot_insn_addr(ctx) & 0xf0000000;
    u32 addr_low_bits = insn_field_instr_index(ctx->insn) << 2;
    u32 target_addr = addr_upper_bits | addr_low_bits;

    // run the delay slot instruction
    CHECK_RETHROW(lift_delay_slot_insn(ctx));

    PIS_EMIT(
        &ctx->args->result,
        PIS_INSN1(PIS_OPCODE_JMP, PIS_OPERAND_RAM(target_addr, PIS_OPERAND_SIZE_1))
    );

cleanup:
    return err;
}

static const opcode_handler_t opcode_handlers_table[MIPS_MAX_OPCODE_VALUE + 1] = {
    opcode_handler_00,
    opcode_handler_01,
    opcode_handler_02,
};

err_t pis_mips_lift(pis_lift_args_t* args, const pis_mips_cpuinfo_t* cpuinfo) {
    err_t err = SUCCESS;

    u32 insn = 0;
    CHECK_RETHROW(cursor_next_4(&args->machine_code, &insn, cpuinfo->endianness));

    ctx_t ctx = {
        .args = args,
        .cpuinfo = cpuinfo,
        .is_in_delay_slot = false,
        .insn = insn,
    };

    CHECK_RETHROW(lift(&ctx));

cleanup:
    return err;
}
