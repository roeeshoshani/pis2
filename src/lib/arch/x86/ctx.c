#include "ctx.h"
#include "arch/x86/common.h"
#include "errors.h"
#include "except.h"
#include "lift_ctx.h"
#include "pis.h"
#include "prefixes.h"
#include "regs.h"

static pis_operand_size_t get_operand_size_for_push(const post_prefixes_ctx_t* ctx) {
    bool has_size_override =
        prefixes_contain_legacy_prefix(ctx->prefixes, LEGACY_PREFIX_OPERAND_SIZE_OVERRIDE);

    switch (ctx->lift_ctx->pis_x86_ctx->cpumode) {
    case PIS_X86_CPUMODE_16_BIT:
        return has_size_override ? PIS_OPERAND_SIZE_4 : PIS_OPERAND_SIZE_2;
    case PIS_X86_CPUMODE_32_BIT:
        return has_size_override ? PIS_OPERAND_SIZE_2 : PIS_OPERAND_SIZE_4;
    case PIS_X86_CPUMODE_64_BIT:
        return has_size_override ? PIS_OPERAND_SIZE_2 : PIS_OPERAND_SIZE_8;
    default:
        // unreachable
        return PIS_OPERAND_SIZE_1;
    }
}

static err_t lift_push_reg(const post_prefixes_ctx_t* ctx, reg_t reg) {
    err_t err = SUCCESS;

    pis_operand_size_t operand_size = get_operand_size_for_push(ctx);
    pis_operand_t sp = get_sp_operand(ctx);
    u64 operand_size_bytes = pis_operand_size_to_bytes(operand_size);

    LIFT_CTX_EMIT(
        ctx->lift_ctx,
        PIS_INSN(PIS_OPCODE_ADD, sp, PIS_OPERAND_CONST_NEG(operand_size_bytes, sp.size))
    );
    LIFT_CTX_EMIT(
        ctx->lift_ctx,
        PIS_INSN(PIS_OPCODE_STORE, sp, reg_get_operand(reg, operand_size, ctx->prefixes))
    );

cleanup:
    return err;
}

static err_t post_prefixes_lift(const post_prefixes_ctx_t* ctx) {
    err_t err = SUCCESS;

    u8 first_opcode_byte = LIFT_CTX_CUR(ctx->lift_ctx);

    if ((first_opcode_byte & (~0b111)) == 0x50) {
        u8 reg_encoding = first_opcode_byte & 0b111;
        if (ctx->prefixes->rex.is_present) {
            // the REX.B bit is an extensions to the register
            reg_encoding |= ctx->prefixes->rex.b << 3;
        }
        reg_t reg = (reg_t) {.encoding = reg_encoding};
        CHECK_RETHROW(lift_push_reg(ctx, reg));
        SUCCESS_CLEANUP();
    }

    CHECK_FAIL_TRACE_CODE(
        PIS_ERR_UNSUPPORTED_INSN,
        "unsupported first opcode byte: 0x%x",
        first_opcode_byte
    );

cleanup:
    return err;
}

static err_t lift(lift_ctx_t* ctx) {
    err_t err = SUCCESS;
    prefixes_t prefixes = {};

    CHECK_RETHROW(parse_prefixes(ctx, &prefixes));

    CHECK_RETHROW(post_prefixes_lift(&(post_prefixes_ctx_t) {
        .lift_ctx = ctx,
        .prefixes = &prefixes,
    }));

cleanup:
    return err;
}

err_t pis_x86_lift(
    const pis_x86_ctx_t* ctx,
    const u8* machine_code,
    size_t machine_code_len,
    pis_lift_result_t* result
) {
    err_t err = SUCCESS;

    CHECK_CODE(machine_code != NULL, PIS_ERR_NULL_ARG);
    CHECK_CODE(machine_code_len > 0, PIS_ERR_EARLY_EOF);

    lift_ctx_t lift_ctx = {
        .pis_x86_ctx = ctx,
        .cur = machine_code,
        .end = machine_code + machine_code_len,
        .result = result,
    };
    CHECK_RETHROW(lift(&lift_ctx));

cleanup:
    return err;
}
