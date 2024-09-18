#include "ctx.h"
#include "arch/x86/common.h"
#include "arch/x86/modrm.h"
#include "errors.h"
#include "except.h"
#include "lift_ctx.h"
#include "pis.h"
#include "prefixes.h"
#include "regs.h"

static err_t post_prefixes_lift(const post_prefixes_ctx_t* ctx) {
    err_t err = SUCCESS;

    u8 first_opcode_byte = LIFT_CTX_CUR1_ADVANCE(ctx->lift_ctx);

    if ((first_opcode_byte & (~0b111)) == 0x50) {
        // push <reg> instruction
        u8 reg_encoding = first_opcode_byte & 0b111;
        if (ctx->prefixes->rex.is_present) {
            // the REX.B bit is an extensions to the register
            reg_encoding |= ctx->prefixes->rex.b << 3;
        }
        reg_t reg = (reg_t) {.encoding = reg_encoding};

        pis_operand_size_t operand_size = ctx->operand_sizes.insn_default_64_bit;
        pis_operand_t sp = ctx->lift_ctx->sp;
        u64 operand_size_bytes = pis_operand_size_to_bytes(operand_size);

        LIFT_CTX_EMIT(
            ctx->lift_ctx,
            PIS_INSN(PIS_OPCODE_ADD, sp, PIS_OPERAND_CONST_NEG(operand_size_bytes, sp.size))
        );
        LIFT_CTX_EMIT(
            ctx->lift_ctx,
            PIS_INSN(PIS_OPCODE_STORE, sp, reg_get_operand(reg, operand_size, ctx->prefixes))
        );
    } else if (first_opcode_byte == 0x89) {
        // move r/m, r instruction
        modrm_operands_t modrm_operands = {};
        CHECK_RETHROW(modrm_fetch_and_process(ctx, &modrm_operands));
        pis_opcode_t opcode =
            modrm_operands.is_rm_operand_memory ? PIS_OPCODE_STORE : PIS_OPCODE_MOVE;
        LIFT_CTX_EMIT(
            ctx->lift_ctx,
            PIS_INSN(opcode, modrm_operands.rm_operand, modrm_operands.reg_operand)
        );
    } else {
        CHECK_FAIL_TRACE_CODE(
            PIS_ERR_UNSUPPORTED_INSN,
            "unsupported first opcode byte: 0x%x",
            first_opcode_byte
        );
    }

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
        .addr_size = get_effective_addr_size(ctx->pis_x86_ctx->cpumode, &prefixes),
        .operand_sizes =
            {
                .insn_default_64_bit =
                    get_effective_operand_size(ctx->pis_x86_ctx->cpumode, &prefixes, true),
                .insn_default_not_64_bit =
                    get_effective_operand_size(ctx->pis_x86_ctx->cpumode, &prefixes, false),
            },
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
        .stack_addr_size = get_effective_stack_addr_size(ctx->cpumode),
        .sp = get_sp_operand(ctx->cpumode),
    };
    CHECK_RETHROW(lift(&lift_ctx));

cleanup:
    return err;
}
