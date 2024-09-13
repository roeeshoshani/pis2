#include "ctx.h"
#include "errors.h"
#include "except.h"
#include "lift_ctx.h"
#include "pis.h"
#include "prefixes.h"
#include "utils.h"

typedef enum {
    REG_RAX,
    REG_RCX,
    REG_RDX,
    REG_RBX,
    REG_RSP_OR_AH,
    REG_RBP_OR_CH,
    REG_RSI_OR_DH,
    REG_RDI_OR_BH,
    REG_AMOUNT,
    REG_MAX = REG_AMOUNT - 1,
} reg_t;

static err_t lift_push_reg(lift_ctx_t* ctx, prefixes_t* prefixes, reg_t reg) {
    err_t err = SUCCESS;

    LIFT_CTX_EMIT(ctx, PIS_INSN(PIS_OPCODE_MOVE, PIS_OPERAND_REG(0, 8), PIS_OPERAND_REG(8, 8)));
    LIFT_CTX_EMIT(ctx, PIS_INSN(PIS_OPCODE_MOVE, PIS_OPERAND_REG(0, 8), PIS_OPERAND_REG(8, 8)));

    UNUSED(prefixes);
    UNUSED(reg);

cleanup:
    return err;
}

static err_t lift(lift_ctx_t* ctx) {
    err_t err = SUCCESS;
    prefixes_t prefixes = {};

    CHECK_RETHROW(parse_prefixes(ctx, &prefixes));
    u8 first_opcode_byte = LIFT_CTX_CUR(ctx);

    if (first_opcode_byte >= 0x50 && first_opcode_byte <= 0x50 + REG_MAX) {
        reg_t reg = (reg_t) (first_opcode_byte - 0x50);
        CHECK_RETHROW(lift_push_reg(ctx, &prefixes, reg));
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
