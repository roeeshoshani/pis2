#include "lift_ctx.h"
#include "ctx.h"
#include "pis.h"

bool lift_ctx_eof(lift_ctx_t* ctx) {
    return ctx->cur >= ctx->end;
}

err_t lift_ctx_advance(lift_ctx_t* ctx) {
    err_t err = SUCCESS;
    CHECK_CODE(!lift_ctx_eof(ctx), PIS_ERR_EARLY_EOF);
    ctx->cur++;
cleanup:
    return err;
}

err_t lift_ctx_cur(lift_ctx_t* ctx, u8* cur_byte) {
    err_t err = SUCCESS;
    CHECK_CODE(!lift_ctx_eof(ctx), PIS_ERR_EARLY_EOF);
    *cur_byte = *ctx->cur;
cleanup:
    return err;
}

pis_operand_size_t lift_ctx_get_operand_size(lift_ctx_t* ctx) {
    switch (ctx->pis_x86_ctx->cpumode) {
    case PIS_X86_CPUMODE_16_BIT:
        return PIS_OPERAND_SIZE_1;
        break;
    case PIS_X86_CPUMODE_32_BIT:
        return PIS_OPERAND_SIZE_1;
        break;
    case PIS_X86_CPUMODE_64_BIT:
        return PIS_OPERAND_SIZE_1;
        break;
    default:
        return PIS_OPERAND_SIZE_1;
    }
}
