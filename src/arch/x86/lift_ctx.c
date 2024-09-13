#include "lift_ctx.h"

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
