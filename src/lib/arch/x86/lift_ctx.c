#include "lift_ctx.h"
#include "ctx.h"
#include "except.h"
#include "pis.h"
#include "prefixes.h"

bool lift_ctx_eof(lift_ctx_t* ctx) {
    return ctx->cur >= ctx->end;
}

err_t lift_ctx_advance(lift_ctx_t* ctx, u32 amount) {
    err_t err = SUCCESS;
    CHECK_CODE(ctx->cur + amount <= ctx->end, PIS_ERR_EARLY_EOF);
    ctx->cur += amount;
cleanup:
    return err;
}

err_t lift_ctx_cur1(lift_ctx_t* ctx, u8* cur_byte) {
    err_t err = SUCCESS;
    CHECK_CODE(!lift_ctx_eof(ctx), PIS_ERR_EARLY_EOF);
    *cur_byte = *ctx->cur;
cleanup:
    return err;
}

err_t lift_ctx_cur2(lift_ctx_t* ctx, u16* cur_word) {
    err_t err = SUCCESS;
    CHECK_CODE(ctx->cur + 1 < ctx->end, PIS_ERR_EARLY_EOF);
    *cur_word = ctx->cur[0] | (ctx->cur[1] << 8);
cleanup:
    return err;
}

err_t lift_ctx_cur4(lift_ctx_t* ctx, u32* cur_dword) {
    err_t err = SUCCESS;
    CHECK_CODE(ctx->cur + 3 < ctx->end, PIS_ERR_EARLY_EOF);
    *cur_dword = ctx->cur[0] | (ctx->cur[1] << 8) | (ctx->cur[2] << 16) | (ctx->cur[3] << 24);
cleanup:
    return err;
}
