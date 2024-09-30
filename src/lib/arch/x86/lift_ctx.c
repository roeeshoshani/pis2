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
    *cur_word = (u16) ctx->cur[0] | ((u16) ctx->cur[1] << 8);
cleanup:
    return err;
}

err_t lift_ctx_cur4(lift_ctx_t* ctx, u32* cur_dword) {
    err_t err = SUCCESS;
    CHECK_CODE(ctx->cur + 3 < ctx->end, PIS_ERR_EARLY_EOF);
    *cur_dword = (u32) ctx->cur[0] | ((u32) ctx->cur[1] << 8) | ((u32) ctx->cur[2] << 16) |
                 ((u32) ctx->cur[3] << 24);
cleanup:
    return err;
}

err_t lift_ctx_cur8(lift_ctx_t* ctx, u64* cur_qword) {
    err_t err = SUCCESS;
    CHECK_CODE(ctx->cur + 7 < ctx->end, PIS_ERR_EARLY_EOF);
    *cur_qword = (u64) ctx->cur[0] | ((u64) ctx->cur[1] << 8) | ((u64) ctx->cur[2] << 16) |
                 ((u64) ctx->cur[3] << 24) | ((u64) ctx->cur[4] << 32) | ((u64) ctx->cur[5] << 40) |
                 ((u64) ctx->cur[6] << 48) | ((u64) ctx->cur[7] << 56);
cleanup:
    return err;
}

size_t lift_ctx_index(const lift_ctx_t* ctx) {
    return ctx->cur - ctx->start;
}
