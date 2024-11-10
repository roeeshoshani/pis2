#include "lift_ctx.h"
#include "../../errors.h"
#include "../../except.h"
#include "../../pis.h"
#include "ctx.h"
#include "prefixes.h"

err_t lift_ctx_new_tmp(lift_ctx_t* ctx, pis_operand_size_t size, pis_operand_t* new_tmp) {
    err_t err = SUCCESS;
    pis_operand_t result = PIS_OPERAND_TMP(ctx->cur_tmp_offset, size);

    u64 size_in_bytes = pis_operand_size_to_bytes(size);

    // make sure that we will not overflow
    CHECK_CODE(ctx->cur_tmp_offset < UINT64_MAX - size_in_bytes, PIS_ERR_TOO_MANY_TMPS);

    ctx->cur_tmp_offset += size_in_bytes;

    *new_tmp = result;
cleanup:
    return err;
}
