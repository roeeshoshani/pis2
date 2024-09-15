#pragma once

#include "ctx.h"
#include "except.h"
#include "pis.h"

#define LIFT_CTX_CUR(LIFT_CTX)                                                                     \
    ({                                                                                             \
        u8 ___cur = 0;                                                                             \
        CHECK_RETHROW(lift_ctx_cur(LIFT_CTX, &___cur));                                            \
        ___cur;                                                                                    \
    })

#define LIFT_CTX_ADVANCE(LIFT_CTX) CHECK_RETHROW(lift_ctx_advance(LIFT_CTX))

#define LIFT_CTX_EMIT(LIFT_CTX, INSN) PIS_LIFT_RESULT_EMIT((LIFT_CTX)->result, INSN)

typedef struct {
    const pis_x86_ctx_t* pis_x86_ctx;
    const u8* cur;
    const u8* end;
    pis_lift_result_t* result;
} lift_ctx_t;

/// have we reached the end of the buffer?
bool lift_ctx_eof(lift_ctx_t* ctx);

/// advances the context by 1 byte.
err_t lift_ctx_advance(lift_ctx_t* ctx);

/// returns the current byte of the context.
err_t lift_ctx_cur(lift_ctx_t* ctx, u8* cur_byte);

pis_operand_size_t lift_ctx_get_operand_size(lift_ctx_t* ctx);
