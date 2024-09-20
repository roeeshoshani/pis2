#pragma once

#include "ctx.h"
#include "except.h"
#include "pis.h"

#define LIFT_CTX_CUR1(LIFT_CTX)                                                                    \
    ({                                                                                             \
        u8 ___cur = 0;                                                                             \
        CHECK_RETHROW(lift_ctx_cur1(LIFT_CTX, &___cur));                                           \
        ___cur;                                                                                    \
    })

#define LIFT_CTX_CUR1_ADVANCE(LIFT_CTX)                                                            \
    ({                                                                                             \
        u8 ___cur = 0;                                                                             \
        CHECK_RETHROW(lift_ctx_cur1(LIFT_CTX, &___cur));                                           \
        CHECK_RETHROW(lift_ctx_advance(LIFT_CTX, 1));                                              \
        ___cur;                                                                                    \
    })

#define LIFT_CTX_CUR2(LIFT_CTX)                                                                    \
    ({                                                                                             \
        u16 ___cur = 0;                                                                            \
        CHECK_RETHROW(lift_ctx_cur2(LIFT_CTX, &___cur));                                           \
        ___cur;                                                                                    \
    })

#define LIFT_CTX_CUR2_ADVANCE(LIFT_CTX)                                                            \
    ({                                                                                             \
        u16 ___cur = 0;                                                                            \
        CHECK_RETHROW(lift_ctx_cur2(LIFT_CTX, &___cur));                                           \
        CHECK_RETHROW(lift_ctx_advance(LIFT_CTX, 2));                                              \
        ___cur;                                                                                    \
    })

#define LIFT_CTX_CUR4(LIFT_CTX)                                                                    \
    ({                                                                                             \
        u32 ___cur = 0;                                                                            \
        CHECK_RETHROW(lift_ctx_cur4(LIFT_CTX, &___cur));                                           \
        ___cur;                                                                                    \
    })

#define LIFT_CTX_CUR4_ADVANCE(LIFT_CTX)                                                            \
    ({                                                                                             \
        u32 ___cur = 0;                                                                            \
        CHECK_RETHROW(lift_ctx_cur4(LIFT_CTX, &___cur));                                           \
        CHECK_RETHROW(lift_ctx_advance(LIFT_CTX, 4));                                              \
        ___cur;                                                                                    \
    })

#define LIFT_CTX_ADVANCE1(LIFT_CTX) CHECK_RETHROW(lift_ctx_advance(LIFT_CTX, 1))
#define LIFT_CTX_ADVANCE2(LIFT_CTX) CHECK_RETHROW(lift_ctx_advance(LIFT_CTX, 2))
#define LIFT_CTX_ADVANCE4(LIFT_CTX) CHECK_RETHROW(lift_ctx_advance(LIFT_CTX, 4))

#define LIFT_CTX_EMIT(LIFT_CTX, INSN) PIS_LIFT_RESULT_EMIT((LIFT_CTX)->result, INSN)

typedef struct {
    const pis_x86_ctx_t* pis_x86_ctx;
    const u8* cur;
    const u8* end;
    pis_lift_result_t* result;
    pis_operand_size_t stack_addr_size;
    pis_operand_t sp;
} lift_ctx_t;

/// have we reached the end of the buffer?
bool lift_ctx_eof(lift_ctx_t* ctx);

/// advances the context by the given amount of bytes.
err_t lift_ctx_advance(lift_ctx_t* ctx, u32 amount);

/// returns the current byte of the context.
err_t lift_ctx_cur1(lift_ctx_t* ctx, u8* cur_byte);

/// returns the current word of the context.
err_t lift_ctx_cur2(lift_ctx_t* ctx, u16* cur_word);

/// returns the current double word of the context.
err_t lift_ctx_cur4(lift_ctx_t* ctx, u32* cur_dword);
