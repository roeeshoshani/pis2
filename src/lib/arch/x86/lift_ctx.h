#pragma once

#include "../../except.h"
#include "../../pis.h"
#include "ctx.h"

#define LIFT_CTX_EMIT(LIFT_CTX, INSN) PIS_LIFT_RESULT_EMIT((LIFT_CTX)->result, INSN)

#define LIFT_CTX_NEW_TMP(LIFT_CTX, SIZE)                                                           \
    ({                                                                                             \
        pis_operand_t ___tmp = {};                                                                 \
        CHECK_RETHROW(lift_ctx_new_tmp((LIFT_CTX), (SIZE), &___tmp));                              \
        ___tmp;                                                                                    \
    })

typedef struct {
    const pis_x86_ctx_t* pis_x86_ctx;
    cursor_t* machine_code;
    u64 machine_code_addr;
    u64 cur_tmp_offset;
    pis_lift_result_t* result;
    pis_operand_size_t stack_addr_size;
    pis_operand_t sp;
} lift_ctx_t;

/// returns a new unique temporary operand of the given size.
err_t lift_ctx_new_tmp(lift_ctx_t* ctx, pis_operand_size_t size, pis_operand_t* new_tmp);
