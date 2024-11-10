#pragma once

#include "except.h"
#include "pis.h"
#include "types.h"

#define TMP_ALLOCATOR_INIT                                                                         \
    { .cur_tmp_offset = 0 }

#define TMP_ALLOC(TMP_ALLOCATOR, SIZE)                                                             \
    ({                                                                                             \
        pis_operand_t ___op = {};                                                                  \
        CHECK_RETHROW(tmp_alloc(TMP_ALLOCATOR, SIZE, &___op));                                     \
        ___op;                                                                                     \
    })

typedef struct {
    u64 cur_tmp_offset;
} tmp_allocator_t;

err_t tmp_alloc(tmp_allocator_t* tmp_allocator, pis_operand_size_t size, pis_operand_t* new_tmp);
