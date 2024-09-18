#pragma once

#include "prefixes.h"
#include "types.h"

typedef struct {
    u8 mod;
    u8 reg;
    u8 rm;
} modrm_t;

typedef struct {
    pis_operand_t rm_operand;
    bool is_rm_operand_memory;
    pis_operand_t reg_operand;
} modrm_operands_t;

modrm_t modrm_decode_byte(u8 modrm_byte);

err_t modrm_fetch_and_process(const post_prefixes_ctx_t* ctx, modrm_operands_t* operands);
