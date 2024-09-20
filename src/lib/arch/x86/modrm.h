#pragma once

#include "pis.h"
#include "prefixes.h"
#include "types.h"

typedef struct {
    u8 mod;
    u8 reg;
    u8 rm;
} modrm_t;

typedef struct {
    u8 scale;
    u8 index;
    u8 base;
} sib_t;

/// an operand representing the modrm r/m field.
typedef struct {
    /// is the r/m field a memory operand or a register operand.
    bool is_memory;

    /// an operand containting address of the r/m field if it is a memory operand, or the register operand if
    /// the r/m field is a register.
    pis_operand_t addr_or_reg;
} modrm_rm_operand_t;

typedef struct {
    modrm_rm_operand_t rm_operand;
    pis_operand_t reg_operand;
} modrm_operands_t;

modrm_t modrm_decode_byte(u8 modrm_byte);

sib_t sib_decode_byte(u8 sib_byte);

err_t modrm_fetch_and_process(const post_prefixes_ctx_t* ctx, modrm_operands_t* operands);
