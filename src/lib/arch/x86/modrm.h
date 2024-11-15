#pragma once

#include "../../pis.h"
#include "../../types.h"
#include "ctx.h"
#include "prefixes.h"

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

    /// an operand containting address of the r/m field if it is a memory operand, or the register
    /// operand if the r/m field is a register.
    pis_operand_t addr_or_reg;
} modrm_rm_operand_t;

typedef enum {
    MODRM_OPERAND_TYPE_REG,
    MODRM_OPERAND_TYPE_RM,
} modrm_operand_type_t;

typedef struct {
    modrm_operand_type_t type;
    union {
        modrm_rm_operand_t rm;
        pis_operand_t reg;
    };
} modrm_operand_t;

typedef struct {
    modrm_operand_t rm_operand;
    modrm_operand_t reg_operand;
    modrm_t modrm;
} modrm_operands_t;

modrm_t modrm_decode_byte(u8 modrm_byte);

sib_t sib_decode_byte(u8 sib_byte);

err_t modrm_decode_rm_operand(
    ctx_t* ctx,
    const modrm_t* modrm,
    pis_size_t operand_size,
    modrm_rm_operand_t* rm_operand
);

err_t modrm_fetch_and_process_with_operand_sizes(
    ctx_t* ctx, modrm_operands_t* operands, pis_size_t rm_size, pis_size_t reg_size
);

err_t modrm_rm_write(
    ctx_t* ctx, const modrm_rm_operand_t* rm_operand, const pis_operand_t* to_write
);

err_t modrm_rm_read(
    ctx_t* ctx, const pis_operand_t* read_into, const modrm_rm_operand_t* rm_operand
);

err_t modrm_operand_read(
    ctx_t* ctx, const pis_operand_t* read_into, const modrm_operand_t* operand
);

err_t modrm_operand_write(
    ctx_t* ctx, const modrm_operand_t* operand, const pis_operand_t* to_write
);
