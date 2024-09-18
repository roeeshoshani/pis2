#pragma once

#include "types.h"
#include "pis.h"

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

modrm_t decode_modrm_byte(u8 modrm_byte);
