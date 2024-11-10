#pragma once

#include "types.h"

typedef enum {
    /// 1 byte
    PIS_OPERAND_SIZE_1 = 1,
    /// 2 bytes
    PIS_OPERAND_SIZE_2 = 2,
    /// 4 bytes
    PIS_OPERAND_SIZE_4 = 4,
    /// 8 bytes
    PIS_OPERAND_SIZE_8 = 8,
} pis_operand_size_t;

u32 pis_operand_size_to_bytes(pis_operand_size_t operand_size);

u32 pis_operand_size_to_bits(pis_operand_size_t operand_size);

u64 pis_operand_size_max_unsigned_value(pis_operand_size_t operand_size);
