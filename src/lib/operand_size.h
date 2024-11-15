#pragma once

#include "types.h"

typedef enum {
    /// 1 byte
    PIS_SIZE_1 = 1,
    /// 2 bytes
    PIS_SIZE_2 = 2,
    /// 4 bytes
    PIS_SIZE_4 = 4,
    /// 8 bytes
    PIS_SIZE_8 = 8,
} pis_size_t;

u32 pis_size_to_bytes(pis_size_t operand_size);

u32 pis_size_to_bits(pis_size_t operand_size);

u64 pis_size_max_unsigned_value(pis_size_t operand_size);
