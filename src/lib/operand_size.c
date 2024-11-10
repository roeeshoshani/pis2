#include "operand_size.h"

u32 pis_operand_size_to_bytes(pis_operand_size_t operand_size) {
    return (u32) operand_size;
}

u32 pis_operand_size_to_bits(pis_operand_size_t operand_size) {
    return pis_operand_size_to_bytes(operand_size) * 8;
}

u64 pis_operand_size_max_unsigned_value(pis_operand_size_t operand_size) {
    u32 bits = pis_operand_size_to_bits(operand_size);
    if (bits == 64) {
        return UINT64_MAX;
    } else {
        return ((u64) 1 << bits) - 1;
    }
}
