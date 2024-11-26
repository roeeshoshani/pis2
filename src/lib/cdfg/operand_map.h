#pragma once

#include "../size.h"
#include "../types.h"
#include "../utils.h"

#define CDFG_OPERAND_MAP_MAX_SLOTS (1024)

typedef enum {
    CDFG_OPERAND_MAP_SIZE_INVALID = 0,
    CDFG_OPERAND_MAP_SIZE_1 = PIS_SIZE_1,
    CDFG_OPERAND_MAP_SIZE_2 = PIS_SIZE_2,
    CDFG_OPERAND_MAP_SIZE_4 = PIS_SIZE_4,
    CDFG_OPERAND_MAP_SIZE_8 = PIS_SIZE_8,
} PACKED cdfg_operand_map_size_t;

/// a slot in the operand map. represents a single operand region that is used in the operand space.
typedef struct {
    /// the offset of the region inside the operand space.
    u16 offset;

    /// the size of the region inside the operand space.
    cdfg_operand_map_size_t size;
} PACKED cdfg_operand_map_slot_t;

/// a map of all accessed operands in a piece of code.
typedef struct {
    // cdfg_operand_map_slot_t slots[]
} cdfg_operand_map_t;
