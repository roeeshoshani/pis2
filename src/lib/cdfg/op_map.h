#pragma once

#include "../size.h"
#include "../types.h"
#include "../utils.h"
#include "../space.h"
#include "../except.h"

#define CDFG_OP_MAP_MAX_SLOTS (1024)

typedef enum {
    CDFG_OP_MAP_SIZE_INVALID = 0,
    CDFG_OP_MAP_SIZE_1 = PIS_SIZE_1,
    CDFG_OP_MAP_SIZE_2 = PIS_SIZE_2,
    CDFG_OP_MAP_SIZE_4 = PIS_SIZE_4,
    CDFG_OP_MAP_SIZE_8 = PIS_SIZE_8,
} PACKED cdfg_op_map_size_t;

/// a slot in the operand map. represents a single operand region that is used in the operand space.
typedef struct {
    /// the offset of the region inside the operand space.
    pis_off_t offset;

    /// the size of the region inside the operand space.
    cdfg_op_map_size_t size;
} PACKED cdfg_op_map_slot_t;

/// a map of all accessed operands throughout a piece of code.
typedef struct {
    cdfg_op_map_slot_t slots[CDFG_OP_MAP_MAX_SLOTS];
    size_t used_slots_amount;
} cdfg_op_map_t;

void cdfg_op_map_reset(cdfg_op_map_t* map);

/// updates the operands map according to an access to some operand in it.
err_t cdfg_op_map_update(cdfg_op_map_t* map, pis_region_t accessed_region);
