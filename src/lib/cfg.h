#pragma once

#include "pis.h"
#include "types.h"

#define PIS_CFG_MAX_UNITS 2048
#define PIS_CFG_MAX_BLOCKS 512
#define PIS_CFG_BLOCK_MAX_UNITS 512

/// represents a single CFG "unit". a unit corresponds to a single machine instruction in the
/// original machine code.
typedef struct {
    /// the address of the original machine instruction.
    u64 addr;

    /// the result of lifting the original machine instruction. this contains the lifted pis instructions and some more info.
    pis_lift_res_t lift_res;
} pis_cfg_unit_t;

/// a unit identifier. this is basically an index into the unit storage of the cfg.
typedef struct {
    /// the index of the unit in the cfg unit storage array. this is only 16-bits since the unit storage array is limited in size
    /// and making this smaller reduces our memory consumption.
    u16 index;
} pis_cfg_unit_id_t;

/// represents a single CFG "block". a block is a collection of units which ends with some control flow operation, and can be pointed
/// to by other blocks.
typedef struct {
    pis_cfg_unit_id_t unit_ids[PIS_CFG_BLOCK_MAX_UNITS];
} pis_cfg_block_t;

typedef struct {
    pis_cfg_unit_t unit_storage[PIS_CFG_MAX_UNITS];
    pis_cfg_block_t blocks[PIS_CFG_MAX_BLOCKS];
} pis_cfg_t;

void pis_cfg_init(pis_cfg_t* cfg);

void pis_cfg_init(pis_cfg_t* cfg);
