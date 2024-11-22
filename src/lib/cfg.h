#pragma once

#include "pis.h"
#include "types.h"

#define PIS_CFG_MAX_INSNS 8192
#define PIS_CFG_MAX_UNITS 2048
#define PIS_CFG_MAX_BLOCKS 512

#define PIS_CFG_UNIT_MAX_INSNS PIS_LIFT_MAX_INSNS_AMOUNT

#define PIS_CFG_BLOCK_MAX_UNITS 512

/// an insn identifier. this is basically an index into the insn storage of the cfg.
typedef struct {
    u16 index;
} pis_cfg_insn_id_t;

/// represents a single CFG "unit". a unit corresponds to a single machine instruction in the
/// original machine code.
typedef struct {
    /// the address of the original machine instruction.
    u64 addr;

    /// the id of the first instruction of the sequence of pis instruction that belongs to this unit.
    pis_cfg_insn_id_t first_insn_id;

    /// the amount of pis instructions in this unit.
    u8 insns_amount;
} pis_cfg_unit_t;

/// a unit identifier. this is basically an index into the unit storage of the cfg.
typedef struct {
    u16 index;
} pis_cfg_unit_id_t;

/// represents a single CFG "block". a block is a collection of units which ends with some control flow operation, and can be pointed
/// to by other blocks.
typedef struct {
    /// the id of the first unit of the sequence of units that belongs to this block.
    pis_cfg_unit_id_t first_unit_id;

    /// the amount of units in this block.
    u16 units_amount;
} pis_cfg_block_t;

typedef struct {
    pis_insn_t insn_storage[PIS_CFG_MAX_INSNS];
    size_t insns_amount;

    pis_cfg_unit_t unit_storage[PIS_CFG_MAX_UNITS];
    size_t units_amount;

    pis_cfg_block_t blocks[PIS_CFG_MAX_BLOCKS];
    size_t blocks_amount;
} pis_cfg_t;

void pis_cfg_init(pis_cfg_t* cfg);
