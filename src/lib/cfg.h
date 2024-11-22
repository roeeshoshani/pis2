#pragma once

#include "lifter.h"
#include "pis.h"
#include "types.h"
#include <limits.h>

#define PIS_CFG_MAX_INSNS 8192
#define PIS_CFG_MAX_UNITS 2048
#define PIS_CFG_MAX_BLOCKS 512

#define PIS_CFG_UNIT_MAX_INSNS PIS_LIFT_MAX_INSNS_AMOUNT

#define PIS_CFG_BLOCK_MAX_UNITS 512

#define PIS_CFG_ITEM_ID_MAX (UINT16_MAX)
#define PIS_CFG_ITEM_ID_INVALID (PIS_CFG_ITEM_ID_MAX)

#define PIS_CFG_BUILDER_MAX_UNEXPLORED_PATHS (64)

typedef u16 pis_cfg_item_id_t;

/// represents a single CFG "unit". a unit corresponds to a single machine instruction in the
/// original machine code.
typedef struct {
    /// the address of the original machine instruction.
    u64 addr;

    /// the id of the first instruction of the sequence of pis instruction that belongs to this
    /// unit.
    pis_cfg_item_id_t first_insn_id;

    /// the amount of pis instructions in this unit.
    u8 insns_amount;
} pis_cfg_unit_t;

/// represents a single CFG "block". a block is a collection of units which ends with some control
/// flow operation, and can be pointed to by other blocks.
typedef struct {
    /// the id of the first unit of the sequence of units that belongs to this block.
    pis_cfg_item_id_t first_unit_id;

    /// the amount of units in this block.
    u16 units_amount;
} pis_cfg_block_t;

/// a CFG. it is basically just a collection of CFG blocks, but provides a centralized storage
/// location for all CFG objects.
typedef struct {
    pis_insn_t insn_storage[PIS_CFG_MAX_INSNS];
    size_t insns_amount;

    pis_cfg_unit_t unit_storage[PIS_CFG_MAX_UNITS];
    size_t units_amount;

    pis_cfg_block_t block_storage[PIS_CFG_MAX_BLOCKS];
    size_t blocks_amount;
} pis_cfg_t;

/// a path in the code that is currently unexplored when building a CFG.
typedef struct {
    /// the offset from the start of the machine code where the first instruction of this path is
    /// located.
    size_t start_offset;
} pis_cfg_unexplored_path_t;

typedef struct {
    /// the id of the block currently being built.
    pis_cfg_item_id_t cur_block_id;

    /// the lifter to use when building the CFG.
    pis_lifter_t lifter;

    /// the machine code to use when building the CFG.
    const u8* machine_code_start;
    size_t machine_code_len;
    u64 machine_code_start_addr;

    /// a queue of currently unexplored paths that should be explored in order to build the cfg.
    pis_cfg_unexplored_path_t unexplored_paths_queue[PIS_CFG_BUILDER_MAX_UNEXPLORED_PATHS];
    size_t unexplored_paths_amount;

    /// the built cfg.
    pis_cfg_t cfg;
} pis_cfg_builder_t;

void pis_cfg_reset(pis_cfg_t* cfg);

void pis_cfg_builder_init(
    pis_cfg_builder_t* builder,
    pis_lifter_t lifter,
    const u8* machine_code_start,
    size_t machine_code_len,
    u64 machine_code_start_addr
);

err_t build_cfg_wip(pis_cfg_builder_t* builder);
