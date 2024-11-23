#pragma once

#include "lifter.h"
#include "pis.h"
#include "types.h"
#include <limits.h>

#define CFG_MAX_INSNS 4096
#define CFG_MAX_UNITS 1024
#define CFG_MAX_BLOCKS 256

#define CFG_ITEM_ID_MAX (UINT16_MAX)
#define CFG_ITEM_ID_INVALID (CFG_ITEM_ID_MAX)

#define CFG_BUILDER_MAX_UNEXPLORED_PATHS (64)

#define CFG_BLOCK_MAX_SUCCESSORS (2)

typedef u16 cfg_item_id_t;

/// represents a single CFG "unit". a unit corresponds to a single machine instruction in the
/// original machine code.
typedef struct {
    /// the address of the original machine instruction.
    u64 addr;

    /// the id of the first instruction of the sequence of pis instruction that belongs to this
    /// unit.
    cfg_item_id_t first_insn_id;

    /// the amount of pis instructions in this unit.
    u8 insns_amount;

    /// the length in bytes of the machine instruction that this unit represents.
    u8 machine_insn_len;
} __attribute__((packed)) cfg_unit_t;

/// represents a single CFG "block". a block is a collection of units which ends with some control
/// flow operation, and can be pointed to by other blocks.
typedef struct {
    /// the id of the first unit of the sequence of units that belongs to this block.
    cfg_item_id_t first_unit_id;

    /// the amount of units in this block.
    u16 units_amount;
} cfg_block_t;

/// a CFG. it is basically just a collection of CFG blocks, but provides a centralized storage
/// location for all CFG objects.
typedef struct {
    pis_insn_t insn_storage[CFG_MAX_INSNS];
    size_t insns_amount;

    cfg_unit_t unit_storage[CFG_MAX_UNITS];
    size_t units_amount;

    cfg_block_t block_storage[CFG_MAX_BLOCKS];
    size_t blocks_amount;
} cfg_t;

/// a path in the code that is currently unexplored when building a CFG.
typedef struct {
    /// the offset from the start of the machine code where the first instruction of this path is
    /// located.
    size_t start_offset;
} cfg_unexplored_path_t;

typedef struct {
    /// the id of the block currently being built.
    cfg_item_id_t cur_block_id;

    /// the lifter to use when building the CFG.
    pis_lifter_t lifter;

    /// the machine code to use when building the CFG.
    const u8* machine_code;
    size_t machine_code_len;
    u64 machine_code_start_addr;

    /// a queue of currently unexplored paths that should be explored in order to build the cfg.
    cfg_unexplored_path_t unexplored_paths_queue[CFG_BUILDER_MAX_UNEXPLORED_PATHS];
    size_t unexplored_paths_amount;

    /// the built cfg.
    cfg_t cfg;
} cfg_builder_t;

void cfg_reset(cfg_t* cfg);

err_t cfg_block_addr_range(
    const cfg_t* cfg, cfg_item_id_t block_id, u64* start, u64* end
);

err_t cfg_block_successors(
    const cfg_t* cfg, cfg_item_id_t block_id, cfg_item_id_t successor_block_ids[CFG_BLOCK_MAX_SUCCESSORS]
);

err_t cfg_block_is_direct_predecessor(
    const cfg_t* cfg, cfg_item_id_t block_id, cfg_item_id_t is_predecessor_of, bool* result
);

err_t cfg_build(
    cfg_builder_t* builder,
    pis_lifter_t lifter,
    const u8* machine_code,
    size_t machine_code_len,
    u64 machine_code_start_addr
);
