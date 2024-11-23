#include "cfg.h"
#include "cursor.h"
#include "errors.h"
#include "except.h"
#include "lifter.h"
#include "pis.h"

#include <string.h>

void cfg_reset(cfg_t* cfg) {
    memset(cfg, 0, sizeof(*cfg));
}

static err_t next_id(size_t* items_amount, cfg_item_id_t* id) {
    err_t err = SUCCESS;

    // make sure that we have more space in our storage.
    CHECK(*items_amount < CFG_MAX_UNITS);

    // allocate a new unit
    size_t index = (*items_amount)++;

    // check for overflow when casting to the item id type
    CHECK(index <= CFG_ITEM_ID_MAX);

    *id = index;

cleanup:
    return err;
}

static err_t next_insn_id(cfg_t* cfg, cfg_item_id_t* id) {
    err_t err = SUCCESS;

    CHECK_RETHROW(next_id(&cfg->insns_amount, id));

cleanup:
    return err;
}

static err_t next_unit_id(cfg_t* cfg, cfg_item_id_t* id) {
    err_t err = SUCCESS;

    CHECK_RETHROW(next_id(&cfg->units_amount, id));

cleanup:
    return err;
}

static err_t next_block_id(cfg_t* cfg, cfg_item_id_t* id) {
    err_t err = SUCCESS;

    CHECK_RETHROW(next_id(&cfg->blocks_amount, id));

cleanup:
    return err;
}

static err_t make_insn(cfg_t* cfg, const pis_insn_t* insn, cfg_item_id_t* id_out) {
    err_t err = SUCCESS;

    // allocate an id
    cfg_item_id_t insn_id = CFG_ITEM_ID_INVALID;
    CHECK_RETHROW(next_insn_id(cfg, &insn_id));

    // store the actual pis instruction information
    cfg->insn_storage[insn_id] = *insn;

    // return the id to the caller
    *id_out = insn_id;

cleanup:
    return err;
}

static err_t make_unit(
    cfg_t* cfg, const pis_lift_res_t* lift_res, u64 machine_insn_addr, cfg_item_id_t* id_out
) {
    err_t err = SUCCESS;

    // store all of the pis instructions in the cfg and remember the id of the first one
    cfg_item_id_t first_insn_id = CFG_ITEM_ID_INVALID;
    for (size_t i = 0; i < lift_res->insns_amount; i++) {
        cfg_item_id_t insn_id = CFG_ITEM_ID_INVALID;
        CHECK_RETHROW(make_insn(cfg, &lift_res->insns[i], &insn_id));

        // if this is the first insn, remember its id.
        if (first_insn_id == CFG_ITEM_ID_INVALID) {
            first_insn_id = insn_id;
        }
    }

    // allocate an id for the unit
    cfg_item_id_t unit_id = CFG_ITEM_ID_INVALID;
    CHECK_RETHROW(next_unit_id(cfg, &unit_id));

    // fill the information about the unit
    cfg->unit_storage[unit_id].addr = machine_insn_addr;
    cfg->unit_storage[unit_id].first_insn_id = first_insn_id;
    cfg->unit_storage[unit_id].insns_amount = lift_res->insns_amount;
    cfg->unit_storage[unit_id].machine_insn_len = lift_res->machine_insn_len;

    // return the id to the caller
    *id_out = unit_id;

cleanup:
    return err;
}

static err_t block_append_unit(cfg_t* cfg, cfg_item_id_t block_id, cfg_item_id_t unit_id) {
    err_t err = SUCCESS;

    cfg_block_t* block = &cfg->block_storage[block_id];

    if (block->units_amount == 0) {
        // no units currently in the block
        block->units_amount = 1;
        block->first_unit_id = unit_id;
    } else {
        // the block already has some units in it. appending a unit to a block is done by just
        // increasing the amount of units in the block, since all units in the block are allocated
        // adjacently, due to how we are building the cfg.

        // first, make sure that the unit adjacency assumption holds.
        cfg_item_id_t last_unit_id = block->first_unit_id + block->units_amount - 1;
        CHECK(last_unit_id + 1 == unit_id);

        // add the unit to the block by just increasing the units amount
        block->units_amount++;
    }

cleanup:
    return err;
}

static bool opcode_is_cfg_jmp(pis_opcode_t opcode) {
    switch (opcode) {
        case PIS_OPCODE_JMP:
            // a regular jump is a CFG jump which is just treated as an inter-function jump.
        case PIS_OPCODE_JMP_RET:
            // a ret is a CFG jump which marks the end of an execution path.
        case PIS_OPCODE_JMP_COND:
            // a condition jump is a CFG jump which splits the CFG and is treater as an
            // inter-function jump.
            return true;
        case PIS_OPCODE_JMP_CALL:
            // a call is not a CFG jump, we assume that the function will return and continue
            // execution on the next instruction.
        case PIS_OPCODE_JMP_CALL_COND:
            // a conditional call is also not a CFG jump, because whether the call was taken or
            // not, execution will continue at the next instruction.
        default:
            return false;
    }
}

/// checks if the given lift result represent a CFG jump machine instruction, and if so, returns
/// the pis opcode inside of it that is responsible for performing the jump.
static err_t find_cfg_jump(const pis_lift_res_t* lift_res, const pis_insn_t** jmp_insn) {
    err_t err = SUCCESS;

    *jmp_insn = NULL;

    for (size_t i = 0; i < lift_res->insns_amount; i++) {
        const pis_insn_t* cur_insn = &lift_res->insns[i];
        if (opcode_is_cfg_jmp(cur_insn->opcode)) {
            // the machine instruction contains a pis jump instruction which looks like a CFG jump.
            //
            // this doesn't necessarily mean that this machine instruction is a CFG jump
            // instruction, since it might also be an inter-instruction jump.

            CHECK(cur_insn->operands_amount >= 1);
            const pis_operand_t* jmp_target = &cur_insn->operands[0];

            if (jmp_target->addr.space == PIS_SPACE_CONST) {
                // this jump is an inter-instruction jump. this is used for example to implement the
                // x86 `REP` prefix, and does not represent an actual CFG jump instruction.
            } else {
                // this jump is an actual CFG jump.

                // such a jump must be the last pis instruction in the lifted representation of the
                // machine instruction, because otherwise it is unclear how we should handle the pis
                // instructions following it when building the cfg.
                CHECK(i + 1 == lift_res->insns_amount);

                *jmp_insn = cur_insn;
            }
        }
    }
cleanup:
    return err;
}

/// appaneds the given unit to the current block.
static err_t cfg_builder_append_to_cur_block(cfg_builder_t* builder, cfg_item_id_t unit_id) {
    err_t err = SUCCESS;

    if (builder->cur_block_id == CFG_ITEM_ID_INVALID) {
        // no current block, so create a new one.
        CHECK_RETHROW(next_block_id(&builder->cfg, &builder->cur_block_id));
    }

    // append the unit to the current block
    CHECK_RETHROW(block_append_unit(&builder->cfg, builder->cur_block_id, unit_id));

cleanup:
    return err;
}

/// enqueue an unexplored path that should explored when building a CFG.
static err_t enqueue_unexplored_path(cfg_builder_t* builder, size_t path_start_offset) {
    err_t err = SUCCESS;

    // make sure that we have more space in our queue.
    CHECK(builder->unexplored_paths_amount < CFG_BUILDER_MAX_UNEXPLORED_PATHS);

    builder->unexplored_paths_queue[builder->unexplored_paths_amount].start_offset =
        path_start_offset;

    builder->unexplored_paths_amount++;

cleanup:
    return err;
}

/// enqueue an unexplored path that should explored when building a CFG.
static err_t dequeue_unexplored_path(cfg_builder_t* builder, size_t* path_start_offset) {
    err_t err = SUCCESS;

    // make sure that we have more space in our queue.
    CHECK(builder->unexplored_paths_amount > 0);

    builder->unexplored_paths_amount--;

    *path_start_offset =
        builder->unexplored_paths_queue[builder->unexplored_paths_amount].start_offset;

cleanup:
    return err;
}

/// enqueue an unexplored path that should be explored when building a CFG.
static err_t
    enqueue_unexplored_path_by_jmp_target(cfg_builder_t* builder, const pis_operand_t* jmp_target) {
    err_t err = SUCCESS;

    CHECK(jmp_target->addr.space == PIS_SPACE_RAM);

    u64 ram_addr = jmp_target->addr.offset;
    CHECK(ram_addr >= builder->machine_code_start_addr);

    u64 offset = ram_addr - builder->machine_code_start_addr;
    CHECK(offset < builder->machine_code_len);

    CHECK_RETHROW(enqueue_unexplored_path(builder, offset));

cleanup:
    return err;
}

/// calculates the start and end machine code addresses of the given block.
err_t cfg_block_addr_range(const cfg_t* cfg, cfg_item_id_t block_id, u64* start, u64* end) {
    err_t err = SUCCESS;

    CHECK(block_id < cfg->blocks_amount);

    const cfg_block_t* block = &cfg->block_storage[block_id];

    // make sure that the block has any content
    CHECK(block->units_amount > 0);

    const cfg_unit_t* first_unit = &cfg->unit_storage[block->first_unit_id];
    *start = first_unit->addr;

    cfg_item_id_t last_unit_id = block->first_unit_id + block->units_amount - 1;
    const cfg_unit_t* last_unit = &cfg->unit_storage[last_unit_id];
    *end = last_unit->addr + last_unit->machine_insn_len;

cleanup:
    return err;
}

/// tries to find a block in the CFG which contains the given machine code address.
/// the id of the block that was found is returned in `found_block_id`.
/// if no block was found, `found_block_id` is set to `CFG_ITEM_ID_INVALID`.
static err_t find_block_containing_addr(const cfg_t* cfg, u64 addr, cfg_item_id_t* found_block_id) {
    err_t err = SUCCESS;

    *found_block_id = CFG_ITEM_ID_INVALID;

    for (size_t i = 0; i < cfg->blocks_amount; i++) {
        u64 block_start = 0;
        u64 block_end = 0;
        CHECK_RETHROW(cfg_block_addr_range(cfg, i, &block_start, &block_end));

        if (addr >= block_start && addr < block_end) {
            *found_block_id = i;
            break;
        }
    }

cleanup:
    return err;
}

static cfg_item_id_t
    block_find_unit_containing_addr(const cfg_t* cfg, const cfg_block_t* block, u64 addr) {
    cfg_item_id_t end_id = block->first_unit_id + block->units_amount;

    for (cfg_item_id_t i = block->first_unit_id; i < end_id; i++) {
        const cfg_unit_t* unit = &cfg->unit_storage[i];

        u64 unit_end_addr = unit->addr + unit->machine_insn_len;

        if (addr >= unit->addr && addr < unit_end_addr) {
            // this unit contains the given addr.
            return i;
        }
    }

    // no unit was found.
    return CFG_ITEM_ID_INVALID;
}

/// explore a path of the code which was already explored previously, and is already contained in an
/// existing block in the CFG.
static err_t
    explore_seen_path(cfg_builder_t* builder, cfg_item_id_t block_id, size_t path_start_offset) {
    err_t err = SUCCESS;

    u64 path_start_addr = builder->machine_code_start_addr + path_start_offset;

    cfg_block_t* block = &builder->cfg.block_storage[block_id];

    // find the start address of the block
    u64 block_start = 0;
    u64 block_end = 0;
    CHECK_RETHROW(cfg_block_addr_range(&builder->cfg, block_id, &block_start, &block_end));

    if (block_start == path_start_offset) {
        // if some flow in the code leads back to the start of this block, there is nothing for us
        // to do, since we have already explored this block.
        SUCCESS_CLEANUP();
    }

    // in this case, some flow in the machine code leads to the middle of this block, so we need to
    // split it.

    // find which unit inside of the block this new path points to.
    cfg_item_id_t unit_id = block_find_unit_containing_addr(&builder->cfg, block, path_start_addr);

    // this block should contain the path, so we expect to find a unit which contains it.
    CHECK(unit_id != CFG_ITEM_ID_INVALID);

    cfg_unit_t* unit = &builder->cfg.unit_storage[unit_id];

    // the path is contained in this unit. make sure that it points to the start of the
    // unit, otherwise the machine code contains jumps to mid-instructions.
    CHECK(path_start_addr == unit->addr);

    // now lets start splitting. first create a new block.
    cfg_item_id_t new_block_id = CFG_ITEM_ID_INVALID;
    CHECK_RETHROW(next_block_id(&builder->cfg, &new_block_id));
    cfg_block_t* new_block = &builder->cfg.block_storage[new_block_id];

    // the new block should start with the unit which this new path points to. for example if the
    // machine code contains a jump to some instruction in the middle of an existing block, we want
    // the new block to start at that instruction.
    new_block->first_unit_id = unit_id;

    // the new block contains all instruction starting from the first one up to the end of the
    // original block.
    cfg_item_id_t unit_offset_in_block = unit_id - block->first_unit_id;
    new_block->units_amount = block->units_amount - unit_offset_in_block;

    // now truncate the original block to only contain unit up to the unit which contains the path.
    block->units_amount = unit_offset_in_block;

cleanup:
    return err;
}

static err_t
    enqueue_cfg_jmp_paths(cfg_builder_t* builder, const pis_insn_t* insn, size_t next_insn_offset) {
    err_t err = SUCCESS;

    // find the target of the jump
    CHECK(insn->operands_amount >= 1);
    const pis_operand_t* jmp_target = &insn->operands[0];

    switch (insn->opcode) {
        case PIS_OPCODE_JMP:
            // regular jump. this is assumed to be a jump into somewhere inside the current
            // function. enqueue exploration of the branch target.
            CHECK_RETHROW(enqueue_unexplored_path_by_jmp_target(builder, jmp_target));
            break;
        case PIS_OPCODE_JMP_RET:
            // ret. this marks the end of a path, and doesn't require any further
            // exploration.
            break;
        case PIS_OPCODE_JMP_COND:
            // conditional jump. this is assumed to be a jump into somewhere inside the
            // current function. enqueue exploration of the branch target, and of the
            // instruction following the branch.
            CHECK_RETHROW(enqueue_unexplored_path_by_jmp_target(builder, jmp_target));
            CHECK_RETHROW(enqueue_unexplored_path(builder, next_insn_offset));
            break;
        default:
            UNREACHABLE();
            break;
    }
cleanup:
    return err;
}

/// explore a previously unseen path of the code.
static err_t explore_unseen_path(cfg_builder_t* builder, size_t path_start_offset) {
    err_t err = SUCCESS;

    size_t cur_offset = path_start_offset;
    while (1) {
        CHECK(cur_offset < builder->machine_code_len);

        // when exploring unseen path, we might reach a point where the next instruction that we are
        // about to explore was already previously explored because there was a branch to it in the
        // code.
        cfg_item_id_t existing_block_id = CFG_ITEM_ID_INVALID;
        CHECK_RETHROW(find_block_containing_addr(&builder->cfg, cur_offset, &existing_block_id));
        if (existing_block_id != CFG_ITEM_ID_INVALID) {
            // the next instruction was already explored and exists in another block. so, the
            // current block is finished, and it just falls through to that block.
            break;
        }

        pis_lift_args_t lift_args = {
            .machine_code = CURSOR_INIT(
                builder->machine_code + cur_offset,
                builder->machine_code_len - cur_offset
            ),
            .machine_code_addr = builder->machine_code_start_addr + cur_offset,
        };

        CHECK_RETHROW(builder->lifter(&lift_args));

        size_t next_offset = cur_offset + lift_args.result.machine_insn_len;

        // create a cfg unit for this machine instruction
        cfg_item_id_t unit_id = CFG_ITEM_ID_INVALID;
        CHECK_RETHROW(
            make_unit(&builder->cfg, &lift_args.result, lift_args.machine_code_addr, &unit_id)
        );

        // check if this machine instruction is a CFG jump instruction, and if so, find the relevant
        // pis instruction.
        const pis_insn_t* cfg_jmp_insn = NULL;
        CHECK_RETHROW(find_cfg_jump(&lift_args.result, &cfg_jmp_insn));

        CHECK_RETHROW(cfg_builder_append_to_cur_block(builder, unit_id));

        if (cfg_jmp_insn != NULL) {
            // this is a cfg jump instruction. handle it accordingly.

            // enqueue the paths that need to be further explored according to the jump.
            CHECK_RETHROW(enqueue_cfg_jmp_paths(builder, cfg_jmp_insn, next_offset));

            // a CFG jump always marks the end of a block. so, stop building the current block.
            break;
        } else {
            // regular, non cfg jump instruction. just advance to the next instruction.
            cur_offset = next_offset;
        }
    }

    // we finished building the current block, don't append any other units to it.
    builder->cur_block_id = CFG_ITEM_ID_INVALID;

cleanup:
    return err;
}

/// explore a single path of the code and build it into the CFG.
static err_t explore_path(cfg_builder_t* builder, size_t path_start_offset) {
    err_t err = SUCCESS;

    u64 path_start_addr = builder->machine_code_start_addr + path_start_offset;

    // first, check if we already have a block which contains this code.
    cfg_item_id_t existing_block_id = CFG_ITEM_ID_INVALID;
    CHECK_RETHROW(find_block_containing_addr(&builder->cfg, path_start_addr, &existing_block_id));
    if (existing_block_id != CFG_ITEM_ID_INVALID) {
        // this path was already explored and is part of an existing block.
        CHECK_RETHROW(explore_seen_path(builder, existing_block_id, path_start_offset));
    } else {
        // this path is unseen.
        CHECK_RETHROW(explore_unseen_path(builder, path_start_offset));
    }

cleanup:
    return err;
}

static void builder_init(
    cfg_builder_t* builder,
    pis_lifter_t lifter,
    const u8* machine_code,
    size_t machine_code_len,
    u64 machine_code_start_addr
) {
    builder->lifter = lifter;
    builder->machine_code = machine_code;
    builder->machine_code_len = machine_code_len;
    builder->machine_code_start_addr = machine_code_start_addr;

    cfg_reset(&builder->cfg);
    builder->cur_block_id = CFG_ITEM_ID_INVALID;
    builder->unexplored_paths_amount = 0;
}

err_t cfg_build(
    cfg_builder_t* builder,
    pis_lifter_t lifter,
    const u8* machine_code,
    size_t machine_code_len,
    u64 machine_code_start_addr
) {
    err_t err = SUCCESS;

    builder_init(builder, lifter, machine_code, machine_code_len, machine_code_start_addr);

    CHECK_RETHROW(enqueue_unexplored_path(builder, 0));

    while (builder->unexplored_paths_amount > 0) {
        size_t path_start_offset = 0;
        CHECK_RETHROW(dequeue_unexplored_path(builder, &path_start_offset));
        CHECK_RETHROW(explore_path(builder, path_start_offset));
    }
cleanup:
    return err;
}
