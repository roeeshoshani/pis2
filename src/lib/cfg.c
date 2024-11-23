#include "cfg.h"
#include "cursor.h"
#include "errors.h"
#include "except.h"
#include "lifter.h"
#include "pis.h"

#include <string.h>

void pis_cfg_reset(pis_cfg_t* cfg) {
    memset(cfg, 0, sizeof(*cfg));
}

static err_t next_id(size_t* items_amount, pis_cfg_item_id_t* id) {
    err_t err = SUCCESS;

    // make sure that we have more space in our storage.
    CHECK(*items_amount < PIS_CFG_MAX_UNITS);

    // allocate a new unit
    size_t index = (*items_amount)++;

    // check for overflow when casting to the item id type
    CHECK(index <= PIS_CFG_ITEM_ID_MAX);

    *id = index;

cleanup:
    return err;
}

static err_t next_insn_id(pis_cfg_t* cfg, pis_cfg_item_id_t* id) {
    err_t err = SUCCESS;

    CHECK_RETHROW(next_id(&cfg->insns_amount, id));

cleanup:
    return err;
}

static err_t next_unit_id(pis_cfg_t* cfg, pis_cfg_item_id_t* id) {
    err_t err = SUCCESS;

    CHECK_RETHROW(next_id(&cfg->units_amount, id));

cleanup:
    return err;
}

static err_t next_block_id(pis_cfg_t* cfg, pis_cfg_item_id_t* id) {
    err_t err = SUCCESS;

    CHECK_RETHROW(next_id(&cfg->blocks_amount, id));

cleanup:
    return err;
}

static err_t make_insn(pis_cfg_t* cfg, const pis_insn_t* insn, pis_cfg_item_id_t* id_out) {
    err_t err = SUCCESS;

    // allocate an id
    pis_cfg_item_id_t insn_id = PIS_CFG_ITEM_ID_INVALID;
    CHECK_RETHROW(next_insn_id(cfg, &insn_id));

    // store the actual pis instruction information
    cfg->insn_storage[insn_id] = *insn;

    // return the id to the caller
    *id_out = insn_id;

cleanup:
    return err;
}

static err_t make_unit(
    pis_cfg_t* cfg, const pis_lift_res_t* lift_res, u64 machine_insn_addr, pis_cfg_item_id_t* id_out
) {
    err_t err = SUCCESS;

    // store all of the pis instructions in the cfg and remember the id of the first one
    pis_cfg_item_id_t first_insn_id = PIS_CFG_ITEM_ID_INVALID;
    for (size_t i = 0; i < lift_res->insns_amount; i++) {
        pis_cfg_item_id_t insn_id = PIS_CFG_ITEM_ID_INVALID;
        CHECK_RETHROW(make_insn(cfg, &lift_res->insns[i], &insn_id));

        // if this is the first insn, remember its id.
        if (first_insn_id == PIS_CFG_ITEM_ID_INVALID) {
            first_insn_id = insn_id;
        }
    }

    // allocate an id for the unit
    pis_cfg_item_id_t unit_id = PIS_CFG_ITEM_ID_INVALID;
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

static err_t
    block_append_unit(pis_cfg_t* cfg, pis_cfg_item_id_t block_id, pis_cfg_item_id_t unit_id) {
    err_t err = SUCCESS;

    pis_cfg_block_t* block = &cfg->block_storage[block_id];

    if (block->units_amount == 0) {
        // no units currently in the block
        block->units_amount = 1;
        block->first_unit_id = unit_id;
    } else {
        // the block already has some units in it. appending a unit to a block is done by just
        // increasing the amount of units in the block, since all units in the block are allocated
        // adjacently, due to how we are building the cfg.

        // first, make sure that the unit adjacency assumption holds.
        pis_cfg_item_id_t last_unit_id = block->first_unit_id + block->units_amount - 1;
        CHECK(last_unit_id + 1 == unit_id);

        // add the unit to the block by just increasing the units amount
        block->units_amount++;
    }

cleanup:
    return err;
}

static bool pis_opcode_is_cfg_jmp(pis_opcode_t opcode) {
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
        if (pis_opcode_is_cfg_jmp(cur_insn->opcode)) {
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
static err_t
    cfg_builder_append_to_cur_block(pis_cfg_builder_t* builder, pis_cfg_item_id_t unit_id) {
    err_t err = SUCCESS;

    if (builder->cur_block_id == PIS_CFG_ITEM_ID_INVALID) {
        // no current block, so create a new one.
        CHECK_RETHROW(next_block_id(&builder->cfg, &builder->cur_block_id));
    }

    // append the unit to the current block
    CHECK_RETHROW(block_append_unit(&builder->cfg, builder->cur_block_id, unit_id));

cleanup:
    return err;
}

/// enqueue an unexplored path that should explored when building a CFG.
static err_t enqueue_unexplored_path(pis_cfg_builder_t* builder, size_t path_start_offset) {
    err_t err = SUCCESS;

    // make sure that we have more space in our queue.
    CHECK(builder->unexplored_paths_amount < PIS_CFG_BUILDER_MAX_UNEXPLORED_PATHS);

    // store the unexplored path
    builder->unexplored_paths_queue[builder->unexplored_paths_amount++].start_offset =
        path_start_offset;

cleanup:
    return err;
}

/// enqueue an unexplored path that should explored when building a CFG.
static err_t dequeue_unexplored_path(pis_cfg_builder_t* builder, size_t* path_start_offset) {
    err_t err = SUCCESS;

    // make sure that we have more space in our queue.
    CHECK(builder->unexplored_paths_amount > 0);

    // store the unexplored path
    *path_start_offset =
        builder->unexplored_paths_queue[builder->unexplored_paths_amount--].start_offset;

cleanup:
    return err;
}

/// queue an unexplored path that should explored when building a CFG.
static err_t enqueue_unexplored_path_by_jmp_target(
    pis_cfg_builder_t* builder, const pis_operand_t* jmp_target
) {
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
static err_t
    block_get_addr_range(const pis_cfg_t* cfg, const pis_cfg_block_t* block, u64* start, u64* end) {
    err_t err = SUCCESS;

    // make sure that the block has any content
    CHECK(block->units_amount > 0);

    const pis_cfg_unit_t* first_unit = &cfg->unit_storage[block->first_unit_id];
    *start = first_unit->addr;

    pis_cfg_item_id_t last_unit_id = block->first_unit_id + block->units_amount - 1;
    const pis_cfg_unit_t* last_unit = &cfg->unit_storage[last_unit_id];
    *end = last_unit->addr + last_unit->machine_insn_len;

cleanup:
    return err;
}

/// tries to find a block in the CFG which contains the given machine code address.
/// the id of the block that was found is returned in `found_block_id`.
/// if no block was found, `found_block_id` is set to `PIS_CFG_ITEM_ID_INVALID`.
static err_t
    find_block_containing_addr(const pis_cfg_t* cfg, u64 addr, pis_cfg_item_id_t* found_block_id) {
    err_t err = SUCCESS;

    *found_block_id = PIS_CFG_ITEM_ID_INVALID;

    for (size_t i = 0; i < cfg->blocks_amount; i++) {
        const pis_cfg_block_t* block = &cfg->block_storage[i];

        u64 block_start = 0;
        u64 block_end = 0;
        CHECK_RETHROW(block_get_addr_range(cfg, block, &block_start, &block_end));

        if (addr >= block_start && addr < block_end) {
            *found_block_id = i;
            break;
        }
    }

cleanup:
    return err;
}

static pis_cfg_item_id_t
    block_find_unit_containing_addr(const pis_cfg_t* cfg, const pis_cfg_block_t* block, u64 addr) {
    pis_cfg_item_id_t end_id = block->first_unit_id + block->units_amount;

    for (pis_cfg_item_id_t i = block->first_unit_id; i < end_id; i++) {
        const pis_cfg_unit_t* unit = &cfg->unit_storage[i];

        u64 unit_end_addr = unit->addr + unit->machine_insn_len;

        if (addr >= unit->addr && addr < unit_end_addr) {
            // this unit contains the given addr.
            return i;
        }
    }

    // no unit was found.
    return PIS_CFG_ITEM_ID_INVALID;
}

/// explore a path of the code which was already explored previously, and is already contained in an
/// existing block in the CFG.
static err_t explore_seen_path(
    pis_cfg_builder_t* builder, pis_cfg_item_id_t block_id, size_t path_start_offset
) {
    err_t err = SUCCESS;

    u64 path_start_addr = builder->machine_code_start_addr + path_start_offset;

    pis_cfg_block_t* block = &builder->cfg.block_storage[block_id];

    // find the start address of the block
    u64 block_start = 0;
    u64 block_end = 0;
    CHECK_RETHROW(block_get_addr_range(&builder->cfg, block, &block_start, &block_end));

    if (block_start == path_start_offset) {
        // if some flow in the code leads back to the start of this block, there is nothing for us
        // to do, since we have already explored this block.
        SUCCESS_CLEANUP();
    }

    // in this case, some flow in the machine code leads to the middle of this block, so we need to
    // split it.

    // find which unit inside of the block this new path points to.
    pis_cfg_item_id_t unit_id =
        block_find_unit_containing_addr(&builder->cfg, block, path_start_addr);

    // this block should contain the path, so we expect to find a unit which contains it.
    CHECK(unit_id != PIS_CFG_ITEM_ID_INVALID);

    pis_cfg_unit_t* unit = &builder->cfg.unit_storage[unit_id];

    // the path is contained in this unit. make sure that it points to the start of the
    // unit, otherwise the machine code contains jumps to mid-instructions.
    CHECK(path_start_addr == unit->addr);

    // TODO: split the fockin block
    TODO();

cleanup:
    return err;
}

/// explore a previously unseen path of the code.
static err_t explore_unseen_path(pis_cfg_builder_t* builder, size_t path_start_offset) {
    err_t err = SUCCESS;

    size_t cur_offset = path_start_offset;
    while (1) {
        CHECK(cur_offset < builder->machine_code_len);

        pis_lift_args_t lift_args = {
            .machine_code = CURSOR_INIT(
                builder->machine_code_start + cur_offset,
                builder->machine_code_len - cur_offset
            ),
            .machine_code_addr = builder->machine_code_start_addr + cur_offset,
        };

        CHECK_RETHROW(builder->lifter(&lift_args));

        // create a cfg unit for this machine instruction
        pis_cfg_item_id_t unit_id = PIS_CFG_ITEM_ID_INVALID;
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

            // find the target of the jump
            CHECK(cfg_jmp_insn->operands_amount >= 1);
            const pis_operand_t* jmp_target = &cfg_jmp_insn->operands[0];

            bool continue_exploring_current_path;
            switch (cfg_jmp_insn->opcode) {
                case PIS_OPCODE_JMP:
                    // regular jump. this is assumed to be a jump into somewhere inside the current
                    // function. queue exploration of the branch target.
                    CHECK_RETHROW(enqueue_unexplored_path_by_jmp_target(builder, jmp_target));

                    // we finished exploring the current path.
                    continue_exploring_current_path = false;

                    break;
                case PIS_OPCODE_JMP_RET:
                    // ret. this marks the end of a path, and doesn't require any further
                    // exploration.

                    // we finished exploring the current path.
                    continue_exploring_current_path = false;

                    break;
                case PIS_OPCODE_JMP_COND:
                    // conditional jump. this is assumed to be a jump into somewhere inside the
                    // current function. queue exploration of the branch target.
                    CHECK_RETHROW(enqueue_unexplored_path_by_jmp_target(builder, jmp_target));

                    // the jump is conditional, so also continue exploration of the current path, in
                    // case the branch is not taken.
                    continue_exploring_current_path = true;

                    break;
                default:
                    UNREACHABLE();
                    break;
            }

            if (!continue_exploring_current_path) {
                // stop exploring.
                break;
            }
        }

        // advance to the next instruction
        cur_offset += lift_args.result.machine_insn_len;
    }

cleanup:
    return err;
}

/// explore a single path of the code and build it into the CFG.
static err_t explore_path(pis_cfg_builder_t* builder, size_t path_start_offset) {
    err_t err = SUCCESS;

    u64 path_start_addr = builder->machine_code_start_addr + path_start_offset;

    // first, check if we already have a block which contains this code.
    pis_cfg_item_id_t existing_block_id = PIS_CFG_ITEM_ID_INVALID;
    CHECK_RETHROW(find_block_containing_addr(&builder->cfg, path_start_addr, &existing_block_id));
    if (existing_block_id != PIS_CFG_ITEM_ID_INVALID) {
        // this path was already explored and is part of an existing block.
        CHECK_RETHROW(explore_seen_path(builder, existing_block_id, path_start_offset));
    } else {
        // this path is unseen.
        CHECK_RETHROW(explore_unseen_path(builder, path_start_offset));
    }

cleanup:
    return err;
}

void pis_cfg_builder_init(
    pis_cfg_builder_t* builder,
    pis_lifter_t lifter,
    const u8* machine_code_start,
    size_t machine_code_len,
    u64 machine_code_start_addr
) {
    builder->lifter = lifter;
    builder->machine_code_start = machine_code_start;
    builder->machine_code_len = machine_code_len;
    builder->machine_code_start_addr = machine_code_start_addr;

    pis_cfg_reset(&builder->cfg);
    builder->cur_block_id = PIS_CFG_ITEM_ID_INVALID;
    builder->unexplored_paths_amount = 0;
}

err_t build_cfg_wip(pis_cfg_builder_t* builder) {
    err_t err = SUCCESS;

    // reset the fields of the CFG builder.
    pis_cfg_reset(&builder->cfg);
    builder->cur_block_id = PIS_CFG_ITEM_ID_INVALID;

    CHECK_RETHROW(enqueue_unexplored_path(builder, 0));

    while (builder->unexplored_paths_amount > 0) {
        size_t path_start_offset = 0;
        CHECK_RETHROW(dequeue_unexplored_path(builder, &path_start_offset));
        CHECK_RETHROW(explore_path(builder, path_start_offset));
    }
cleanup:
    return err;
}
