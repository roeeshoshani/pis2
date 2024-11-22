#include "cfg.h"
#include "cursor.h"
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

/// checks if the given lift result represent a CFG jump machine instruction, and if so, returns
/// the pis opcode inside of it that is responsible for performing the jump.
static err_t find_cfg_jump(const pis_lift_res_t* lift_res, const pis_insn_t** jmp_insn) {
    err_t err = SUCCESS;

    *jmp_insn = NULL;

    for (size_t i = 0; i < lift_res->insns_amount; i++) {
        const pis_insn_t* cur_insn = &lift_res->insns[i];
        if (cur_insn->opcode == PIS_OPCODE_JMP || cur_insn->opcode == PIS_OPCODE_JMP_COND) {
            // the machine instruction contains a pis jump instruction.
            //
            // this might mean that this machine instruction is a CFG jump instruction, or it might
            // just be an inter-instruction jump. check if the target of the branch is inside of the
            // current instruction.
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

err_t build_cfg_wip(
    pis_cfg_builder_t* builder, pis_lifter_t lifter, const u8* code, size_t code_len, u64 code_addr
) {
    err_t err = SUCCESS;

    // reset the fields of the CFG builder.
    pis_cfg_reset(&builder->cfg);
    builder->cur_block_id = PIS_CFG_ITEM_ID_INVALID;

    size_t cur_offset = 0;
    while (1) {
        pis_lift_args_t lift_args = {
            .machine_code = CURSOR_INIT(code + cur_offset, code_len - cur_offset),
            .machine_code_addr = code_addr + cur_offset,
        };

        CHECK_RETHROW(lifter(&lift_args));

        // create a cfg unit for this machine instruction
        pis_cfg_item_id_t unit_id = PIS_CFG_ITEM_ID_INVALID;
        CHECK_RETHROW(
            make_unit(&builder->cfg, &lift_args.result, lift_args.machine_code_addr, &unit_id)
        );

        const pis_insn_t* cfg_jmp_insn = NULL;
        CHECK_RETHROW(find_cfg_jump(&lift_args.result, &cfg_jmp_insn));

        CHECK_RETHROW(cfg_builder_append_to_cur_block(builder, unit_id));

        if (cfg_jmp_insn != NULL) {
            // this is a cfg jump instruction. this will mark the end of the current block.
        }

        // advance to the next instruction
        cur_offset += lift_args.result.machine_insn_len;
    }
cleanup:
    return err;
}
