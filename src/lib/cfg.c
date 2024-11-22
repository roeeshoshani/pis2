#include "cfg.h"
#include "cursor.h"
#include "except.h"
#include "lifter.h"
#include "pis.h"

#include <string.h>

void pis_cfg_init(pis_cfg_t* cfg) {
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

    // appending a unit to a block is done by just increasing the amount of units in the block,
    // since all units in the block are allocated adjacently.

    // first, make sure that the unit adjacency assumption holds.
    pis_cfg_item_id_t last_unit_id =
        cfg->block_storage[block_id].first_unit_id + cfg->block_storage[block_id].units_amount - 1;
    CHECK(last_unit_id + 1 == unit_id);

    // add the unit to the block by just increasing the units amount
    cfg->block_storage[block_id].units_amount++;

cleanup:
    return err;
}

err_t build_cfg_wip(pis_cfg_t* cfg, pis_lifter_t lifter, cursor_t code, u64 code_addr) {
    err_t err = SUCCESS;

    pis_cfg_item_id_t cur_block_id = PIS_CFG_ITEM_ID_INVALID;

    while (1) {
        pis_lift_args_t args = {
            .machine_code = code,
            .machine_code_addr = code_addr,
        };
        CHECK_RETHROW(lifter(&args));

        // create a cfg unit for this machine instruction
        pis_cfg_item_id_t unit_id = PIS_CFG_ITEM_ID_INVALID;
        CHECK_RETHROW(make_unit(cfg, &args.result, code_addr, &unit_id));

        if (cur_block_id == PIS_CFG_ITEM_ID_INVALID) {
            // create a new block and append the unit to it
            CHECK_RETHROW(next_block_id(cfg, &cur_block_id));
            cfg->block_storage[cur_block_id].first_unit_id = unit_id;
            cfg->block_storage[cur_block_id].units_amount = 1;
        } else {
            // append the unit to the current block
            CHECK_RETHROW(block_append_unit(cfg, cur_block_id, unit_id));
        }

        // update the current instruction address to the next address
        code_addr += args.result.machine_insn_len;
    }
cleanup:
    return err;
}
