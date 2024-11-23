#include "cdfg.h"
#include "cfg.h"
#include "except.h"
#include "pis.h"

static err_t next_id(size_t* items_amount, size_t max, cdfg_item_id_t* id) {
    err_t err = SUCCESS;

    // make sure that we have more space in our storage.
    CHECK(*items_amount < max);

    // allocate a new item
    size_t index = (*items_amount)++;

    // check for overflow when casting to the item id type
    CHECK(index <= CDFG_ITEM_ID_MAX);

    *id = index;

cleanup:
    return err;
}

static err_t next_node_id(cdfg_t* cdfg, cfg_item_id_t* id) {
    err_t err = SUCCESS;

    CHECK_RETHROW(next_id(&cdfg->nodes_amount, CDFG_MAX_NODES, id));

cleanup:
    return err;
}

/// fetch the value of the given operand according to the given operand state.
/// returns the id of the node which represents the value of the operand, or `CDFG_ITEM_ID_INVALID`
/// if the operand is currently uninitialized.
static cdfg_item_id_t
    op_state_read_operand(const cdfg_op_state_t* op_state, const pis_operand_t* operand) {
    for (size_t i = 0; i < op_state->used_slots_amount; i++) {
        const cdfg_op_state_slot_t* slot = &op_state->slots[i];
        if (slot->value_node_id == CDFG_ITEM_ID_INVALID) {
            // this slot is vacant.
            continue;
        }
        if (pis_operand_equals(operand, &slot->operand)) {
            return slot->value_node_id;
        }
    }
    return CDFG_ITEM_ID_INVALID;
}

/// tries to find an existing immediate node with the given value in the cdfg.
/// returns the id of the found node, or `CDFG_ITEM_ID_INVALID` if no such node was found.
static cdfg_item_id_t find_imm_node(const cdfg_t* cdfg, u64 value) {
    for (size_t i = 0; i < cdfg->nodes_amount; i++) {
        const cdfg_node_t* node = &cdfg->node_storage[i];
        if (node->kind != CDFG_NODE_KIND_IMM) {
            continue;
        }
        if (node->content.imm.value == value) {
            return i;
        }
    }
    return CDFG_ITEM_ID_INVALID;
}

/// reads an immediate operand with the given value. returns the node id of a node which represents
/// that immediate value.
static err_t read_imm_operand(cdfg_builder_t* builder, u64 value, cdfg_item_id_t* out_node_id) {
    err_t err = SUCCESS;

    cdfg_item_id_t node_id = find_imm_node(&builder->cdfg, value);

    if (node_id == CDFG_ITEM_ID_INVALID) {
        // no existing node, create a new one.
        CHECK_RETHROW(next_node_id(&builder->cdfg, &node_id));

        cdfg_node_t* node = &builder->cdfg.node_storage[node_id];
        node->content.imm.value = value;
    }

    *out_node_id = node_id;

cleanup:
    return err;
}

static err_t read_reg_operand(
    const pis_operand_t* operand,
    cdfg_builder_t* builder,
    const cdfg_op_state_t* op_state,
    cdfg_item_id_t* out_node_id
) {
    err_t err = SUCCESS;
    TODO();
cleanup:
    return err;
}

static err_t read_tmp_operand(
    const pis_operand_t* operand, const cdfg_op_state_t* op_state, cdfg_item_id_t* out_node_id
) {
    err_t err = SUCCESS;

    // tmp operands can't be uninitialized when read, so just read it from the op state.
    cdfg_item_id_t node_id = op_state_read_operand(op_state, operand);
    CHECK(node_id != CDFG_ITEM_ID_INVALID);

    *out_node_id = node_id;
cleanup:
    return err;
}

/// reads the given operand according to the given op state and returns the id of a node which
/// represents the value of the operand.
static err_t read_operand(
    const pis_operand_t* operand,
    cdfg_builder_t* builder,
    const cdfg_op_state_t* op_state,
    cdfg_item_id_t* out_node_id
) {
    err_t err = SUCCESS;
    switch (operand->addr.space) {
        case PIS_SPACE_CONST:
            CHECK_RETHROW(read_imm_operand(builder, operand->addr.offset, out_node_id));
            break;
        case PIS_SPACE_REG:
            CHECK_RETHROW(read_reg_operand(operand, builder, op_state, out_node_id));
            break;
        case PIS_SPACE_TMP:
            CHECK_RETHROW(read_tmp_operand(operand, op_state, out_node_id));
            break;
        case PIS_SPACE_RAM:
            // ram operands are only used in jump instructions, and can't be read directly. reading
            // from ram is done using the load instruction.
            UNREACHABLE();
        default:
            UNREACHABLE();
    }
cleanup:
    return err;
}

err_t cdfg_build(cdfg_builder_t* builder, const cfg_t* cfg) {
    err_t err = SUCCESS;

    const cfg_block_t* block = &cfg->block_storage[0];
    CHECK(block->units_amount > 0);

    cdfg_op_state_t op_state = {};

    const cfg_unit_t* block_units = &cfg->unit_storage[block->first_unit_id];
    for (size_t unit_idx = 0; unit_idx < block->units_amount; unit_idx++) {
        const cfg_unit_t* unit = &block_units[unit_idx];
        const pis_insn_t* unit_insns = &cfg->insn_storage[unit->first_insn_id];
        for (size_t insn_idx = 0; insn_idx < unit->insns_amount; insn_idx++) {
            const pis_insn_t* insn = &unit_insns[insn_idx];
        }
    }

cleanup:
    return err;
}
