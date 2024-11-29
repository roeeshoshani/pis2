#include "cdfg.h"
#include "cdfg/op_map.h"
#include "cfg.h"
#include "errors.h"
#include "except.h"
#include "pis.h"
#include "size.h"
#include "space.h"
#include "trace.h"
#include "utils.h"
#include <stddef.h>
#include <string.h>

typedef err_t (*opcode_handler_t)(cdfg_builder_t* builder, const pis_insn_t* insn);

STR_ENUM_IMPL(cdfg_calculation, CDFG_CALCULATION);

void cdfg_reset(cdfg_t* cdfg) {
    memset(cdfg, 0, sizeof(*cdfg));
}

static err_t find_node_inputs(
    const cdfg_t* cdfg,
    cdfg_node_id_t node_id,
    cdfg_edge_kind_t edge_kind,
    cdfg_node_id_t* input_node_ids,
    size_t inputs_amount
) {
    err_t err = SUCCESS;
    size_t cur_inputs_amount = 0;
    for (size_t i = 0; i < cdfg->edges_amount; i++) {
        const cdfg_edge_t* edge = &cdfg->edge_storage[i];
        if (edge->to_node.id != node_id.id || edge->kind != edge_kind) {
            continue;
        }

        CHECK(cur_inputs_amount < inputs_amount);
        input_node_ids[cur_inputs_amount] = edge->from_node;
        cur_inputs_amount++;
    }

    CHECK_TRACE(
        cur_inputs_amount == inputs_amount,
        "expected inputs amount %lu, instead got %lu",
        inputs_amount,
        cur_inputs_amount
    );

cleanup:
    return err;
}

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

static err_t next_node_id(cdfg_t* cdfg, cdfg_node_id_t* id) {
    err_t err = SUCCESS;

    CHECK_RETHROW(next_id(&cdfg->nodes_amount, CDFG_MAX_NODES, &id->id));

cleanup:
    return err;
}

static err_t next_edge_id(cdfg_t* cdfg, cdfg_edge_id_t* id) {
    err_t err = SUCCESS;

    CHECK_RETHROW(next_id(&cdfg->edges_amount, CDFG_MAX_EDGES, &id->id));

cleanup:
    return err;
}

static err_t next_op_state_slot_id(cdfg_op_state_t* op_state, cdfg_op_state_slot_id_t* id) {
    err_t err = SUCCESS;

    CHECK_RETHROW(next_id(&op_state->used_slots_amount, CDFG_OP_STATE_MAX_SLOTS, &id->id));

cleanup:
    return err;
}

static err_t
    make_op_state_slot(cdfg_op_state_t* op_state, pis_var_t var, cdfg_node_id_t value_node_id) {
    err_t err = SUCCESS;
    cdfg_op_state_slot_id_t slot_id = {.id = CDFG_ITEM_ID_INVALID};
    CHECK_RETHROW(next_op_state_slot_id(op_state, &slot_id));
    op_state->slots[slot_id.id] = (cdfg_op_state_slot_t) {
        .var = var,
        .value_node_id = value_node_id,
    };
cleanup:
    return err;
}

static err_t op_state_find_slot(
    const cdfg_op_state_t* op_state, pis_var_t var, cdfg_op_state_slot_id_t* out_slot_id
) {
    err_t err = SUCCESS;

    out_slot_id->id = CDFG_ITEM_ID_INVALID;

    for (size_t i = 0; i < op_state->used_slots_amount; i++) {
        const cdfg_op_state_slot_t* slot = &op_state->slots[i];
        if (slot->value_node_id.id == CDFG_ITEM_ID_INVALID) {
            // this slot is vacant.
            continue;
        }
        if (pis_vars_intersect(var, slot->var)) {
            // partially initialized nodes are not allowed in the CDFG.
            CHECK(pis_vars_equal(var, slot->var));

            out_slot_id->id = i;
        }
    }

cleanup:
    return err;
}

static err_t op_state_find_var_value(
    const cdfg_op_state_t* op_state, pis_var_t var, cdfg_node_id_t* out_node_id
) {
    err_t err = SUCCESS;

    cdfg_op_state_slot_id_t slot_id = {.id = CDFG_ITEM_ID_INVALID};
    CHECK_RETHROW(op_state_find_slot(op_state, var, &slot_id));
    if (slot_id.id == CDFG_ITEM_ID_INVALID) {
        out_node_id->id = CDFG_ITEM_ID_INVALID;
    } else {
        *out_node_id = op_state->slots[slot_id.id].value_node_id;
    }
cleanup:
    return err;
}

/// tries to find an existing immediate node with the given value in the cdfg.
/// returns the id of the found node, or `CDFG_ITEM_ID_INVALID` if no such node was found.
static cdfg_node_id_t find_imm_node(const cdfg_t* cdfg, u64 value) {
    for (size_t i = 0; i < cdfg->nodes_amount; i++) {
        const cdfg_node_t* node = &cdfg->node_storage[i];
        if (node->kind != CDFG_NODE_KIND_IMM) {
            continue;
        }
        if (node->content.imm.value == value) {
            return (cdfg_node_id_t) {.id = i};
        }
    }
    return (cdfg_node_id_t) {.id = CDFG_ITEM_ID_INVALID};
}

static cdfg_node_id_t find_var_node(const cdfg_t* cdfg, pis_region_t region) {
    for (size_t i = 0; i < cdfg->nodes_amount; i++) {
        const cdfg_node_t* node = &cdfg->node_storage[i];
        if (node->kind != CDFG_NODE_KIND_VAR) {
            continue;
        }
        if (pis_regions_equal(node->content.var.reg_region, region)) {
            return (cdfg_node_id_t) {.id = i};
        }
    }
    return (cdfg_node_id_t) {.id = CDFG_ITEM_ID_INVALID};
}

/// returns an immediate node with the given immediate value, either by creating one or by reusing
/// an existing one.
static err_t make_imm_node(cdfg_t* cdfg, u64 value, cdfg_node_id_t* out_node_id) {
    err_t err = SUCCESS;

    cdfg_node_id_t node_id = find_imm_node(cdfg, value);

    if (node_id.id == CDFG_ITEM_ID_INVALID) {
        // no existing node, create a new one.
        CHECK_RETHROW(next_node_id(cdfg, &node_id));

        cdfg->node_storage[node_id.id] = (cdfg_node_t) {
            .kind = CDFG_NODE_KIND_IMM,
            .content =
                {
                    .imm = {.value = value},
                },
        };
    }

    *out_node_id = node_id;

cleanup:
    return err;
}

static err_t make_edge(
    cdfg_t* cdfg,
    cdfg_edge_kind_t kind,
    cdfg_node_id_t from_node,
    cdfg_node_id_t to_node,
    u8 to_node_input_index
) {
    err_t err = SUCCESS;

    cdfg_edge_id_t edge_id = {.id = CDFG_ITEM_ID_INVALID};
    CHECK_RETHROW(next_edge_id(cdfg, &edge_id));

    // make sure that the value is in range of the bitfield.
    CHECK(to_node_input_index < (1 << 7));

    cdfg->edge_storage[edge_id.id] = (cdfg_edge_t) {
        .kind = kind,
        .to_node_input_index = to_node_input_index,
        .from_node = from_node,
        .to_node = to_node,
    };

cleanup:
    return err;
}

static err_t
    make_calc_node(cdfg_t* cdfg, cdfg_calculation_t calculation, cdfg_node_id_t* out_node_id) {
    err_t err = SUCCESS;

    cdfg_node_id_t node_id = {.id = CDFG_ITEM_ID_INVALID};
    CHECK_RETHROW(next_node_id(cdfg, &node_id));

    cdfg->node_storage[node_id.id] = (cdfg_node_t) {
        .kind = CDFG_NODE_KIND_CALC,
        .content =
            {
                .calc =
                    {
                        .calculation = calculation,
                    },
            },
    };

    *out_node_id = node_id;
cleanup:
    return err;
}

/// link a node which requires control flow into the control flow chain.
static err_t link_cf_node(cdfg_builder_t* builder, cdfg_node_id_t node_id) {
    err_t err = SUCCESS;

    CHECK_RETHROW(make_edge(
        &builder->cdfg,
        CDFG_EDGE_KIND_CONTROL_FLOW,
        builder->op_state.last_cf_node_id,
        node_id,
        0
    ));

    builder->op_state.last_cf_node_id = node_id;

cleanup:
    return err;
}

static err_t
    make_empty_node_of_kind(cdfg_t* cdfg, cdfg_node_kind_t kind, cdfg_node_id_t* out_node_id) {
    err_t err = SUCCESS;

    cdfg_node_id_t node_id = {.id = CDFG_ITEM_ID_INVALID};
    CHECK_RETHROW(next_node_id(cdfg, &node_id));

    cdfg->node_storage[node_id.id] = (cdfg_node_t) {
        .kind = kind,
        .content = {},
    };

    *out_node_id = node_id;
cleanup:
    return err;
}

static err_t make_store_node(cdfg_t* cdfg, cdfg_node_id_t* out_node_id) {
    err_t err = SUCCESS;

    CHECK_RETHROW(make_empty_node_of_kind(cdfg, CDFG_NODE_KIND_STORE, out_node_id));

cleanup:
    return err;
}

static err_t make_load_node(cdfg_t* cdfg, cdfg_node_id_t* out_node_id) {
    err_t err = SUCCESS;

    CHECK_RETHROW(make_empty_node_of_kind(cdfg, CDFG_NODE_KIND_LOAD, out_node_id));
cleanup:
    return err;
}

static err_t make_if_node(cdfg_t* cdfg, cdfg_node_id_t* out_node_id) {
    err_t err = SUCCESS;

    CHECK_RETHROW(make_empty_node_of_kind(cdfg, CDFG_NODE_KIND_IF, out_node_id));

cleanup:
    return err;
}

static err_t make_region_node(cdfg_t* cdfg, cdfg_node_id_t* out_node_id) {
    err_t err = SUCCESS;

    CHECK_RETHROW(make_empty_node_of_kind(cdfg, CDFG_NODE_KIND_REGION, out_node_id));

cleanup:
    return err;
}

static err_t make_phi_node(cdfg_t* cdfg, cdfg_node_id_t* out_node_id) {
    err_t err = SUCCESS;

    CHECK_RETHROW(make_empty_node_of_kind(cdfg, CDFG_NODE_KIND_PHI, out_node_id));

cleanup:
    return err;
}

static err_t do_if(cdfg_builder_t* builder, cdfg_node_id_t cond_node_id) {
    err_t err = SUCCESS;

    cdfg_node_id_t if_node_id = {.id = CDFG_ITEM_ID_INVALID};
    CHECK_RETHROW(make_if_node(&builder->cdfg, &if_node_id));

    CHECK_RETHROW(make_edge(&builder->cdfg, CDFG_EDGE_KIND_DATA_FLOW, cond_node_id, if_node_id, 0));

    CHECK_RETHROW(link_cf_node(builder, if_node_id));
cleanup:
    return err;
}

static err_t
    do_store(cdfg_builder_t* builder, cdfg_node_id_t addr_node_id, cdfg_node_id_t val_node_id) {
    err_t err = SUCCESS;

    cdfg_node_id_t store_node_id = {.id = CDFG_ITEM_ID_INVALID};
    CHECK_RETHROW(make_store_node(&builder->cdfg, &store_node_id));

    CHECK_RETHROW(
        make_edge(&builder->cdfg, CDFG_EDGE_KIND_DATA_FLOW, addr_node_id, store_node_id, 0)
    );
    CHECK_RETHROW(make_edge(&builder->cdfg, CDFG_EDGE_KIND_DATA_FLOW, val_node_id, store_node_id, 1)
    );

    CHECK_RETHROW(link_cf_node(builder, store_node_id));

cleanup:
    return err;
}

static err_t do_load(
    cdfg_builder_t* builder, cdfg_node_id_t addr_node_id, cdfg_node_id_t* out_loaded_val_node_id
) {
    err_t err = SUCCESS;

    cdfg_node_id_t load_node_id = {.id = CDFG_ITEM_ID_INVALID};
    CHECK_RETHROW(make_load_node(&builder->cdfg, &load_node_id));

    CHECK_RETHROW(make_edge(&builder->cdfg, CDFG_EDGE_KIND_DATA_FLOW, addr_node_id, load_node_id, 0)
    );

    CHECK_RETHROW(link_cf_node(builder, load_node_id));

    *out_loaded_val_node_id = load_node_id;

cleanup:
    return err;
}

static err_t make_entry_node(cdfg_t* cdfg, cdfg_node_id_t* out_node_id) {
    err_t err = SUCCESS;

    CHECK_RETHROW(make_empty_node_of_kind(cdfg, CDFG_NODE_KIND_ENTRY, out_node_id));

cleanup:
    return err;
}

static err_t
    make_block_entry_node(cdfg_t* cdfg, cfg_item_id_t block_id, cdfg_node_id_t* out_node_id) {
    err_t err = SUCCESS;

    cdfg_node_id_t node_id = {.id = CDFG_ITEM_ID_INVALID};
    CHECK_RETHROW(next_node_id(cdfg, &node_id));

    cdfg->node_storage[node_id.id] = (cdfg_node_t) {
        .kind = CDFG_NODE_KIND_BLOCK_ENTRY,
        .content =
            {
                .block_entry = {.block_id = block_id},
            },
    };

    *out_node_id = node_id;

cleanup:
    return err;
}

static err_t make_finish_node(cdfg_t* cdfg, cdfg_node_id_t* out_node_id) {
    err_t err = SUCCESS;

    CHECK_RETHROW(make_empty_node_of_kind(cdfg, CDFG_NODE_KIND_FINISH, out_node_id));

cleanup:
    return err;
}

static err_t find_existing_binop_node(
    cdfg_t* cdfg,
    cdfg_calculation_t calculation,
    cdfg_node_id_t lhs_node_id,
    cdfg_node_id_t rhs_node_id,
    cdfg_node_id_t* out_existing_binop_node_id
) {
    err_t err = SUCCESS;

    cdfg_node_id_t existing_binop_node_id = {.id = CDFG_ITEM_ID_INVALID};

    for (size_t i = 0; i < cdfg->nodes_amount; i++) {
        cdfg_node_t* cur_node = &cdfg->node_storage[i];
        cdfg_node_id_t cur_node_id = {.id = i};

        if (cur_node->kind != CDFG_NODE_KIND_CALC) {
            continue;
        }

        if (cur_node->content.calc.calculation != calculation) {
            continue;
        }

        cdfg_node_id_t inputs[2] = {{.id = CDFG_ITEM_ID_INVALID}, {.id = CDFG_ITEM_ID_INVALID}};
        CHECK_RETHROW(find_node_inputs(cdfg, cur_node_id, CDFG_EDGE_KIND_DATA_FLOW, inputs, 2));

        if ((inputs[0].id == lhs_node_id.id && inputs[1].id == rhs_node_id.id) ||
            (inputs[1].id == lhs_node_id.id && inputs[0].id == rhs_node_id.id)) {
            // found an exact match
            existing_binop_node_id.id = i;
            break;
        }
    }

    *out_existing_binop_node_id = existing_binop_node_id;
cleanup:
    return err;
}

static err_t make_binop_node(
    cdfg_t* cdfg,
    cdfg_calculation_t calculation,
    cdfg_node_id_t lhs_node_id,
    cdfg_node_id_t rhs_node_id,
    cdfg_node_id_t* out_binop_node_id
) {
    err_t err = SUCCESS;

    cdfg_node_id_t existing_node_id = {.id = CDFG_ITEM_ID_INVALID};
    CHECK_RETHROW(
        find_existing_binop_node(cdfg, calculation, lhs_node_id, rhs_node_id, &existing_node_id)
    );
    if (existing_node_id.id != CDFG_ITEM_ID_INVALID) {
        // found an existing node, use it.
        *out_binop_node_id = existing_node_id;
        SUCCESS_CLEANUP();
    }

    cdfg_node_id_t node_id = {.id = CDFG_ITEM_ID_INVALID};
    CHECK_RETHROW(make_calc_node(cdfg, calculation, &node_id));

    CHECK_RETHROW(make_edge(cdfg, CDFG_EDGE_KIND_DATA_FLOW, lhs_node_id, node_id, 0));
    CHECK_RETHROW(make_edge(cdfg, CDFG_EDGE_KIND_DATA_FLOW, rhs_node_id, node_id, 1));

    *out_binop_node_id = node_id;
cleanup:
    return err;
}

static err_t make_unary_op_node(
    cdfg_t* cdfg,
    cdfg_calculation_t calculation,
    cdfg_node_id_t input_node_id,
    cdfg_node_id_t* out_binop_node_id
) {
    err_t err = SUCCESS;

    cdfg_node_id_t node_id = {.id = CDFG_ITEM_ID_INVALID};
    CHECK_RETHROW(make_calc_node(cdfg, calculation, &node_id));

    CHECK_RETHROW(make_edge(cdfg, CDFG_EDGE_KIND_DATA_FLOW, input_node_id, node_id, 0));

    *out_binop_node_id = node_id;
cleanup:
    return err;
}

static err_t mark_block_final_value(
    cdfg_t* cdfg, cfg_item_id_t block_id, pis_var_t var, cdfg_node_id_t final_value
) {
    err_t err = SUCCESS;

    // only regs are allowed here
    CHECK(var.space == PIS_VAR_SPACE_REG);

    cdfg_node_id_t node_id = {.id = CDFG_ITEM_ID_INVALID};
    CHECK_RETHROW(next_node_id(cdfg, &node_id));

    cdfg->node_storage[node_id.id] = (cdfg_node_t) {
        .kind = CDFG_NODE_KIND_BLOCK_FINAL_VALUE,
        .content =
            {
                .block_final_value =
                    {
                        .block_id = block_id,
                        .reg_region = pis_var_region(var),
                    },
            },
    };

    CHECK_RETHROW(make_edge(cdfg, CDFG_EDGE_KIND_DATA_FLOW, final_value, node_id, 0));

cleanup:
    return err;
}

static err_t make_var_node(cdfg_t* cdfg, pis_var_t var, cdfg_node_id_t* out_node_id) {
    err_t err = SUCCESS;

    // variable nodes are only for register operands
    CHECK(var.space == PIS_VAR_SPACE_REG);

    pis_region_t region = pis_var_region(var);
    cdfg_node_id_t node_id = find_var_node(cdfg, region);

    if (node_id.id == CDFG_ITEM_ID_INVALID) {
        // no existing node, create a new one.
        CHECK_RETHROW(next_node_id(cdfg, &node_id));
        cdfg->node_storage[node_id.id] = (cdfg_node_t) {
            .kind = CDFG_NODE_KIND_VAR,
            .content =
                {
                    .var = {.reg_region = region},
                },
        };
    }

    *out_node_id = node_id;
cleanup:
    return err;
}

static err_t find_block_var_node(
    const cdfg_t* cdfg, cfg_item_id_t block_id, pis_region_t region, cdfg_node_id_t* out_node_id
) {
    err_t err = SUCCESS;

    cdfg_node_id_t found_node_id = {.id = CDFG_ITEM_ID_INVALID};

    for (size_t i = 0; i < cdfg->nodes_amount; i++) {
        const cdfg_node_t* node = &cdfg->node_storage[i];
        if (node->kind != CDFG_NODE_KIND_BLOCK_VAR) {
            continue;
        }
        if (node->content.block_var.block_id == block_id &&
            pis_regions_intersect(node->content.block_var.reg_region, region)) {
            CHECK(pis_regions_equal(node->content.block_var.reg_region, region));

            CHECK(found_node_id.id == CDFG_ITEM_ID_INVALID);
            found_node_id.id = i;
        }
    }

    *out_node_id = found_node_id;

cleanup:
    return err;
}

static err_t make_block_var_node(
    cdfg_t* cdfg, cfg_item_id_t block_id, pis_var_t var, cdfg_node_id_t* out_node_id
) {
    err_t err = SUCCESS;

    // block var nodes are only for register operands
    CHECK(var.space == PIS_VAR_SPACE_REG);

    pis_region_t region = pis_var_region(var);
    cdfg_node_id_t node_id = {.id = CDFG_ITEM_ID_INVALID};
    CHECK_RETHROW(find_block_var_node(cdfg, block_id, region, &node_id));

    if (node_id.id == CDFG_ITEM_ID_INVALID) {
        // no existing node, create a new one.
        CHECK_RETHROW(next_node_id(cdfg, &node_id));
        cdfg->node_storage[node_id.id] = (cdfg_node_t) {
            .kind = CDFG_NODE_KIND_BLOCK_VAR,
            .content =
                {
                    .block_var =
                        {
                            .block_id = block_id,
                            .reg_region = region,
                        },
                },
        };
    }

    *out_node_id = node_id;
cleanup:
    return err;
}

static err_t
    read_var_operand_direct(cdfg_builder_t* builder, pis_var_t var, cdfg_node_id_t* out_node_id) {
    err_t err = SUCCESS;

    cdfg_node_id_t existing_node_id = {.id = CDFG_ITEM_ID_INVALID};
    op_state_find_var_value(&builder->op_state, var, &existing_node_id);

    if (existing_node_id.id == CDFG_ITEM_ID_INVALID) {
        // the variable operand is uninitialized.

        // only register operands are allowed to be read when uninitialized.
        CHECK(var.space == PIS_VAR_SPACE_REG);

        // initialize it to a new variable node.

        // first, create the block var node
        cdfg_node_id_t node_id = {.id = CDFG_ITEM_ID_INVALID};
        CHECK(builder->cur_block_id != CFG_ITEM_ID_INVALID);
        CHECK_RETHROW(make_block_var_node(&builder->cdfg, builder->cur_block_id, var, &node_id));

        // now add a slot in the op state to point to it
        CHECK_RETHROW(make_op_state_slot(&builder->op_state, var, node_id));

        *out_node_id = node_id;
    } else {
        // the variable operand is initialized, use its value.
        *out_node_id = existing_node_id;
    }
cleanup:
    return err;
}

static err_t read_reg_operand_sub_region(
    cdfg_builder_t* builder,
    pis_region_t region,
    pis_region_t enclosing_region,
    cdfg_node_id_t* out_node_id
) {
    err_t err = SUCCESS;


    // read the enclosing region value
    pis_var_t enclosing_var = {
        .offset = enclosing_region.offset,
        .size = enclosing_region.size,
        .space = PIS_VAR_SPACE_REG,
    };
    cdfg_node_id_t enclosing_value_node = {.id = CDFG_ITEM_ID_INVALID};
    CHECK_RETHROW(read_var_operand_direct(builder, enclosing_var, &enclosing_value_node));

    // shift the value to put it at the right offset in the GPR
    size_t shift_bytes = region.offset - enclosing_region.offset;
    size_t shift_bits = shift_bytes * 8;
    cdfg_node_id_t shifted_value_node;
    if (shift_bytes == 0) {
        // no shift needed, use the unshifted value
        shifted_value_node = enclosing_value_node;
    } else {
        // shift needed, shift the value accordingly
        cdfg_node_id_t shift_bits_node = {.id = CDFG_ITEM_ID_INVALID};
        CHECK_RETHROW(make_imm_node(&builder->cdfg, shift_bits, &shift_bits_node));

        CHECK_RETHROW(make_binop_node(
            &builder->cdfg,
            CDFG_CALCULATION_SHIFT_RIGHT,
            enclosing_value_node,
            shift_bits_node,
            &shifted_value_node
        ));
    }

    u64 mask = pis_size_max_unsigned_value(region.size);

    // mask the shifted enclosing value.
    cdfg_node_id_t mask_node = {.id = CDFG_ITEM_ID_INVALID};
    CHECK_RETHROW(make_imm_node(&builder->cdfg, mask, &mask_node));

    cdfg_node_id_t final_value_node = {.id = CDFG_ITEM_ID_INVALID};
    CHECK_RETHROW(make_binop_node(
        &builder->cdfg,
        CDFG_CALCULATION_AND,
        shifted_value_node,
        mask_node,
        &final_value_node
    ));

    *out_node_id = final_value_node;

cleanup:
    return err;
}

static err_t read_reg_operand(cdfg_builder_t* builder, pis_var_t var, cdfg_node_id_t* out_node_id) {
    err_t err = SUCCESS;

    // register operands are allowed to be accessed using different operand sizes and offsets,
    // even inside of a single register. so, we must do read/write merging manually according to the
    // operand map that we built before processing the code.

    // find the container region of this register in the register operand map. all reads and writes
    // must be performed using that container region.
    pis_region_t region = pis_var_region(var);
    pis_region_t enclosing_region = {};
    bool found_enclosing_region = false;
    CHECK_RETHROW(cdfg_op_map_largest_enclosing(
        &builder->reg_op_map,
        region,
        &found_enclosing_region,
        &enclosing_region
    ));

    // all registers should be in the register operand map.
    CHECK(found_enclosing_region);

    if (pis_regions_equal(region, enclosing_region)) {
        // the region is standalone. read it directly.
        CHECK_RETHROW(read_var_operand_direct(builder, var, out_node_id));
    } else {
        // the region is a sub-region of a larger region
        CHECK_RETHROW(read_reg_operand_sub_region(builder, region, enclosing_region, out_node_id));
    }

cleanup:
    return err;
}

static err_t read_var_operand(cdfg_builder_t* builder, pis_var_t var, cdfg_node_id_t* out_node_id) {
    err_t err = SUCCESS;

    switch (var.space) {
        case PIS_VAR_SPACE_REG:
            CHECK_RETHROW(read_reg_operand(builder, var, out_node_id));
            break;
        case PIS_VAR_SPACE_TMP:
            CHECK_RETHROW(read_var_operand_direct(builder, var, out_node_id));
            break;
    }

cleanup:
    return err;
}

/// reads the given operand according to the current op state and returns the id of a node which
/// represents the value of the operand.
static err_t
    read_operand(cdfg_builder_t* builder, const pis_op_t* op, cdfg_node_id_t* out_node_id) {
    err_t err = SUCCESS;
    switch (op->kind) {
        case PIS_OP_KIND_IMM:
            CHECK_RETHROW(make_imm_node(&builder->cdfg, op->v.imm.value, out_node_id));
            break;
        case PIS_OP_KIND_VAR:
            CHECK_RETHROW(read_var_operand(builder, pis_op_var(op), out_node_id));
            break;
        case PIS_OP_KIND_RAM:
            // ram operands are only used in jump instructions, and can't be read directly. reading
            // from ram is done using the load instruction.
            UNREACHABLE();
            break;
        default:
            UNREACHABLE();
            break;
    }
cleanup:
    return err;
}

static err_t
    write_var_operand_direct(cdfg_builder_t* builder, pis_var_t var, cdfg_node_id_t value_node_id) {
    err_t err = SUCCESS;

    cdfg_op_state_slot_id_t existing_slot_id = {.id = CDFG_ITEM_ID_INVALID};
    CHECK_RETHROW(op_state_find_slot(&builder->op_state, var, &existing_slot_id));

    if (existing_slot_id.id != CDFG_ITEM_ID_INVALID) {
        // found existing slot. overwrite its value with the new value.
        builder->op_state.slots[existing_slot_id.id].value_node_id = value_node_id;
    } else {
        // operand is uninitialized. just add a new slot which contains the new value for this
        // operand.
        CHECK_RETHROW(make_op_state_slot(&builder->op_state, var, value_node_id));
    }

cleanup:
    return err;
}

static err_t write_reg_operand_sub_region(
    cdfg_builder_t* builder,
    pis_region_t region,
    pis_region_t enclosing_region,
    cdfg_node_id_t value_node_id
) {
    err_t err = SUCCESS;

    // read the enclosing region value
    pis_var_t enclosing_var = {
        .offset = enclosing_region.offset,
        .size = enclosing_region.size,
        .space = PIS_VAR_SPACE_REG,
    };
    cdfg_node_id_t enclosing_value_node = {.id = CDFG_ITEM_ID_INVALID};
    CHECK_RETHROW(read_var_operand_direct(builder, enclosing_var, &enclosing_value_node));

    // shift the value to put it at the right offset in the GPR
    size_t shift_bytes = region.offset - enclosing_region.offset;
    size_t shift_bits = shift_bytes * 8;
    cdfg_node_id_t shifted_value_node;
    if (shift_bytes == 0) {
        // no shift needed, use the unshifted value
        shifted_value_node = value_node_id;
    } else {
        // shift needed, shift the value accordingly
        cdfg_node_id_t shift_bits_node = {.id = CDFG_ITEM_ID_INVALID};
        CHECK_RETHROW(make_imm_node(&builder->cdfg, shift_bits, &shift_bits_node));

        CHECK_RETHROW(make_binop_node(
            &builder->cdfg,
            CDFG_CALCULATION_SHIFT_LEFT,
            value_node_id,
            shift_bits_node,
            &shifted_value_node
        ));
    }

    // calculate the mask to be used on the enclosing value to remove the relevant bits that will be
    // set by the shifted value.
    u64 value_bits_mask = pis_size_max_unsigned_value(region.size) << shift_bits;
    u64 mask = (~value_bits_mask) & pis_size_max_unsigned_value(enclosing_region.size);

    // mask the enclosing value.
    cdfg_node_id_t mask_node = {.id = CDFG_ITEM_ID_INVALID};
    CHECK_RETHROW(make_imm_node(&builder->cdfg, mask, &mask_node));

    cdfg_node_id_t masked_enclosing_value_node = {.id = CDFG_ITEM_ID_INVALID};
    CHECK_RETHROW(make_binop_node(
        &builder->cdfg,
        CDFG_CALCULATION_AND,
        enclosing_value_node,
        mask_node,
        &masked_enclosing_value_node
    ));

    // OR the shifted value into the masked enclosing value to get the final result
    cdfg_node_id_t final_value_node = {.id = CDFG_ITEM_ID_INVALID};
    CHECK_RETHROW(make_binop_node(
        &builder->cdfg,
        CDFG_CALCULATION_OR,
        masked_enclosing_value_node,
        shifted_value_node,
        &final_value_node
    ));

    // write the final value to the enclosing var
    CHECK_RETHROW(write_var_operand_direct(builder, enclosing_var, final_value_node));
cleanup:
    return err;
}

static err_t
    write_reg_operand(cdfg_builder_t* builder, pis_var_t var, cdfg_node_id_t value_node_id) {
    err_t err = SUCCESS;

    // register operands are allowed to be accessed using different operand sizes and offsets,
    // even inside of a single register. so, we must do read/write merging manually according to the
    // operand map that we built before processing the code.

    // find the container region of this register in the register operand map. all reads and writes
    // must be performed using that container region.
    pis_region_t region = pis_var_region(var);
    pis_region_t enclosing_region = {};
    bool found_enclosing_region = false;
    CHECK_RETHROW(cdfg_op_map_largest_enclosing(
        &builder->reg_op_map,
        region,
        &found_enclosing_region,
        &enclosing_region
    ));

    // all registers should be in the register operand map.
    CHECK(found_enclosing_region);

    if (pis_regions_equal(region, enclosing_region)) {
        // the region is standalone. write to it directly.
        CHECK_RETHROW(write_var_operand_direct(builder, var, value_node_id));
    } else {
        // the region is a sub-region of a larger region
        CHECK_RETHROW(write_reg_operand_sub_region(builder, region, enclosing_region, value_node_id)
        );
    }

cleanup:
    return err;
}

static err_t
    write_var_operand(cdfg_builder_t* builder, pis_var_t var, cdfg_node_id_t value_node_id) {
    err_t err = SUCCESS;

    switch (var.space) {
        case PIS_VAR_SPACE_REG:
            CHECK_RETHROW(write_reg_operand(builder, var, value_node_id));
            break;
        case PIS_VAR_SPACE_TMP:
            CHECK_RETHROW(write_var_operand_direct(builder, var, value_node_id));
            break;
    }

cleanup:
    return err;
}

/// writes the given operand to the current op state.
static err_t
    write_operand(cdfg_builder_t* builder, const pis_op_t* op, cdfg_node_id_t value_node_id) {
    err_t err = SUCCESS;
    switch (op->kind) {
        case PIS_OP_KIND_VAR:
            CHECK_RETHROW(write_var_operand(builder, pis_op_var(op), value_node_id));
            break;
        case PIS_OP_KIND_IMM:
            // can't write to const operands.
            UNREACHABLE();
            break;
        case PIS_OP_KIND_RAM:
            // ram operands are only used in jump instructions, and can't be written to directly.
            // writing to ram is done using the store instruction.
            UNREACHABLE();
            break;
        default:
            UNREACHABLE();
            break;
    }
cleanup:
    return err;
}

static err_t opcode_handler_binop(
    cdfg_builder_t* builder, const pis_insn_t* insn, cdfg_calculation_t calculation
) {
    err_t err = SUCCESS;
    CHECK_CODE(insn->operands_amount == 3, PIS_ERR_OPCODE_WRONG_OPERANDS_AMOUNT);

    cdfg_node_id_t lhs_node_id = {.id = CDFG_ITEM_ID_INVALID};
    CHECK_RETHROW(read_operand(builder, &insn->operands[1], &lhs_node_id));

    cdfg_node_id_t rhs_node_id = {.id = CDFG_ITEM_ID_INVALID};
    CHECK_RETHROW(read_operand(builder, &insn->operands[2], &rhs_node_id));

    cdfg_node_id_t result_node_id = {.id = CDFG_ITEM_ID_INVALID};
    CHECK_RETHROW(
        make_binop_node(&builder->cdfg, calculation, lhs_node_id, rhs_node_id, &result_node_id)
    );

    CHECK_RETHROW(write_operand(builder, &insn->operands[0], result_node_id));
cleanup:
    return err;
}

static err_t opcode_handler_unary_op(
    cdfg_builder_t* builder, const pis_insn_t* insn, cdfg_calculation_t calculation
) {
    err_t err = SUCCESS;
    CHECK_CODE(insn->operands_amount == 2, PIS_ERR_OPCODE_WRONG_OPERANDS_AMOUNT);

    cdfg_node_id_t input_node_id = {.id = CDFG_ITEM_ID_INVALID};
    CHECK_RETHROW(read_operand(builder, &insn->operands[1], &input_node_id));

    cdfg_node_id_t result_node_id = {.id = CDFG_ITEM_ID_INVALID};
    CHECK_RETHROW(make_unary_op_node(&builder->cdfg, calculation, input_node_id, &result_node_id));

    CHECK_RETHROW(write_operand(builder, &insn->operands[0], result_node_id));
cleanup:
    return err;
}

/// perform a move instruction without checking the operands.
static err_t do_move_nocheck(cdfg_builder_t* builder, const pis_insn_t* insn) {
    err_t err = SUCCESS;

    cdfg_node_id_t src_node_id = {.id = CDFG_ITEM_ID_INVALID};
    CHECK_RETHROW(read_operand(builder, &insn->operands[1], &src_node_id));

    CHECK_RETHROW(write_operand(builder, &insn->operands[0], src_node_id));
cleanup:
    return err;
}

static err_t opcode_handler_move(cdfg_builder_t* builder, const pis_insn_t* insn) {
    err_t err = SUCCESS;
    CHECK_CODE(insn->operands_amount == 2, PIS_ERR_OPCODE_WRONG_OPERANDS_AMOUNT);

    CHECK_RETHROW(do_move_nocheck(builder, insn));
cleanup:
    return err;
}

static err_t opcode_handler_zero_extend(cdfg_builder_t* builder, const pis_insn_t* insn) {
    err_t err = SUCCESS;
    CHECK_CODE(insn->operands_amount == 2, PIS_ERR_OPCODE_WRONG_OPERANDS_AMOUNT);

    CHECK_RETHROW(do_move_nocheck(builder, insn));
cleanup:
    return err;
}

static err_t opcode_handler_get_low_bits(cdfg_builder_t* builder, const pis_insn_t* insn) {
    err_t err = SUCCESS;
    CHECK_CODE(insn->operands_amount == 2, PIS_ERR_OPCODE_WRONG_OPERANDS_AMOUNT);

    // fetching the low bits of a value is like masking it

    cdfg_node_id_t src_node_id = {.id = CDFG_ITEM_ID_INVALID};
    CHECK_RETHROW(read_operand(builder, &insn->operands[1], &src_node_id));

    cdfg_node_id_t mask_node_id = {.id = CDFG_ITEM_ID_INVALID};
    CHECK_RETHROW(make_imm_node(
        &builder->cdfg,
        pis_size_max_unsigned_value(insn->operands[0].size),
        &mask_node_id
    ));

    cdfg_node_id_t masked_src_node_id = {.id = CDFG_ITEM_ID_INVALID};
    CHECK_RETHROW(make_binop_node(
        &builder->cdfg,
        CDFG_CALCULATION_AND,
        src_node_id,
        mask_node_id,
        &masked_src_node_id
    ));

    CHECK_RETHROW(write_operand(builder, &insn->operands[0], masked_src_node_id));
cleanup:
    return err;
}

static err_t opcode_handler_store(cdfg_builder_t* builder, const pis_insn_t* insn) {
    err_t err = SUCCESS;
    CHECK_CODE(insn->operands_amount == 2, PIS_ERR_OPCODE_WRONG_OPERANDS_AMOUNT);

    cdfg_node_id_t addr_node_id = {.id = CDFG_ITEM_ID_INVALID};
    CHECK_RETHROW(read_operand(builder, &insn->operands[0], &addr_node_id));

    cdfg_node_id_t val_node_id = {.id = CDFG_ITEM_ID_INVALID};
    CHECK_RETHROW(read_operand(builder, &insn->operands[1], &val_node_id));

    CHECK_RETHROW(do_store(builder, addr_node_id, val_node_id));

cleanup:
    return err;
}

static err_t opcode_handler_load(cdfg_builder_t* builder, const pis_insn_t* insn) {
    err_t err = SUCCESS;
    CHECK_CODE(insn->operands_amount == 2, PIS_ERR_OPCODE_WRONG_OPERANDS_AMOUNT);

    cdfg_node_id_t addr_node_id = {.id = CDFG_ITEM_ID_INVALID};
    CHECK_RETHROW(read_operand(builder, &insn->operands[1], &addr_node_id));

    cdfg_node_id_t loaded_val_node_id = {.id = CDFG_ITEM_ID_INVALID};
    CHECK_RETHROW(do_load(builder, addr_node_id, &loaded_val_node_id));

    CHECK_RETHROW(write_operand(builder, &insn->operands[0], loaded_val_node_id));

cleanup:
    return err;
}

static err_t opcode_handler_add(cdfg_builder_t* builder, const pis_insn_t* insn) {
    err_t err = SUCCESS;
    CHECK_RETHROW(opcode_handler_binop(builder, insn, CDFG_CALCULATION_ADD));
cleanup:
    return err;
}

static err_t opcode_handler_unsigned_mul(cdfg_builder_t* builder, const pis_insn_t* insn) {
    err_t err = SUCCESS;
    CHECK_RETHROW(opcode_handler_binop(builder, insn, CDFG_CALCULATION_UNSIGNED_MUL));
cleanup:
    return err;
}

static err_t opcode_handler_signed_mul(cdfg_builder_t* builder, const pis_insn_t* insn) {
    err_t err = SUCCESS;
    CHECK_RETHROW(opcode_handler_binop(builder, insn, CDFG_CALCULATION_SIGNED_MUL));
cleanup:
    return err;
}

static err_t opcode_handler_sub(cdfg_builder_t* builder, const pis_insn_t* insn) {
    err_t err = SUCCESS;
    CHECK_RETHROW(opcode_handler_binop(builder, insn, CDFG_CALCULATION_SUB));
cleanup:
    return err;
}

static err_t opcode_handler_xor(cdfg_builder_t* builder, const pis_insn_t* insn) {
    err_t err = SUCCESS;
    CHECK_RETHROW(opcode_handler_binop(builder, insn, CDFG_CALCULATION_XOR));
cleanup:
    return err;
}

static err_t opcode_handler_or(cdfg_builder_t* builder, const pis_insn_t* insn) {
    err_t err = SUCCESS;
    CHECK_RETHROW(opcode_handler_binop(builder, insn, CDFG_CALCULATION_OR));
cleanup:
    return err;
}

static err_t opcode_handler_and(cdfg_builder_t* builder, const pis_insn_t* insn) {
    err_t err = SUCCESS;
    CHECK_RETHROW(opcode_handler_binop(builder, insn, CDFG_CALCULATION_AND));
cleanup:
    return err;
}

static err_t opcode_handler_shift_right(cdfg_builder_t* builder, const pis_insn_t* insn) {
    err_t err = SUCCESS;
    CHECK_RETHROW(opcode_handler_binop(builder, insn, CDFG_CALCULATION_SHIFT_RIGHT));
cleanup:
    return err;
}

static err_t opcode_handler_shift_right_signed(cdfg_builder_t* builder, const pis_insn_t* insn) {
    err_t err = SUCCESS;
    CHECK_RETHROW(opcode_handler_binop(builder, insn, CDFG_CALCULATION_SHIFT_RIGHT_SIGNED));
cleanup:
    return err;
}

static err_t opcode_handler_shift_left(cdfg_builder_t* builder, const pis_insn_t* insn) {
    err_t err = SUCCESS;
    CHECK_RETHROW(opcode_handler_binop(builder, insn, CDFG_CALCULATION_SHIFT_LEFT));
cleanup:
    return err;
}

static err_t opcode_handler_unsigned_less_than(cdfg_builder_t* builder, const pis_insn_t* insn) {
    err_t err = SUCCESS;
    CHECK_RETHROW(opcode_handler_binop(builder, insn, CDFG_CALCULATION_UNSIGNED_LESS_THAN));
cleanup:
    return err;
}

static err_t opcode_handler_signed_mul_overflow(cdfg_builder_t* builder, const pis_insn_t* insn) {
    err_t err = SUCCESS;
    CHECK_RETHROW(opcode_handler_binop(builder, insn, CDFG_CALCULATION_SIGNED_MUL_OVERFLOW));
cleanup:
    return err;
}

static err_t opcode_handler_signed_carry(cdfg_builder_t* builder, const pis_insn_t* insn) {
    err_t err = SUCCESS;
    CHECK_RETHROW(opcode_handler_binop(builder, insn, CDFG_CALCULATION_SIGNED_CARRY));
cleanup:
    return err;
}

static err_t opcode_handler_unsigned_carry(cdfg_builder_t* builder, const pis_insn_t* insn) {
    err_t err = SUCCESS;
    CHECK_RETHROW(opcode_handler_binop(builder, insn, CDFG_CALCULATION_UNSIGNED_CARRY));
cleanup:
    return err;
}

static err_t opcode_handler_equals(cdfg_builder_t* builder, const pis_insn_t* insn) {
    err_t err = SUCCESS;
    CHECK_RETHROW(opcode_handler_binop(builder, insn, CDFG_CALCULATION_EQUALS));
cleanup:
    return err;
}

static err_t opcode_handler_signed_less_than(cdfg_builder_t* builder, const pis_insn_t* insn) {
    err_t err = SUCCESS;
    CHECK_RETHROW(opcode_handler_binop(builder, insn, CDFG_CALCULATION_SIGNED_LESS_THAN));
cleanup:
    return err;
}

static err_t opcode_handler_parity(cdfg_builder_t* builder, const pis_insn_t* insn) {
    err_t err = SUCCESS;
    CHECK_RETHROW(opcode_handler_unary_op(builder, insn, CDFG_CALCULATION_PARITY));
cleanup:
    return err;
}

static err_t opcode_handler_neg(cdfg_builder_t* builder, const pis_insn_t* insn) {
    err_t err = SUCCESS;
    CHECK_RETHROW(opcode_handler_unary_op(builder, insn, CDFG_CALCULATION_NEG));
cleanup:
    return err;
}

static err_t opcode_handler_not(cdfg_builder_t* builder, const pis_insn_t* insn) {
    err_t err = SUCCESS;
    CHECK_RETHROW(opcode_handler_unary_op(builder, insn, CDFG_CALCULATION_NOT));
cleanup:
    return err;
}

static err_t opcode_handler_cond_negate(cdfg_builder_t* builder, const pis_insn_t* insn) {
    err_t err = SUCCESS;
    CHECK_RETHROW(opcode_handler_unary_op(builder, insn, CDFG_CALCULATION_COND_NEGATE));
cleanup:
    return err;
}

static err_t opcode_handler_jmp_cond(cdfg_builder_t* builder, const pis_insn_t* insn) {
    err_t err = SUCCESS;

    CHECK_CODE(insn->operands_amount == 2, PIS_ERR_OPCODE_WRONG_OPERANDS_AMOUNT);

    cdfg_node_id_t cond_node_id = {.id = CDFG_ITEM_ID_INVALID};
    CHECK_RETHROW(read_operand(builder, &insn->operands[1], &cond_node_id));

    CHECK_RETHROW(do_if(builder, cond_node_id));

cleanup:
    return err;
}

static err_t opcode_handler_ret(cdfg_builder_t* builder, const pis_insn_t* insn) {
    err_t err = SUCCESS;

    UNUSED(insn);

    cdfg_node_id_t retval_node_id = {.id = CDFG_ITEM_ID_INVALID};
    pis_op_t return_value = pis_reg_to_op(*builder->cfg->arch->return_value);
    CHECK_RETHROW(read_operand(builder, &return_value, &retval_node_id));

    cdfg_node_id_t finish_node_id = {.id = CDFG_ITEM_ID_INVALID};
    CHECK_RETHROW(make_finish_node(&builder->cdfg, &finish_node_id));

    CHECK_RETHROW(link_cf_node(builder, finish_node_id));

    CHECK_RETHROW(
        make_edge(&builder->cdfg, CDFG_EDGE_KIND_DATA_FLOW, retval_node_id, finish_node_id, 0)
    );

cleanup:
    return err;
}

static err_t opcode_handler_jmp(cdfg_builder_t* builder, const pis_insn_t* insn) {
    UNUSED(builder);
    UNUSED(insn);

    return SUCCESS;
}

static opcode_handler_t g_opcode_handlers_table[PIS_OPCODES_AMOUNT] = {
    [PIS_OPCODE_ADD] = opcode_handler_add,
    [PIS_OPCODE_AND] = opcode_handler_and,
    [PIS_OPCODE_SUB] = opcode_handler_sub,
    [PIS_OPCODE_XOR] = opcode_handler_xor,
    [PIS_OPCODE_OR] = opcode_handler_or,
    [PIS_OPCODE_UNSIGNED_MUL] = opcode_handler_unsigned_mul,
    [PIS_OPCODE_SIGNED_MUL] = opcode_handler_signed_mul,
    [PIS_OPCODE_SIGNED_MUL_OVERFLOW] = opcode_handler_signed_mul_overflow,
    [PIS_OPCODE_SIGNED_CARRY] = opcode_handler_signed_carry,
    [PIS_OPCODE_UNSIGNED_CARRY] = opcode_handler_unsigned_carry,
    [PIS_OPCODE_SHIFT_RIGHT] = opcode_handler_shift_right,
    [PIS_OPCODE_SHIFT_RIGHT_SIGNED] = opcode_handler_shift_right_signed,
    [PIS_OPCODE_SHIFT_LEFT] = opcode_handler_shift_left,
    [PIS_OPCODE_MOVE] = opcode_handler_move,
    [PIS_OPCODE_STORE] = opcode_handler_store,
    [PIS_OPCODE_LOAD] = opcode_handler_load,
    [PIS_OPCODE_ZERO_EXTEND] = opcode_handler_zero_extend,
    [PIS_OPCODE_GET_LOW_BITS] = opcode_handler_get_low_bits,
    [PIS_OPCODE_UNSIGNED_LESS_THAN] = opcode_handler_unsigned_less_than,
    [PIS_OPCODE_SIGNED_LESS_THAN] = opcode_handler_signed_less_than,
    [PIS_OPCODE_PARITY] = opcode_handler_parity,
    [PIS_OPCODE_EQUALS] = opcode_handler_equals,
    [PIS_OPCODE_JMP_COND] = opcode_handler_jmp_cond,
    [PIS_OPCODE_NEG] = opcode_handler_neg,
    [PIS_OPCODE_NOT] = opcode_handler_not,
    [PIS_OPCODE_COND_NEGATE] = opcode_handler_cond_negate,
    [PIS_OPCODE_JMP_RET] = opcode_handler_ret,
    [PIS_OPCODE_JMP] = opcode_handler_jmp,
};

static err_t process_insn(cdfg_builder_t* builder, const pis_insn_t* insn) {
    err_t err = SUCCESS;
    opcode_handler_t handler = g_opcode_handlers_table[insn->opcode];
    CHECK_TRACE_CODE(
        handler != NULL,
        PIS_ERR_UNSUPPORTED_INSN,
        "CDFG does not support pis opcode %s",
        pis_opcode_to_str(insn->opcode)
    );
    CHECK_RETHROW(handler(builder, insn));
cleanup:
    return err;
}

/// invalidate all slots which represent tmp operands.
static void invalidate_tmps(cdfg_op_state_t* op_state) {
    for (size_t i = 0; i < op_state->used_slots_amount; i++) {
        cdfg_op_state_slot_t* slot = &op_state->slots[i];
        if (slot->value_node_id.id == CDFG_ITEM_ID_INVALID) {
            // this slot is vacant.
            continue;
        }
        if (slot->var.space == PIS_VAR_SPACE_TMP) {
            // invalidate the slot
            slot->value_node_id.id = CDFG_ITEM_ID_INVALID;
        }
    }
}

static err_t process_block(cdfg_builder_t* builder, cfg_item_id_t block_id) {
    err_t err = SUCCESS;


    builder->cur_block_id = block_id;

    const cfg_block_t* block = &builder->cfg->block_storage[block_id];
    CHECK(block->units_amount > 0);

    const cfg_unit_t* block_units = &builder->cfg->unit_storage[block->first_unit_id];
    for (size_t unit_idx = 0; unit_idx < block->units_amount; unit_idx++) {
        const cfg_unit_t* unit = &block_units[unit_idx];
        const pis_insn_t* unit_insns = &builder->cfg->insn_storage[unit->first_insn_id];
        for (size_t insn_idx = 0; insn_idx < unit->insns_amount; insn_idx++) {
            const pis_insn_t* insn = &unit_insns[insn_idx];
            CHECK_RETHROW(process_insn(builder, insn));
        }
        // invalidate all tmps. tmps are only valid for the unit in which they were defined.
        invalidate_tmps(&builder->op_state);
    }

    // finished processing all the code in the block. we now have the final state of the block.
    // create nodes to represent each of the final values of the registers at the end of this block.
    for (size_t i = 0; i > builder->op_state.used_slots_amount; i++) {
        cdfg_op_state_slot_t* slot = &builder->op_state.slots[i];
        if (slot->value_node_id.id == CDFG_ITEM_ID_INVALID) {
            // slot is vacant.
            continue;
        }
        if (slot->var.space != PIS_VAR_SPACE_REG) {
            // only registers are relevant here. tmps are not preserved accross CFG blocks.
            continue;
        }
        CHECK_RETHROW(
            mark_block_final_value(&builder->cdfg, block_id, slot->var, slot->value_node_id)
        );
    }

    // remember the last cf node of this block
    builder->block_infos[block_id].last_cf_node = builder->op_state.last_cf_node_id;

cleanup:
    return err;
}

static err_t integrate_root_block(cdfg_builder_t* builder, cfg_item_id_t block_id) {
    err_t err = SUCCESS;

    // TODO: convert block entry to entry, block finish to finish, block var to var.

cleanup:
    return err;
}

static err_t integrate_predecessor_final_value(
    cdfg_builder_t* builder,
    cdfg_node_id_t final_value_node_id,
    cfg_item_id_t block_id,
    cfg_item_id_t predecessor_block_id,
    size_t predecessor_index
) {
    err_t err = SUCCESS;

    cdfg_node_t* final_value_node = &builder->cdfg.node_storage[final_value_node_id.id];
    CHECK(final_value_node->kind == CDFG_NODE_KIND_BLOCK_FINAL_VALUE);

    // find the block variable that matches the register for which the value was provided.
    cdfg_node_id_t block_var_node_id = {.id = CDFG_ITEM_ID_INVALID};
    CHECK_RETHROW(find_block_var_node(
        &builder->cdfg,
        block_id,
        final_value_node->content.block_final_value.reg_region,
        &block_var_node_id
    ));

    CHECK_RETHROW(make_edge(
        &builder->cdfg,
        CDFG_EDGE_KIND_DATA_FLOW,
        final_value_node_id,
        block_var_node_id,
        predecessor_index
    ));

    cdfg_node_t* block_var_node = &builder->cdfg.node_storage[block_var_node_id.id];
    CHECK(block_var_node->kind == CDFG_NODE_KIND_BLOCK_VAR);
    block_var_node->content.block_var.predecessor_values_amount++;

cleanup:
    return err;
}

static err_t integrate_predecessor(
    cdfg_builder_t* builder,
    cfg_item_id_t block_id,
    cfg_item_id_t predecessor_block_id,
    size_t predecessor_index
) {
    err_t err = SUCCESS;

    // first, connect the predecessor's last cf node into the entry node of this block.
    cdfg_node_id_t entry_node_id = builder->block_infos[block_id].entry_node;
    CHECK(entry_node_id.id != CDFG_ITEM_ID_INVALID);

    cdfg_node_id_t predecessor_last_cf_node_id =
        builder->block_infos[predecessor_block_id].last_cf_node;
    CHECK(predecessor_last_cf_node_id.id != CDFG_ITEM_ID_INVALID);

    CHECK_RETHROW(make_edge(
        &builder->cdfg,
        CDFG_EDGE_KIND_CONTROL_FLOW,
        predecessor_last_cf_node_id,
        entry_node_id,
        predecessor_index
    ));

    // now integrate the predecessor's final values.
    for (size_t i = 0; i < builder->cdfg.nodes_amount; i++) {
        cdfg_node_id_t node_id = {.id = i};
        cdfg_node_t* node = &builder->cdfg.node_storage[i];
        if (node->kind == CDFG_NODE_KIND_BLOCK_FINAL_VALUE &&
            node->content.block_final_value.block_id == predecessor_block_id) {
            // found a node which represents the final value of a register in the predecessor.
            CHECK_RETHROW(integrate_predecessor_final_value(
                builder,
                node_id,
                block_id,
                predecessor_block_id,
                predecessor_index
            ));
        }
    }

cleanup:
    return err;
}

static err_t integrate_block(cdfg_builder_t* builder, cfg_item_id_t block_id) {
    err_t err = SUCCESS;

    size_t found_predecessors_amount = 0;

    // we want to merge the final states of all direct predecessors of this block
    for (size_t i = 0; i < builder->cfg->blocks_amount; i++) {
        if (i == block_id) {
            // skip the block itself
            continue;
        }

        bool is_direct_predecessor = false;
        CHECK_RETHROW(
            cfg_block_is_direct_predecessor(builder->cfg, i, block_id, &is_direct_predecessor)
        );
        if (is_direct_predecessor) {
            // the current block is a direct predecessor of the prepared block, so we should use all
            // its op state.
            CHECK_RETHROW(integrate_predecessor(builder, block_id, i, found_predecessors_amount));
            found_predecessors_amount++;
        }
    }

    // make sure that we found any predecessors. only the first block is allowed to have no
    // predecessors.
    if (found_predecessors_amount == 0) {
        CHECK_RETHROW(integrate_root_block(builder, block_id));
    } else {
        // our op state should now represent a merged state of all predecessors. all values are
        // merged using phi nodes.
        // in some cases, one of the predecessors might initialize a register while another
        // predecessor does not. in this case, we will have partially initialized phi nodes, which
        // only have some of their inputs connected. in those cases, we want to treat the register
        // as uninitialized, since safe code should not use potentially uninitialized registers.
        for (size_t i = 0; i < builder->op_state.used_slots_amount; i++) {
            cdfg_op_state_slot_t* slot = &builder->op_state.slots[i];
            if (slot->value_node_id.id == CDFG_ITEM_ID_INVALID) {
                // this slot is vacant.
                continue;
            }
            cdfg_node_id_t phi_node_id = slot->value_node_id;
            cdfg_node_t* phi_node = &builder->cdfg.node_storage[phi_node_id.id];
            if (phi_node->content.phi.inputs_amount != found_predecessors_amount) {
                // sanity
                CHECK(phi_node->content.phi.inputs_amount < found_predecessors_amount);

                // invalidate this slot to make this register uninitialized
                slot->value_node_id.id = CDFG_ITEM_ID_INVALID;
            }
        }
    }


cleanup:
    return err;
}

static err_t merge_predecessor_var_operand_value(
    cdfg_builder_t* builder,
    pis_var_t var,
    cdfg_node_id_t value_node_id,
    cdfg_node_id_t region_node_id,
    size_t predecessor_index
) {
    err_t err = SUCCESS;

    cdfg_node_id_t phi_node_id;
    cdfg_op_state_slot_id_t slot_id = {.id = CDFG_ITEM_ID_INVALID};
    CHECK_RETHROW(op_state_find_slot(&builder->op_state, var, &slot_id));
    if (slot_id.id == CDFG_ITEM_ID_INVALID) {
        // operand is uninitialized. it can mean one of two things:
        // - if we are the first predecessor, then we just haven't initialized this operand yet.
        // - if we are not the first predecessor, it means that the first predecessor didn't provide
        //   a value for this operand.
        //   in this case, it means that this variable may potentially be uninitialized, in which
        //   case we just want to assume that it is completely uninitialized.
        //   so, in this case we shouldn't initialize it at all.
        if (predecessor_index != 0) {
            // we are not the first predecessor, so this value is potentially uninitialized, so
            // don't initialize it at all.
            SUCCESS_CLEANUP();
        } else {
            // we are the first predecessor, so initialize the value, as explained above.

            // create a phi node for it.
            CHECK_RETHROW(make_phi_node(&builder->cdfg, &phi_node_id));

            // connect the control flow from the region node to our new phi node
            CHECK_RETHROW(make_edge(
                &builder->cdfg,
                CDFG_EDGE_KIND_CONTROL_FLOW,
                region_node_id,
                phi_node_id,
                0
            ));

            // add a new slot for it
            CHECK_RETHROW(make_op_state_slot(&builder->op_state, var, phi_node_id));
        }
    } else {
        // found an existing slot.
        const cdfg_op_state_slot_t* existing_slot = &builder->op_state.slots[slot_id.id];
        phi_node_id = existing_slot->value_node_id;
    }

    cdfg_node_t* phi_node = &builder->cdfg.node_storage[phi_node_id.id];
    CHECK(phi_node->kind == CDFG_NODE_KIND_PHI);

    // connect this value to the correct entry in the phi node.
    CHECK_RETHROW(make_edge(
        &builder->cdfg,
        CDFG_EDGE_KIND_DATA_FLOW,
        value_node_id,
        phi_node_id,
        predecessor_index
    ));

    // increment the phi node's input counter
    phi_node->content.phi.inputs_amount++;

cleanup:
    return err;
}

// /// mergess the op state of the given predecessor block into the current op state.
// static err_t merge_predecessor_op_state(
//     cdfg_builder_t* builder, cfg_item_id_t predecessor_block_id, size_t predecessor_index
// ) {
//     err_t err = SUCCESS;

//     // first, merge the control flow into a region node

//     if (builder->op_state.last_cf_node_id.id == CDFG_ITEM_ID_INVALID) {
//         // no node yet, create a new empty region node.
//         CHECK_RETHROW(make_region_node(&builder->cdfg, &builder->op_state.last_cf_node_id));
//     }


//     cdfg_node_id_t region_node_id = builder->op_state.last_cf_node_id;
//     cdfg_node_t* region_node = &builder->cdfg.node_storage[region_node_id.id];

//     // connect the control flow to the region node
//     CHECK_RETHROW(make_edge(
//         &builder->cdfg,
//         CDFG_EDGE_KIND_CONTROL_FLOW,
//         predecessor_block_final_state->last_cf_node_id,
//         builder->op_state.last_cf_node_id,
//         predecessor_index
//     ));

//     // increase the region inputs counter
//     region_node->content.region.inputs_amount++;

//     // now merge each of the operand values.
//     for (size_t i = 0; i < predecessor_block_final_state->used_slots_amount; i++) {
//         const cdfg_op_state_slot_t* slot = &predecessor_block_final_state->slots[i];
//         if (slot->value_node_id.id == CDFG_ITEM_ID_INVALID) {
//             // this slot is vacant.
//         }
//         if (slot->var.space == PIS_VAR_SPACE_TMP) {
//             // tmp operands don't need to be merged. only registers should be merged.
//             continue;
//         }

//         // merge the value
//         CHECK_RETHROW(merge_predecessor_var_operand_value(
//             builder,
//             slot->var,
//             slot->value_node_id,
//             region_node_id,
//             predecessor_index
//         ));
//     }

// cleanup:
//     return err;
// }

// static err_t prepare_non_first_block_initial_op_state(
//     cdfg_builder_t* builder, cfg_item_id_t prepared_block_id, bool* can_process_block
// ) {
//     err_t err = SUCCESS;

//     builder->op_state.used_slots_amount = 0;
//     builder->op_state.last_cf_node_id.id = CDFG_ITEM_ID_INVALID;

//     size_t found_predecessors_amount = 0;

//     // we want to merge the op states of all direct predecessors of this block
//     for (size_t i = 0; i < builder->cfg->blocks_amount; i++) {
//         if (i == prepared_block_id) {
//             // skip the block itself
//             continue;
//         }

//         bool is_direct_predecessor = false;
//         CHECK_RETHROW(cfg_block_is_direct_predecessor(
//             builder->cfg,
//             i,
//             prepared_block_id,
//             &is_direct_predecessor
//         ));
//         if (is_direct_predecessor) {
//             // the current block is a direct predecessor of the prepared block, so we should use
//             all
//             // its op state.
//             if (!builder->block_states[i].was_processed) {
//                 // this block wasn't yet processed. for now we will ignore its exist
//                 *can_process_block = false;
//                 SUCCESS_CLEANUP();
//             } else {
//                 // the prepared block may have multiple predecessors, and we want to merge all of
//                 // their op states into one.
//                 CHECK_RETHROW(merge_predecessor_op_state(builder, i, found_predecessors_amount));

//                 found_predecessors_amount++;
//             }
//         }
//     }

//     // make sure that we found any predecessors. only the first block is allowed to have no
//     // predecessors.
//     CHECK(found_predecessors_amount > 0);

//     // our op state should now represent a merged state of all predecessors. all values are
//     // merged using phi nodes.
//     // in some cases, one of the predecessors might initialize a register while another
//     predecessor
//     // does not. in this case, we will have partially initialized phi nodes, which only have some
//     of
//     // their inputs connected.
//     // in those cases, we want to treat the register as uninitialized, since safe code should not
//     // use potentially uninitialized registers.
//     for (size_t i = 0; i < builder->op_state.used_slots_amount; i++) {
//         cdfg_op_state_slot_t* slot = &builder->op_state.slots[i];
//         if (slot->value_node_id.id == CDFG_ITEM_ID_INVALID) {
//             // this slot is vacant.
//             continue;
//         }
//         cdfg_node_id_t phi_node_id = slot->value_node_id;
//         cdfg_node_t* phi_node = &builder->cdfg.node_storage[phi_node_id.id];
//         if (phi_node->content.phi.inputs_amount != found_predecessors_amount) {
//             // sanity
//             CHECK(phi_node->content.phi.inputs_amount < found_predecessors_amount);

//             // invalidate this slot to make this register uninitialized
//             slot->value_node_id.id = CDFG_ITEM_ID_INVALID;
//         }
//     }

//     *can_process_block = true;

// cleanup:
//     return err;
// }

static err_t prepare_block_initial_op_state(cdfg_builder_t* builder, cfg_item_id_t block_id) {
    err_t err = SUCCESS;

    // reset the op state.
    builder->op_state.used_slots_amount = 0;
    builder->op_state.last_cf_node_id.id = CDFG_ITEM_ID_INVALID;

    // create a block entry node which will be the root of control flow.
    cdfg_node_id_t entry_node_id = {.id = CDFG_ITEM_ID_INVALID};
    CHECK_RETHROW(make_block_entry_node(&builder->cdfg, block_id, &entry_node_id));
    builder->block_infos[block_id].entry_node = entry_node_id;
    builder->op_state.last_cf_node_id = entry_node_id;
cleanup:
    return err;
}

static bool is_node_used_as_input_of_kind(
    const cdfg_t* cdfg, cdfg_node_id_t node_id, cdfg_edge_kind_t edge_kind
) {
    for (size_t i = 0; i < cdfg->edges_amount; i++) {
        const cdfg_edge_t* edge = &cdfg->edge_storage[i];
        if (edge->from_node.id == node_id.id && edge->kind == edge_kind) {
            return true;
        }
    }
    return false;
}

static bool is_node_used_as_input(const cdfg_t* cdfg, cdfg_node_id_t node_id) {
    for (size_t i = 0; i < cdfg->edges_amount; i++) {
        if (cdfg->edge_storage[i].from_node.id == node_id.id) {
            return true;
        }
    }
    return false;
}

static bool does_node_have_cf_input(const cdfg_t* cdfg, cdfg_node_id_t node_id) {
    for (size_t i = 0; i < cdfg->edges_amount; i++) {
        const cdfg_edge_t* edge = &cdfg->edge_storage[i];
        if (edge->kind == CDFG_EDGE_KIND_CONTROL_FLOW && edge->to_node.id == node_id.id) {
            return true;
        }
    }
    return false;
}

/// removes unused nodes and edges. returns whether any nodes or edges were removed.
static bool remove_unused_nodes_and_edges(cdfg_t* cdfg) {
    bool removed_anything = false;
    for (size_t i = 0; i < cdfg->nodes_amount; i++) {
        cdfg_node_id_t node_id = {.id = i};
        cdfg_node_t* node = &cdfg->node_storage[i];
        if (node->kind == CDFG_NODE_KIND_INVALID) {
            // node is vacant.
            continue;
        }

        bool is_node_required = is_node_used_as_input(cdfg, node_id) ||
                                does_node_have_cf_input(cdfg, node_id) ||
                                node->kind == CDFG_NODE_KIND_FINISH;
        if (!is_node_required) {
            // if the node's value is not used anywhere, and it is not a finish node (which by
            // definition must be kept), remove it.
            node->kind = CDFG_NODE_KIND_INVALID;
            removed_anything = true;
        }
    }

    // remove all edges that now point to invalid nodes
    for (size_t i = 0; i < cdfg->edges_amount; i++) {
        cdfg_edge_t* edge = &cdfg->edge_storage[i];
        if (edge->to_node.id == CDFG_ITEM_ID_INVALID) {
            // this edge is vacant.
            continue;
        }
        const cdfg_node_t* to_node = &cdfg->node_storage[edge->to_node.id];
        if (to_node->kind == CDFG_NODE_KIND_INVALID) {
            edge->from_node.id = CDFG_ITEM_ID_INVALID;
            edge->to_node.id = CDFG_ITEM_ID_INVALID;
            removed_anything = true;
        }
    }
    return removed_anything;
}

/// finds the single input edge of the given kind to the given node. makes sure that only one such
/// edge exists, and that it does exist.
static err_t node_find_single_input_edge(
    const cdfg_t* cdfg,
    cdfg_edge_kind_t kind,
    cdfg_node_id_t node_id,
    cdfg_node_id_t* out_found_item_id
) {
    err_t err = SUCCESS;
    cdfg_item_id_t found_id = CDFG_ITEM_ID_INVALID;
    for (size_t i = 0; i < cdfg->edges_amount; i++) {
        const cdfg_edge_t* edge = &cdfg->edge_storage[i];
        if (edge->to_node.id == node_id.id && edge->kind == kind) {
            // make sure that we don't find multiple matchine edges.
            CHECK(found_id == CDFG_ITEM_ID_INVALID);

            found_id = i;
        }
    }

    // make sure that we found any matching edge.
    CHECK(found_id != CDFG_ITEM_ID_INVALID);

    out_found_item_id->id = found_id;
cleanup:
    return err;
}

/// replaces all usages of the given node as a the "from" node of an edge with the given other node.
static void substitute(
    cdfg_t* cdfg, cdfg_node_id_t node_id_to_replace, cdfg_node_id_t replace_with_node_id
) {
    for (size_t i = 0; i < cdfg->edges_amount; i++) {
        if (cdfg->edge_storage[i].from_node.id == node_id_to_replace.id) {
            cdfg->edge_storage[i].from_node = replace_with_node_id;
        }
    }
}

static err_t remove_single_input_region_phi_nodes(cdfg_t* cdfg, bool* did_anything) {
    err_t err = SUCCESS;

    for (size_t i = 0; i < cdfg->nodes_amount; i++) {
        cdfg_node_id_t node_id = {.id = i};
        cdfg_node_t* node = &cdfg->node_storage[i];
        if (!(node->kind == CDFG_NODE_KIND_PHI || node->kind == CDFG_NODE_KIND_REGION)) {
            // only phi/region nodes are relevant here
            continue;
        }

        // calculate the inputs amount of the phi/region node
        size_t inputs_amount;
        if (node->kind == CDFG_NODE_KIND_PHI) {
            inputs_amount = node->content.phi.inputs_amount;
        } else {
            inputs_amount = node->content.region.inputs_amount;
        }

        if (inputs_amount != 1) {
            // phi/region node has more than one input so it can't be optimized
            continue;
        }

        cdfg_edge_kind_t desired_edge_kind;
        if (node->kind == CDFG_NODE_KIND_PHI) {
            desired_edge_kind = CDFG_EDGE_KIND_DATA_FLOW;
        } else {
            desired_edge_kind = CDFG_EDGE_KIND_CONTROL_FLOW;
        }

        cdfg_node_id_t input_edge_id = {.id = CDFG_ITEM_ID_INVALID};
        CHECK_RETHROW(node_find_single_input_edge(cdfg, desired_edge_kind, node_id, &input_edge_id)
        );

        cdfg_edge_t* edge = &cdfg->edge_storage[input_edge_id.id];

        // this phi/region node has a single input, its index should be zero.
        CHECK(edge->to_node_input_index == 0);

        // find the underlying node of this phi/region node
        cdfg_node_id_t underlying_node_id = edge->from_node;

        // replace all usages of the phi/region node with the underlying node.
        substitute(cdfg, node_id, underlying_node_id);

        // invalidate the current node. no need to remove the edges since they will be removed by
        // other optimization passes.
        node->kind = CDFG_NODE_KIND_INVALID;

        *did_anything = true;
    }
cleanup:
    return err;
}

static size_t
    node_count_inputs(const cdfg_t* cdfg, cdfg_node_id_t node_id, cdfg_edge_kind_t edge_kind) {
    size_t amount = 0;

    for (size_t i = 0; i < cdfg->edges_amount; i++) {
        const cdfg_edge_t* edge = &cdfg->edge_storage[i];

        if (edge->to_node.id != node_id.id || edge->kind != edge_kind) {
            continue;
        }

        amount++;
    }

    return amount;
}

static err_t binop_node_find_data_inputs(
    const cdfg_t* cdfg, cdfg_node_id_t node_id, cdfg_node_id_t input_node_ids[2]
) {
    err_t err = SUCCESS;

    CHECK_RETHROW(find_node_inputs(cdfg, node_id, CDFG_EDGE_KIND_DATA_FLOW, input_node_ids, 2));

cleanup:
    return err;
}

typedef bool (*node_predicate_t)(const cdfg_t* cdfg, cdfg_node_id_t node_id);

static err_t node_find_input_by_predicate(
    const cdfg_t* cdfg,
    cdfg_node_id_t node_id,
    cdfg_edge_kind_t edge_kind,
    node_predicate_t predicate,
    cdfg_node_id_t* out_found_node_id
) {
    err_t err = SUCCESS;

    cdfg_node_id_t found_node_id = {.id = CDFG_ITEM_ID_INVALID};
    for (size_t i = 0; i < cdfg->edges_amount; i++) {
        const cdfg_edge_t* edge = &cdfg->edge_storage[i];
        // make sure that the edge has the right kind
        if (edge->kind != edge_kind) {
            continue;
        }

        // make sure that the edge points to our node
        if (edge->to_node.id != node_id.id) {
            continue;
        }

        // make sure that the predicate holds for the src node
        if (!predicate(cdfg, edge->from_node)) {
            continue;
        }

        // make sure that we only found one such item.
        CHECK(found_node_id.id == CDFG_ITEM_ID_INVALID);

        found_node_id = edge->from_node;
    }

    *out_found_node_id = found_node_id;

cleanup:
    return err;
}

static bool node_is_zero_imm(const cdfg_t* cdfg, cdfg_node_id_t node_id) {
    const cdfg_node_t* from_node = &cdfg->node_storage[node_id.id];
    return from_node->kind == CDFG_NODE_KIND_IMM && from_node->content.imm.value == 0;
}

static bool node_is_sub(const cdfg_t* cdfg, cdfg_node_id_t node_id) {
    const cdfg_node_t* from_node = &cdfg->node_storage[node_id.id];
    return from_node->kind == CDFG_NODE_KIND_CALC &&
           from_node->content.calc.calculation == CDFG_CALCULATION_SUB;
}

static err_t optimize_sub_equals_zero(cdfg_t* cdfg, bool* did_anything) {
    err_t err = SUCCESS;

    for (size_t cur_node_index = 0; cur_node_index < cdfg->nodes_amount; cur_node_index++) {
        cdfg_node_id_t cur_node_id = {.id = cur_node_index};
        cdfg_node_t* node = &cdfg->node_storage[cur_node_index];
        if (node->kind != CDFG_NODE_KIND_CALC) {
            continue;
        }
        if (node->content.calc.calculation != CDFG_CALCULATION_EQUALS) {
            continue;
        }

        // the current node is an equals node.

        // we need one of the inputs to be a zero immediate operand.
        cdfg_node_id_t zero_imm_node_id = {.id = CDFG_ITEM_ID_INVALID};
        CHECK_RETHROW(node_find_input_by_predicate(
            cdfg,
            cur_node_id,
            CDFG_EDGE_KIND_DATA_FLOW,
            node_is_zero_imm,
            &zero_imm_node_id
        ));
        if (zero_imm_node_id.id == CDFG_ITEM_ID_INVALID) {
            continue;
        }

        // we need another one of the inputs to be a sub operation.
        cdfg_node_id_t sub_node_id = {.id = CDFG_ITEM_ID_INVALID};
        CHECK_RETHROW(node_find_input_by_predicate(
            cdfg,
            cur_node_id,
            CDFG_EDGE_KIND_DATA_FLOW,
            node_is_sub,
            &sub_node_id
        ));
        if (sub_node_id.id == CDFG_ITEM_ID_INVALID) {
            continue;
        }

        // doing `x - y == 0` is like doing `x == y`, so we want to create an equals node with the
        // same operands as the sub node.
        cdfg_node_id_t sub_input_node_ids[2] = {};
        CHECK_RETHROW(binop_node_find_data_inputs(cdfg, sub_node_id, sub_input_node_ids));

        cdfg_node_id_t optimized_eq_node_id = {.id = CDFG_ITEM_ID_INVALID};
        CHECK_RETHROW(make_binop_node(
            cdfg,
            CDFG_CALCULATION_EQUALS,
            sub_input_node_ids[0],
            sub_input_node_ids[1],
            &optimized_eq_node_id
        ));

        substitute(cdfg, cur_node_id, optimized_eq_node_id);

        *did_anything = true;
    }
cleanup:
    return err;
}

err_t cdfg_optimize(cdfg_t* cdfg) {
    err_t err = SUCCESS;

    bool did_anything = true;

    while (did_anything) {
        did_anything = false;
        did_anything |= remove_unused_nodes_and_edges(cdfg);
        CHECK_RETHROW(remove_single_input_region_phi_nodes(cdfg, &did_anything));
        CHECK_RETHROW(optimize_sub_equals_zero(cdfg, &did_anything));
    }
cleanup:
    return err;
}

static err_t cdfg_build_reg_op_map(cdfg_builder_t* builder, const cfg_t* cfg) {
    err_t err = SUCCESS;

    // iterate over all code in the cfg and update the register operand map according to each
    // register access.
    for (size_t block_idx = 0; block_idx < cfg->blocks_amount; block_idx++) {
        const cfg_block_t* block = &builder->cfg->block_storage[block_idx];
        CHECK(block->units_amount > 0);

        const cfg_unit_t* block_units = &builder->cfg->unit_storage[block->first_unit_id];
        for (size_t unit_idx = 0; unit_idx < block->units_amount; unit_idx++) {
            const cfg_unit_t* unit = &block_units[unit_idx];
            const pis_insn_t* unit_insns = &builder->cfg->insn_storage[unit->first_insn_id];
            for (size_t insn_idx = 0; insn_idx < unit->insns_amount; insn_idx++) {
                const pis_insn_t* insn = &unit_insns[insn_idx];
                for (size_t op_idx = 0; op_idx < insn->operands_amount; op_idx++) {
                    const pis_op_t* op = &insn->operands[op_idx];
                    if (op->kind != PIS_OP_KIND_VAR) {
                        continue;
                    }
                    if (op->v.var.addr.space != PIS_VAR_SPACE_REG) {
                        continue;
                    }
                    CHECK_RETHROW(cdfg_op_map_update(&builder->reg_op_map, pis_op_var_region(op)));
                }
            }
        }
    }

cleanup:
    return err;
}

err_t cdfg_build(cdfg_builder_t* builder, const cfg_t* cfg) {
    err_t err = SUCCESS;

    // initialize the builder
    builder->cfg = cfg;
    cdfg_reset(&builder->cdfg);
    cdfg_op_map_reset(&builder->reg_op_map);

    // build the register operand map
    CHECK_RETHROW(cdfg_build_reg_op_map(builder, cfg));

    // process all blocks
    for (size_t i = 0; i < cfg->blocks_amount; i++) {
        // prepare the initial op state for the block
        CHECK_RETHROW(prepare_block_initial_op_state(builder, i));

        // process the block
        CHECK_RETHROW(process_block(builder, i));
    }

    // now we need to integrate all blocks with each other
    for (size_t i = 0; i < cfg->blocks_amount; i++) {
        CHECK_RETHROW(integrate_block(builder, i));
    }

cleanup:
    return err;
}

static void cdfg_dump_node_desciption(const cdfg_node_t* node) {
    switch (node->kind) {
        case CDFG_NODE_KIND_ENTRY:
            TRACE_NO_NEWLINE("entry");
            break;
        case CDFG_NODE_KIND_FINISH:
            TRACE_NO_NEWLINE("finish");
            break;
        case CDFG_NODE_KIND_VAR:
            TRACE_NO_NEWLINE(
                "REG[0x%x]:%u",
                node->content.var.reg_region.offset,
                pis_size_to_bytes(node->content.var.reg_region.size)
            );
            break;
        case CDFG_NODE_KIND_IMM:
            TRACE_NO_NEWLINE("0x%lx", node->content.imm.value);
            break;
        case CDFG_NODE_KIND_CALC:
            TRACE_NO_NEWLINE("%s", cdfg_calculation_to_str(node->content.calc.calculation));
            break;
        case CDFG_NODE_KIND_STORE:
            TRACE_NO_NEWLINE("store");
            break;
        case CDFG_NODE_KIND_LOAD:
            TRACE_NO_NEWLINE("load");
            break;
        case CDFG_NODE_KIND_IF:
            TRACE_NO_NEWLINE("if");
            break;
        case CDFG_NODE_KIND_REGION:
            TRACE_NO_NEWLINE("region");
            break;
        case CDFG_NODE_KIND_PHI:
            TRACE_NO_NEWLINE("phi");
            break;
        case CDFG_NODE_KIND_INVALID:
            TRACE_NO_NEWLINE("invalid");
            break;
        case CDFG_NODE_KIND_BLOCK_VAR:
            TRACE_NO_NEWLINE(
                "block %u var REG[0x%x]:%u, %u inputs",
                node->content.block_var.block_id,
                node->content.block_var.reg_region.offset,
                pis_size_to_bytes(node->content.block_var.reg_region.size),
                node->content.block_var.predecessor_values_amount
            );
            break;
        case CDFG_NODE_KIND_BLOCK_ENTRY:
            TRACE_NO_NEWLINE("block %u entry", node->content.block_entry.block_id);
            break;
        case CDFG_NODE_KIND_BLOCK_FINAL_VALUE:
            TRACE_NO_NEWLINE(
                "block %u final value REG[0x%x]:%u",
                node->content.block_final_value.block_id,
                node->content.block_final_value.reg_region.offset,
                pis_size_to_bytes(node->content.block_final_value.reg_region.size)
            );
            break;
    }
}

static void cdfg_dump_node_ident(cdfg_node_id_t node_id) {
    TRACE_NO_NEWLINE("id_%u", node_id.id);
}

static void cdfg_dump_node(const cdfg_t* cdfg, cdfg_node_id_t node_id) {
    cdfg_dump_node_ident(node_id);

    bool has_cf_input = does_node_have_cf_input(cdfg, node_id);
    size_t data_inputs_amount = node_count_inputs(cdfg, node_id, CDFG_EDGE_KIND_DATA_FLOW);

    bool has_cf_output = is_node_used_as_input_of_kind(cdfg, node_id, CDFG_EDGE_KIND_CONTROL_FLOW);
    bool has_df_output = is_node_used_as_input_of_kind(cdfg, node_id, CDFG_EDGE_KIND_DATA_FLOW);

    TRACE_NO_NEWLINE(" [shape=record, label=\" ");


    bool has_inputs = has_cf_input || data_inputs_amount > 0;

    // special case for nodes with no inputs and only one dataflow output
    if (has_df_output && !has_inputs && !has_cf_output) {
        // make the node only have a global label, and nothing else.
        TRACE_NO_NEWLINE("<dout> ");
        cdfg_dump_node_desciption(&cdfg->node_storage[node_id.id]);
    } else {
        // regular node output format

        TRACE_NO_NEWLINE(" { ");
        if (has_inputs) {
            TRACE_NO_NEWLINE("{");
            if (does_node_have_cf_input(cdfg, node_id)) {
                TRACE_NO_NEWLINE("<cfin> ");
                if (data_inputs_amount > 0) {
                    TRACE_NO_NEWLINE("| ");
                }
            }

            size_t data_inputs_amount = node_count_inputs(cdfg, node_id, CDFG_EDGE_KIND_DATA_FLOW);
            for (size_t i = 0; i < data_inputs_amount; i++) {
                TRACE_NO_NEWLINE("<din%lu> ", (unsigned long) i);
                if (i + 1 < data_inputs_amount) {
                    TRACE_NO_NEWLINE("| ");
                }
            }
            TRACE_NO_NEWLINE("} | ");
        }

        cdfg_dump_node_desciption(&cdfg->node_storage[node_id.id]);
        TRACE_NO_NEWLINE(" | ");

        if (has_cf_output || has_df_output) {
            TRACE_NO_NEWLINE("{ ");

            if (has_cf_output) {
                TRACE_NO_NEWLINE("<cfout> ");
                if (has_df_output) {
                    TRACE_NO_NEWLINE("| ");
                }
            }

            if (has_df_output) {
                TRACE_NO_NEWLINE("<dout> ");
            }

            TRACE_NO_NEWLINE("} ");
        }
        TRACE_NO_NEWLINE(" }");
    }
    TRACE_NO_NEWLINE(" \" ] ");
}

/// dumps a DOT representation of the CDFG to stdout.
void cdfg_dump_dot(const cdfg_t* cdfg) {
    TRACE("digraph {");

    // order the ports properly
    TRACE("rankdir=TB;");

    // make it dark theme
    TRACE("bgcolor=\"#181818\"");
    TRACE("node [");
    TRACE("fontcolor = \"#e6e6e6\",");
    TRACE("style = filled,");
    TRACE("color = \"#e6e6e6\",");
    TRACE("fillcolor = \"#333333\"");
    TRACE("]");
    TRACE("edge [");
    TRACE("color = \"#e6e6e6\",");
    TRACE("fontcolor = \"#e6e6e6\"");
    TRACE("]");

    for (size_t i = 0; i < cdfg->nodes_amount; i++) {
        if (cdfg->node_storage[i].kind == CDFG_NODE_KIND_INVALID) {
            // the node is vacant.
            continue;
        }

        cdfg_node_id_t node_id = {.id = i};
        cdfg_dump_node(cdfg, node_id);
        TRACE();
    }

    for (size_t i = 0; i < cdfg->edges_amount; i++) {
        const cdfg_edge_t* edge = &cdfg->edge_storage[i];
        if (edge->from_node.id == CDFG_ITEM_ID_INVALID) {
            // the edge is vacant.
            continue;
        }

        cdfg_dump_node_ident(edge->from_node);
        switch (edge->kind) {
            case CDFG_EDGE_KIND_DATA_FLOW:
                TRACE_NO_NEWLINE(":dout");
                break;
            case CDFG_EDGE_KIND_CONTROL_FLOW:
                TRACE_NO_NEWLINE(":cfout");
                break;
        }


        TRACE_NO_NEWLINE(" -> ");

        cdfg_dump_node_ident(edge->to_node);
        switch (edge->kind) {
            case CDFG_EDGE_KIND_DATA_FLOW:
                TRACE_NO_NEWLINE(":din%u", edge->to_node_input_index);
                break;
            case CDFG_EDGE_KIND_CONTROL_FLOW:
                TRACE_NO_NEWLINE(":cfin");
                break;
        }

        if (edge->kind == CDFG_EDGE_KIND_CONTROL_FLOW) {
            TRACE_NO_NEWLINE(" [color=\"blue\"]");
        }

        TRACE();
    }
    TRACE("}");
}
