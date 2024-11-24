#include "cdfg.h"
#include "cfg.h"
#include "endianness.h"
#include "errors.h"
#include "except.h"
#include "operand_size.h"
#include "pis.h"
#include "trace.h"
#include "utils.h"
#include <stddef.h>
#include <string.h>

typedef err_t (*opcode_handler_t)(cdfg_builder_t* builder, const pis_insn_t* insn);

STR_ENUM_IMPL(cdfg_calculation, CDFG_CALCULATION);

void cdfg_reset(cdfg_t* cdfg) {
    memset(cdfg, 0, sizeof(*cdfg));
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

static err_t next_node_id(cdfg_t* cdfg, cdfg_item_id_t* id) {
    err_t err = SUCCESS;

    CHECK_RETHROW(next_id(&cdfg->nodes_amount, CDFG_MAX_NODES, id));

cleanup:
    return err;
}

static err_t next_edge_id(cdfg_t* cdfg, cdfg_item_id_t* id) {
    err_t err = SUCCESS;

    CHECK_RETHROW(next_id(&cdfg->edges_amount, CDFG_MAX_EDGES, id));

cleanup:
    return err;
}

static err_t next_op_state_slot_id(cdfg_op_state_t* op_state, cdfg_item_id_t* id) {
    err_t err = SUCCESS;

    CHECK_RETHROW(next_id(&op_state->used_slots_amount, CDFG_OP_STATE_MAX_SLOTS, id));

cleanup:
    return err;
}

static err_t make_op_state_slot(
    cdfg_op_state_t* op_state, const pis_operand_t* operand, cdfg_item_id_t value_node_id
) {
    err_t err = SUCCESS;
    cdfg_item_id_t slot_id = CDFG_ITEM_ID_INVALID;
    CHECK_RETHROW(next_op_state_slot_id(op_state, &slot_id));
    op_state->slots[slot_id] = (cdfg_op_state_slot_t) {
        .operand = *operand,
        .value_node_id = value_node_id,
    };
cleanup:
    return err;
}

/// tries to find an exact match for the given operand in the operand state. if an exact match was
/// found, returns the id of the slot which matched the operand.
static cdfg_item_id_t
    find_slot_exact(const cdfg_op_state_t* op_state, const pis_operand_t* operand) {
    for (size_t i = 0; i < op_state->used_slots_amount; i++) {
        const cdfg_op_state_slot_t* slot = &op_state->slots[i];
        if (slot->value_node_id == CDFG_ITEM_ID_INVALID) {
            // this slot is vacant.
            continue;
        }
        if (pis_operand_equals(operand, &slot->operand)) {
            // exact match
            return i;
        }
    }

    // no exact match was found
    return CDFG_ITEM_ID_INVALID;
}

/// tries to find an exact match for the given operand in the operand state. if an exact match was
/// found, returns the id of the node which represents the value of the given operand.
static cdfg_item_id_t
    read_operand_exact(const cdfg_op_state_t* op_state, const pis_operand_t* operand) {
    cdfg_item_id_t slot_id = find_slot_exact(op_state, operand);
    if (slot_id == CDFG_ITEM_ID_INVALID) {
        return CDFG_ITEM_ID_INVALID;
    }
    return op_state->slots[slot_id].value_node_id;
}

/// checks if the given operand is fully uninitialized. that is, none of its bytes are
/// initialized. if at least one of its bytes is initialized, then it is not considered fully
/// uninitialized.
static bool is_operand_fully_uninit(const cdfg_op_state_t* op_state, const pis_operand_t* operand) {
    for (size_t i = 0; i < op_state->used_slots_amount; i++) {
        const cdfg_op_state_slot_t* slot = &op_state->slots[i];
        if (slot->value_node_id == CDFG_ITEM_ID_INVALID) {
            // this slot is vacant.
            continue;
        }
        if (pis_operands_intersect(operand, &slot->operand)) {
            // found a slot which intersects with the examined operand. this means that at least one
            // of its bytes is initialized, so it is not fully uninitialized.
            return false;
        }
    }

    // none of the slots in the operand state intersect with the operand, so it is fully
    // uninitialized.
    return true;
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

/// tries to find an existing variable node with the given parameters in the cdfg.
/// returns the id of the found node, or `CDFG_ITEM_ID_INVALID` if no such node was found.
static cdfg_item_id_t find_var_node(const cdfg_t* cdfg, u64 reg_offset, pis_size_t reg_size) {
    for (size_t i = 0; i < cdfg->nodes_amount; i++) {
        const cdfg_node_t* node = &cdfg->node_storage[i];
        if (node->kind != CDFG_NODE_KIND_VAR) {
            continue;
        }
        if (node->content.var.reg_offset == reg_offset && node->content.var.reg_size == reg_size) {
            return i;
        }
    }
    return CDFG_ITEM_ID_INVALID;
}

/// returns an immediate node with the given immediate value, either by creating one or by reusing
/// an existing one.
static err_t make_imm_node(cdfg_t* cdfg, u64 value, cdfg_item_id_t* out_node_id) {
    err_t err = SUCCESS;

    cdfg_item_id_t node_id = find_imm_node(cdfg, value);

    if (node_id == CDFG_ITEM_ID_INVALID) {
        // no existing node, create a new one.
        CHECK_RETHROW(next_node_id(cdfg, &node_id));

        cdfg->node_storage[node_id] = (cdfg_node_t) {
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
    cdfg_item_id_t from_node,
    cdfg_item_id_t to_node,
    u8 to_node_input_index
) {
    err_t err = SUCCESS;

    cdfg_item_id_t edge_id = CDFG_ITEM_ID_INVALID;
    CHECK_RETHROW(next_edge_id(cdfg, &edge_id));

    // make sure that the value is in range of the bitfield.
    CHECK(to_node_input_index < (1 << 7));

    cdfg->edge_storage[edge_id] = (cdfg_edge_t) {
        .kind = kind,
        .to_node_input_index = to_node_input_index,
        .from_node = from_node,
        .to_node = to_node,
    };

cleanup:
    return err;
}

static err_t
    make_calc_node(cdfg_t* cdfg, cdfg_calculation_t calculation, cdfg_item_id_t* out_node_id) {
    err_t err = SUCCESS;

    cdfg_item_id_t node_id = CDFG_ITEM_ID_INVALID;
    CHECK_RETHROW(next_node_id(cdfg, &node_id));

    cdfg->node_storage[node_id] = (cdfg_node_t) {
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
static err_t link_cf_node(cdfg_builder_t* builder, cdfg_item_id_t node_id) {
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
    make_empty_node_of_kind(cdfg_t* cdfg, cdfg_node_kind_t kind, cdfg_item_id_t* out_node_id) {
    err_t err = SUCCESS;

    cdfg_item_id_t node_id = CDFG_ITEM_ID_INVALID;
    CHECK_RETHROW(next_node_id(cdfg, &node_id));

    cdfg->node_storage[node_id] = (cdfg_node_t) {
        .kind = kind,
        .content = {},
    };

    *out_node_id = node_id;
cleanup:
    return err;
}

static err_t make_store_node(cdfg_t* cdfg, cdfg_item_id_t* out_node_id) {
    err_t err = SUCCESS;

    CHECK_RETHROW(make_empty_node_of_kind(cdfg, CDFG_NODE_KIND_STORE, out_node_id));

cleanup:
    return err;
}

static err_t make_load_node(cdfg_t* cdfg, cdfg_item_id_t* out_node_id) {
    err_t err = SUCCESS;

    CHECK_RETHROW(make_empty_node_of_kind(cdfg, CDFG_NODE_KIND_LOAD, out_node_id));
cleanup:
    return err;
}

static err_t make_if_node(cdfg_t* cdfg, cdfg_item_id_t* out_node_id) {
    err_t err = SUCCESS;

    CHECK_RETHROW(make_empty_node_of_kind(cdfg, CDFG_NODE_KIND_IF, out_node_id));

cleanup:
    return err;
}

static err_t make_region_node(cdfg_t* cdfg, cdfg_item_id_t* out_node_id) {
    err_t err = SUCCESS;

    CHECK_RETHROW(make_empty_node_of_kind(cdfg, CDFG_NODE_KIND_REGION, out_node_id));

cleanup:
    return err;
}

static err_t make_phi_node(cdfg_t* cdfg, cdfg_item_id_t* out_node_id) {
    err_t err = SUCCESS;

    CHECK_RETHROW(make_empty_node_of_kind(cdfg, CDFG_NODE_KIND_PHI, out_node_id));

cleanup:
    return err;
}

static err_t do_if(cdfg_builder_t* builder, cdfg_item_id_t cond_node_id) {
    err_t err = SUCCESS;

    cdfg_item_id_t if_node_id = CDFG_ITEM_ID_INVALID;
    CHECK_RETHROW(make_if_node(&builder->cdfg, &if_node_id));

    CHECK_RETHROW(make_edge(&builder->cdfg, CDFG_EDGE_KIND_DATA_FLOW, cond_node_id, if_node_id, 0));

    CHECK_RETHROW(link_cf_node(builder, if_node_id));
cleanup:
    return err;
}

static err_t
    do_store(cdfg_builder_t* builder, cdfg_item_id_t addr_node_id, cdfg_item_id_t val_node_id) {
    err_t err = SUCCESS;

    cdfg_item_id_t store_node_id = CDFG_ITEM_ID_INVALID;
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
    cdfg_builder_t* builder, cdfg_item_id_t addr_node_id, cdfg_item_id_t* out_loaded_val_node_id
) {
    err_t err = SUCCESS;

    cdfg_item_id_t load_node_id = CDFG_ITEM_ID_INVALID;
    CHECK_RETHROW(make_load_node(&builder->cdfg, &load_node_id));

    CHECK_RETHROW(make_edge(&builder->cdfg, CDFG_EDGE_KIND_DATA_FLOW, addr_node_id, load_node_id, 0)
    );

    CHECK_RETHROW(link_cf_node(builder, load_node_id));

    *out_loaded_val_node_id = load_node_id;

cleanup:
    return err;
}

static err_t make_entry_node(cdfg_t* cdfg, cdfg_item_id_t* out_node_id) {
    err_t err = SUCCESS;

    CHECK_RETHROW(make_empty_node_of_kind(cdfg, CDFG_NODE_KIND_ENTRY, out_node_id));

cleanup:
    return err;
}

static err_t make_finish_node(cdfg_t* cdfg, cdfg_item_id_t* out_node_id) {
    err_t err = SUCCESS;

    CHECK_RETHROW(make_empty_node_of_kind(cdfg, CDFG_NODE_KIND_FINISH, out_node_id));

cleanup:
    return err;
}

static err_t make_binop_node(
    cdfg_t* cdfg,
    cdfg_calculation_t calculation,
    cdfg_item_id_t lhs_node_id,
    cdfg_item_id_t rhs_node_id,
    cdfg_item_id_t* out_binop_node_id
) {
    err_t err = SUCCESS;

    cdfg_item_id_t node_id = CDFG_ITEM_ID_INVALID;
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
    cdfg_item_id_t input_node_id,
    cdfg_item_id_t* out_binop_node_id
) {
    err_t err = SUCCESS;

    cdfg_item_id_t node_id = CDFG_ITEM_ID_INVALID;
    CHECK_RETHROW(make_calc_node(cdfg, calculation, &node_id));

    CHECK_RETHROW(make_edge(cdfg, CDFG_EDGE_KIND_DATA_FLOW, input_node_id, node_id, 0));

    *out_binop_node_id = node_id;
cleanup:
    return err;
}

static err_t
    make_var_node(cdfg_t* cdfg, const pis_operand_t* reg_operand, cdfg_item_id_t* out_node_id) {
    err_t err = SUCCESS;

    CHECK(reg_operand->addr.space == PIS_SPACE_REG);

    cdfg_item_id_t node_id = find_var_node(cdfg, reg_operand->addr.offset, reg_operand->size);

    if (node_id == CDFG_ITEM_ID_INVALID) {
        // no existing node, create a new one.
        CHECK_RETHROW(next_node_id(cdfg, &node_id));
        cdfg->node_storage[node_id] = (cdfg_node_t) {
            .kind = CDFG_NODE_KIND_VAR,
            .content =
                {
                    .var =
                        {
                            .reg_offset = reg_operand->addr.offset,
                            .reg_size = reg_operand->size,
                        },
                },
        };
    }

    *out_node_id = node_id;
cleanup:
    return err;
}

static err_t read_reg_operand(
    cdfg_builder_t* builder, const pis_operand_t* operand, cdfg_item_id_t* out_node_id
) {
    err_t err = SUCCESS;

    if (is_operand_fully_uninit(&builder->op_state, operand)) {
        // the reg operand is fully uninitialized. initialize it to a new variable node.

        // first, create the variable node
        cdfg_item_id_t node_id = CDFG_ITEM_ID_INVALID;
        CHECK_RETHROW(make_var_node(&builder->cdfg, operand, &node_id));

        // now add a slot in the op state to point to it
        CHECK_RETHROW(make_op_state_slot(&builder->op_state, operand, node_id));

        *out_node_id = node_id;
    } else {
        // node is either fully initialized or partially initialized.
        //
        // partially initialized nodes are not allowed in the CDFG. the lifter implementations
        // must make sure to not emit intersection GPR accesses to make this ok.
        //
        // so, we expect the node to have an exact match node id.
        cdfg_item_id_t exact_match_node_id = read_operand_exact(&builder->op_state, operand);
        CHECK(exact_match_node_id != CDFG_ITEM_ID_INVALID);

        // found an exact match for the node, use it.
        *out_node_id = exact_match_node_id;
    }
cleanup:
    return err;
}

static err_t read_tmp_operand(
    cdfg_builder_t* builder, const pis_operand_t* operand, cdfg_item_id_t* out_node_id
) {
    err_t err = SUCCESS;

    // tmp operands don't allow the shitty combinatorics that are allowed for reg operands. they
    // must always be initialized when read, and they only allow exact matches in the op state, no
    // partial reads/writes.
    cdfg_item_id_t node_id = read_operand_exact(&builder->op_state, operand);
    CHECK(node_id != CDFG_ITEM_ID_INVALID);

    *out_node_id = node_id;
cleanup:
    return err;
}

/// reads the given operand according to the current op state and returns the id of a node which
/// represents the value of the operand.
static err_t read_operand(
    cdfg_builder_t* builder, const pis_operand_t* operand, cdfg_item_id_t* out_node_id
) {
    err_t err = SUCCESS;
    switch (operand->addr.space) {
        case PIS_SPACE_CONST:
            CHECK_RETHROW(make_imm_node(&builder->cdfg, operand->addr.offset, out_node_id));
            break;
        case PIS_SPACE_REG:
            CHECK_RETHROW(read_reg_operand(builder, operand, out_node_id));
            break;
        case PIS_SPACE_TMP:
            CHECK_RETHROW(read_tmp_operand(builder, operand, out_node_id));
            break;
        case PIS_SPACE_RAM:
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

static err_t write_tmp_operand(
    cdfg_builder_t* builder, const pis_operand_t* operand, cdfg_item_id_t value_node_id
) {
    err_t err = SUCCESS;

    cdfg_item_id_t exact_slot_id = find_slot_exact(&builder->op_state, operand);
    if (exact_slot_id != CDFG_ITEM_ID_INVALID) {
        // found an exactly matching slot. overwrite its value with the new value.
        builder->op_state.slots[exact_slot_id].value_node_id = value_node_id;
    } else {
        // no exactly matching slot.

        // make sure that we don't have any intersecting slots, as tmp operands are not allowed to
        // use partial read/writes.
        CHECK(is_operand_fully_uninit(&builder->op_state, operand));

        // add a new slot which contains the new value for this tmp operand
        CHECK_RETHROW(make_op_state_slot(&builder->op_state, operand, value_node_id));
    }

cleanup:
    return err;
}

/// write to a register operand.
static err_t write_reg_operand(
    cdfg_builder_t* builder, const pis_operand_t* operand, cdfg_item_id_t value_node_id
) {
    err_t err = SUCCESS;

    cdfg_item_id_t exact_slot_id = find_slot_exact(&builder->op_state, operand);
    if (exact_slot_id != CDFG_ITEM_ID_INVALID) {
        // found an exactly matching slot. overwrite its value with the new value.
        builder->op_state.slots[exact_slot_id].value_node_id = value_node_id;
    } else {
        // no exact match. either the operand is partially initialized, or it is completely
        // uninitialized.
        //
        // partially initialized nodes are not allowed in the CDFG. the lifter implementations
        // must make sure to not emit intersection GPR accesses to make this ok.
        //
        // so, we expect the operand to be fully uninitialized here.
        CHECK(is_operand_fully_uninit(&builder->op_state, operand));
        // operand is completely uninitialized. just add a new slot which contains the new value
        // for this operand.
        CHECK_RETHROW(make_op_state_slot(&builder->op_state, operand, value_node_id));
    }

cleanup:
    return err;
}

/// writes the given operand to the current op state.
static err_t write_operand(
    cdfg_builder_t* builder, const pis_operand_t* operand, cdfg_item_id_t value_node_id
) {
    err_t err = SUCCESS;
    switch (operand->addr.space) {
        case PIS_SPACE_REG:
            CHECK_RETHROW(write_reg_operand(builder, operand, value_node_id));
            break;
        case PIS_SPACE_TMP:
            CHECK_RETHROW(write_tmp_operand(builder, operand, value_node_id));
            break;
        case PIS_SPACE_CONST:
            // can't write to const operands.
            UNREACHABLE();
            break;
        case PIS_SPACE_RAM:
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

static err_t opcode_handler_binop(
    cdfg_builder_t* builder, const pis_insn_t* insn, cdfg_calculation_t calculation
) {
    err_t err = SUCCESS;
    CHECK_CODE(insn->operands_amount == 3, PIS_ERR_OPCODE_WRONG_OPERANDS_AMOUNT);

    // make sure that all operands are of the same size
    CHECK_TRACE_CODE(
        insn->operands[0].size == insn->operands[1].size &&
            insn->operands[1].size == insn->operands[2].size,
        PIS_ERR_OPERAND_SIZE_MISMATCH,
        "operand size mismatch in opcode %s, operand sizes: %u %u %u",
        pis_opcode_to_str(insn->opcode),
        insn->operands[0].size,
        insn->operands[1].size,
        insn->operands[2].size
    );

    cdfg_item_id_t lhs_node_id = CDFG_ITEM_ID_INVALID;
    CHECK_RETHROW(read_operand(builder, &insn->operands[1], &lhs_node_id));

    cdfg_item_id_t rhs_node_id = CDFG_ITEM_ID_INVALID;
    CHECK_RETHROW(read_operand(builder, &insn->operands[2], &rhs_node_id));

    cdfg_item_id_t result_node_id = CDFG_ITEM_ID_INVALID;
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

    // make sure that all operands are of the same size
    CHECK_TRACE_CODE(
        insn->operands[0].size == insn->operands[1].size,
        PIS_ERR_OPERAND_SIZE_MISMATCH,
        "operand size mismatch in opcode %s, operand sizes: %u %u",
        pis_opcode_to_str(insn->opcode),
        insn->operands[0].size,
        insn->operands[1].size
    );

    cdfg_item_id_t input_node_id = CDFG_ITEM_ID_INVALID;
    CHECK_RETHROW(read_operand(builder, &insn->operands[1], &input_node_id));

    cdfg_item_id_t result_node_id = CDFG_ITEM_ID_INVALID;
    CHECK_RETHROW(make_unary_op_node(&builder->cdfg, calculation, input_node_id, &result_node_id));

    CHECK_RETHROW(write_operand(builder, &insn->operands[0], result_node_id));
cleanup:
    return err;
}

static err_t opcode_handler_comparison(
    cdfg_builder_t* builder, const pis_insn_t* insn, cdfg_calculation_t calculation
) {
    err_t err = SUCCESS;
    CHECK_CODE(insn->operands_amount == 3, PIS_ERR_OPCODE_WRONG_OPERANDS_AMOUNT);

    CHECK_TRACE_CODE(
        insn->operands[0].size == PIS_SIZE_1 && insn->operands[1].size == insn->operands[2].size,
        PIS_ERR_OPERAND_SIZE_MISMATCH,
        "operand size mismatch in opcode %s, operand sizes: %u %u %u",
        pis_opcode_to_str(insn->opcode),
        insn->operands[0].size,
        insn->operands[1].size,
        insn->operands[2].size
    );

    cdfg_item_id_t lhs_node_id = CDFG_ITEM_ID_INVALID;
    CHECK_RETHROW(read_operand(builder, &insn->operands[1], &lhs_node_id));

    cdfg_item_id_t rhs_node_id = CDFG_ITEM_ID_INVALID;
    CHECK_RETHROW(read_operand(builder, &insn->operands[2], &rhs_node_id));

    cdfg_item_id_t result_node_id = CDFG_ITEM_ID_INVALID;
    CHECK_RETHROW(
        make_binop_node(&builder->cdfg, calculation, lhs_node_id, rhs_node_id, &result_node_id)
    );

    CHECK_RETHROW(write_operand(builder, &insn->operands[0], result_node_id));
cleanup:
    return err;
}

/// perform a move instruction without checking the operands.
static err_t do_move_nocheck(cdfg_builder_t* builder, const pis_insn_t* insn) {
    err_t err = SUCCESS;

    cdfg_item_id_t src_node_id = CDFG_ITEM_ID_INVALID;
    CHECK_RETHROW(read_operand(builder, &insn->operands[1], &src_node_id));

    CHECK_RETHROW(write_operand(builder, &insn->operands[0], src_node_id));
cleanup:
    return err;
}

static err_t opcode_handler_move(cdfg_builder_t* builder, const pis_insn_t* insn) {
    err_t err = SUCCESS;
    CHECK_CODE(insn->operands_amount == 2, PIS_ERR_OPCODE_WRONG_OPERANDS_AMOUNT);

    // check operand sizes
    CHECK_CODE(insn->operands[0].size == insn->operands[1].size, PIS_ERR_OPERAND_SIZE_MISMATCH);

    CHECK_RETHROW(do_move_nocheck(builder, insn));
cleanup:
    return err;
}

static err_t opcode_handler_zero_extend(cdfg_builder_t* builder, const pis_insn_t* insn) {
    err_t err = SUCCESS;
    CHECK_CODE(insn->operands_amount == 2, PIS_ERR_OPCODE_WRONG_OPERANDS_AMOUNT);

    // check operand sizes
    CHECK_CODE(insn->operands[0].size > insn->operands[1].size, PIS_ERR_OPERAND_SIZE_MISMATCH);

    CHECK_RETHROW(do_move_nocheck(builder, insn));
cleanup:
    return err;
}

static err_t opcode_handler_get_low_bits(cdfg_builder_t* builder, const pis_insn_t* insn) {
    err_t err = SUCCESS;
    CHECK_CODE(insn->operands_amount == 2, PIS_ERR_OPCODE_WRONG_OPERANDS_AMOUNT);

    // check operand sizes
    CHECK_CODE(insn->operands[0].size < insn->operands[1].size, PIS_ERR_OPERAND_SIZE_MISMATCH);

    CHECK_RETHROW(do_move_nocheck(builder, insn));
cleanup:
    return err;
}

static err_t opcode_handler_store(cdfg_builder_t* builder, const pis_insn_t* insn) {
    err_t err = SUCCESS;
    CHECK_CODE(insn->operands_amount == 2, PIS_ERR_OPCODE_WRONG_OPERANDS_AMOUNT);

    cdfg_item_id_t addr_node_id = CDFG_ITEM_ID_INVALID;
    CHECK_RETHROW(read_operand(builder, &insn->operands[0], &addr_node_id));

    cdfg_item_id_t val_node_id = CDFG_ITEM_ID_INVALID;
    CHECK_RETHROW(read_operand(builder, &insn->operands[1], &val_node_id));

    CHECK_RETHROW(do_store(builder, addr_node_id, val_node_id));

cleanup:
    return err;
}

static err_t opcode_handler_load(cdfg_builder_t* builder, const pis_insn_t* insn) {
    err_t err = SUCCESS;
    CHECK_CODE(insn->operands_amount == 2, PIS_ERR_OPCODE_WRONG_OPERANDS_AMOUNT);

    cdfg_item_id_t addr_node_id = CDFG_ITEM_ID_INVALID;
    CHECK_RETHROW(read_operand(builder, &insn->operands[1], &addr_node_id));

    cdfg_item_id_t loaded_val_node_id = CDFG_ITEM_ID_INVALID;
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
    CHECK_RETHROW(opcode_handler_comparison(builder, insn, CDFG_CALCULATION_UNSIGNED_LESS_THAN));
cleanup:
    return err;
}

static err_t opcode_handler_equals(cdfg_builder_t* builder, const pis_insn_t* insn) {
    err_t err = SUCCESS;
    CHECK_RETHROW(opcode_handler_comparison(builder, insn, CDFG_CALCULATION_EQUALS));
cleanup:
    return err;
}

static err_t opcode_handler_signed_less_than(cdfg_builder_t* builder, const pis_insn_t* insn) {
    err_t err = SUCCESS;
    CHECK_RETHROW(opcode_handler_comparison(builder, insn, CDFG_CALCULATION_SIGNED_LESS_THAN));
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

static err_t opcode_handler_cond_negate(cdfg_builder_t* builder, const pis_insn_t* insn) {
    err_t err = SUCCESS;
    CHECK_RETHROW(opcode_handler_unary_op(builder, insn, CDFG_CALCULATION_COND_NEGATE));
cleanup:
    return err;
}

static err_t opcode_handler_jmp_cond(cdfg_builder_t* builder, const pis_insn_t* insn) {
    err_t err = SUCCESS;

    CHECK_CODE(insn->operands_amount == 2, PIS_ERR_OPCODE_WRONG_OPERANDS_AMOUNT);

    // check operand sizes
    CHECK_CODE(insn->operands[1].size == PIS_SIZE_1, PIS_ERR_OPERAND_SIZE_MISMATCH);

    cdfg_item_id_t cond_node_id = CDFG_ITEM_ID_INVALID;
    CHECK_RETHROW(read_operand(builder, &insn->operands[1], &cond_node_id));

    CHECK_RETHROW(do_if(builder, cond_node_id));

cleanup:
    return err;
}

static err_t opcode_handler_ret(cdfg_builder_t* builder, const pis_insn_t* insn) {
    err_t err = SUCCESS;

    UNUSED(insn);

    cdfg_item_id_t finish_node_id = CDFG_ITEM_ID_INVALID;
    CHECK_RETHROW(make_finish_node(&builder->cdfg, &finish_node_id));

    CHECK_RETHROW(link_cf_node(builder, finish_node_id));

cleanup:
    return err;
}

static opcode_handler_t g_opcode_handlers_table[PIS_OPCODES_AMOUNT] = {
    [PIS_OPCODE_ADD] = opcode_handler_add,
    [PIS_OPCODE_SUB] = opcode_handler_sub,
    [PIS_OPCODE_XOR] = opcode_handler_xor,
    [PIS_OPCODE_OR] = opcode_handler_or,
    [PIS_OPCODE_UNSIGNED_MUL] = opcode_handler_unsigned_mul,
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
    [PIS_OPCODE_COND_NEGATE] = opcode_handler_cond_negate,
    [PIS_OPCODE_JMP_RET] = opcode_handler_ret,
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
        if (slot->value_node_id == CDFG_ITEM_ID_INVALID) {
            // this slot is vacant.
            continue;
        }
        if (slot->operand.addr.space == PIS_SPACE_TMP) {
            // invalidate the slot
            slot->value_node_id = CDFG_ITEM_ID_INVALID;
        }
    }
}

static err_t process_block(cdfg_builder_t* builder, cfg_item_id_t block_id) {
    err_t err = SUCCESS;

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

    // finished processing the block.
    builder->block_states[block_id] = (cdfg_block_state_t) {
        .was_processed = true,
        .final_state = builder->op_state,
    };

cleanup:
    return err;
}

static err_t merge_predecessor_operand_value(
    cdfg_builder_t* builder,
    const pis_operand_t* operand,
    cdfg_item_id_t value_node_id,
    cdfg_item_id_t region_node_id,
    size_t predecessor_index
) {
    err_t err = SUCCESS;

    cdfg_item_id_t phi_node_id;
    cdfg_item_id_t slot_id = find_slot_exact(&builder->op_state, operand);
    if (slot_id == CDFG_ITEM_ID_INVALID) {
        // no exact match. make sure that the operand is fully uninitialized. partial initialization
        // is not allowed when combining predecessors.
        CHECK(is_operand_fully_uninit(&builder->op_state, operand));

        // operand is completely uninitialized. create a phi node for it.
        phi_node_id = CDFG_ITEM_ID_INVALID;
        CHECK_RETHROW(make_phi_node(&builder->cdfg, &phi_node_id));

        // connect the control flow from the region node to our new phi node
        CHECK_RETHROW(
            make_edge(&builder->cdfg, CDFG_EDGE_KIND_CONTROL_FLOW, region_node_id, phi_node_id, 0)
        );

        // add a new slot for it
        CHECK_RETHROW(make_op_state_slot(&builder->op_state, operand, phi_node_id));
    } else {
        // found an exactly matching slot. the slot's value should be a phi node.
        const cdfg_op_state_slot_t* existing_slot = &builder->op_state.slots[slot_id];
        phi_node_id = existing_slot->value_node_id;
    }

    cdfg_node_t* phi_node = &builder->cdfg.node_storage[phi_node_id];
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

/// mergess the op state of the given predecessor block into the current op state.
static err_t merge_predecessor_op_state(
    cdfg_builder_t* builder, cfg_item_id_t predecessor_block_id, size_t predecessor_index
) {
    err_t err = SUCCESS;

    const cdfg_op_state_t* predecessor_block_final_state =
        &builder->block_states[predecessor_block_id].final_state;

    // first, merge the control flow into a region node

    if (builder->op_state.last_cf_node_id == CDFG_ITEM_ID_INVALID) {
        // no node yet, create a new empty region node.
        CHECK_RETHROW(make_region_node(&builder->cdfg, &builder->op_state.last_cf_node_id));
    }


    cdfg_item_id_t region_node_id = builder->op_state.last_cf_node_id;
    cdfg_node_t* region_node = &builder->cdfg.node_storage[region_node_id];

    // connect the control flow to the region node
    CHECK_RETHROW(make_edge(
        &builder->cdfg,
        CDFG_EDGE_KIND_CONTROL_FLOW,
        predecessor_block_final_state->last_cf_node_id,
        builder->op_state.last_cf_node_id,
        predecessor_index
    ));

    // increase the region inputs counter
    region_node->content.region.inputs_amount++;

    // now merge each of the operand values.
    for (size_t i = 0; i < predecessor_block_final_state->used_slots_amount; i++) {
        const cdfg_op_state_slot_t* slot = &predecessor_block_final_state->slots[i];
        if (slot->value_node_id == CDFG_ITEM_ID_INVALID) {
            // this slot is vacant.
        }
        if (slot->operand.addr.space == PIS_SPACE_TMP) {
            // tmp operands don't need to be merged.
            continue;
        }

        // sanity. only registers should be merged.
        CHECK(slot->operand.addr.space == PIS_SPACE_REG);

        // merge the value
        CHECK_RETHROW(merge_predecessor_operand_value(
            builder,
            &slot->operand,
            slot->value_node_id,
            region_node_id,
            predecessor_index
        ));
    }

cleanup:
    return err;
}

static err_t prepare_non_first_block_initial_op_state(
    cdfg_builder_t* builder, cfg_item_id_t prepared_block_id, bool* can_process_block
) {
    err_t err = SUCCESS;

    builder->op_state.used_slots_amount = 0;
    builder->op_state.last_cf_node_id = CDFG_ITEM_ID_INVALID;

    size_t found_predecessors_amount = 0;

    // we want to merge the op states of all direct predecessors of this block
    for (size_t i = 0; i < builder->cfg->blocks_amount; i++) {
        if (i == prepared_block_id) {
            // skip the block itself
            continue;
        }

        bool is_direct_predecessor = false;
        CHECK_RETHROW(cfg_block_is_direct_predecessor(
            builder->cfg,
            i,
            prepared_block_id,
            &is_direct_predecessor
        ));
        if (is_direct_predecessor) {
            // the current block is a direct predecessor of the prepared block, so we should use all
            // its op state.
            if (!builder->block_states[i].was_processed) {
                // this block wasn't yet processed, but is required to process the prepared block.
                *can_process_block = false;
                SUCCESS_CLEANUP();
            }

            // the prepared block may have multiple predecessors, and we want to merge all of
            // their op states into one.
            CHECK_RETHROW(merge_predecessor_op_state(builder, i, found_predecessors_amount));

            found_predecessors_amount++;
        }
    }

    // make sure that we found any predecessors. only the first block is allowed to have no
    // predecessors.
    CHECK(found_predecessors_amount > 0);

    // our op state should now represent a merged state of all predecessors. all values are
    // merged using phi nodes.
    // in some cases, one of the predecessors might initialize a register while another predecessor
    // does not. in this case, we will have partially initialized phi nodes, which only have some of
    // their inputs connected.
    // in those cases, we want to treat the register as uninitialized, since safe code should not
    // use potentially uninitialized registers.
    for (size_t i = 0; i < builder->op_state.used_slots_amount; i++) {
        cdfg_op_state_slot_t* slot = &builder->op_state.slots[i];
        if (slot->value_node_id == CDFG_ITEM_ID_INVALID) {
            // this slot is vacant.
            continue;
        }
        cdfg_item_id_t phi_node_id = slot->value_node_id;
        cdfg_node_t* phi_node = &builder->cdfg.node_storage[phi_node_id];
        if (phi_node->content.phi.inputs_amount != found_predecessors_amount) {
            // sanity
            CHECK(phi_node->content.phi.inputs_amount < found_predecessors_amount);

            // invalidate this slot to make this register uninitialized
            slot->value_node_id = CDFG_ITEM_ID_INVALID;
        }
    }

    *can_process_block = true;

cleanup:
    return err;
}

static err_t prepare_block_initial_op_state(
    cdfg_builder_t* builder, cfg_item_id_t block_id, bool* can_process_block
) {
    err_t err = SUCCESS;


    if (block_id == 0) {
        // for the first block, create an empty op state with a single initial entry node.
        builder->op_state.used_slots_amount = 0;
        builder->op_state.last_cf_node_id = CDFG_ITEM_ID_INVALID;
        CHECK_RETHROW(make_entry_node(&builder->cdfg, &builder->op_state.last_cf_node_id));
        *can_process_block = true;
    } else {
        // non-first blocks require some more complex logic
        CHECK_RETHROW(prepare_non_first_block_initial_op_state(builder, block_id, can_process_block)
        );
    }
cleanup:
    return err;
}

static bool is_node_used_as_input(const cdfg_t* cdfg, cdfg_item_id_t node_id) {
    for (size_t i = 0; i < cdfg->edges_amount; i++) {
        if (cdfg->edge_storage[i].from_node == node_id) {
            return true;
        }
    }
    return false;
}

static bool does_node_use_cf(const cdfg_t* cdfg, cdfg_item_id_t node_id) {
    for (size_t i = 0; i < cdfg->edges_amount; i++) {
        const cdfg_edge_t* edge = &cdfg->edge_storage[i];
        if (edge->kind == CDFG_EDGE_KIND_CONTROL_FLOW && edge->to_node == node_id) {
            return true;
        }
    }
    return false;
}

/// removes unused nodes and edges. returns whether any nodes or edges were removed.
static bool remove_unused_nodes_and_edges(cdfg_t* cdfg) {
    bool removed_anything = false;
    for (size_t i = 0; i < cdfg->nodes_amount; i++) {
        cdfg_node_t* node = &cdfg->node_storage[i];
        if (node->kind == CDFG_NODE_KIND_INVALID) {
            // node is vacant.
            continue;
        }

        bool is_node_required = is_node_used_as_input(cdfg, i) || does_node_use_cf(cdfg, i) ||
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
        if (edge->to_node == CDFG_ITEM_ID_INVALID) {
            // this edge is vacant.
            continue;
        }
        const cdfg_node_t* to_node = &cdfg->node_storage[edge->to_node];
        if (to_node->kind == CDFG_NODE_KIND_INVALID) {
            edge->from_node = CDFG_ITEM_ID_INVALID;
            edge->to_node = CDFG_ITEM_ID_INVALID;
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
    cdfg_item_id_t node_id,
    cdfg_item_id_t* out_found_item_id
) {
    err_t err = SUCCESS;
    cdfg_item_id_t found_id = CDFG_ITEM_ID_INVALID;
    for (size_t i = 0; i < cdfg->edges_amount; i++) {
        const cdfg_edge_t* edge = &cdfg->edge_storage[i];
        if (edge->to_node == node_id && edge->kind == kind) {
            // make sure that we don't find multiple matchine edges.
            CHECK(found_id == CDFG_ITEM_ID_INVALID);

            found_id = i;
        }
    }

    // make sure that we found any matching edge.
    CHECK(found_id != CDFG_ITEM_ID_INVALID);

    *out_found_item_id = found_id;
cleanup:
    return err;
}

/// replaces all usages of the given node as a the "from" node of an edge with the given other node.
static void node_replace_usages(
    cdfg_t* cdfg, cdfg_item_id_t node_id_to_replace, cdfg_item_id_t replace_with_node_id
) {
    for (size_t i = 0; i < cdfg->edges_amount; i++) {
        if (cdfg->edge_storage[i].from_node == node_id_to_replace) {
            cdfg->edge_storage[i].from_node = replace_with_node_id;
        }
    }
}

static err_t remove_single_input_region_phi_nodes(cdfg_t* cdfg, bool* did_anything) {
    err_t err = SUCCESS;

    for (size_t i = 0; i < cdfg->nodes_amount; i++) {
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

        cdfg_item_id_t input_edge_id = CDFG_ITEM_ID_INVALID;
        CHECK_RETHROW(node_find_single_input_edge(cdfg, desired_edge_kind, i, &input_edge_id));

        cdfg_edge_t* edge = &cdfg->edge_storage[input_edge_id];

        // this phi/region node has a single input, its index should be zero.
        CHECK(edge->to_node_input_index == 0);

        // find the underlying node of this phi/region node
        cdfg_item_id_t underlying_node_id = edge->from_node;

        // replace all usages of the phi/region node with the underlying node.
        node_replace_usages(cdfg, i, underlying_node_id);

        // invalidate the current node. no need to remove the edges since they will be removed by
        // other optimization passes.
        node->kind = CDFG_NODE_KIND_INVALID;

        *did_anything = true;
    }
cleanup:
    return err;
}

static err_t node_find_inputs(
    const cdfg_t* cdfg,
    cdfg_item_id_t node_id,
    cdfg_edge_kind_t edge_kind,
    cdfg_item_id_t* input_node_ids,
    size_t inputs_amount
) {
    err_t err = SUCCESS;
    size_t cur_inputs_amount = 0;
    for (size_t i = 0; i < cdfg->edges_amount; i++) {
        const cdfg_edge_t* edge = &cdfg->edge_storage[i];
        if (edge->to_node != node_id || edge->kind != edge_kind) {
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

static err_t binop_node_find_data_inputs(
    const cdfg_t* cdfg, cdfg_item_id_t node_id, cdfg_item_id_t input_node_ids[2]
) {
    err_t err = SUCCESS;

    CHECK_RETHROW(node_find_inputs(cdfg, node_id, CDFG_EDGE_KIND_DATA_FLOW, input_node_ids, 2));

cleanup:
    return err;
}

typedef bool (*node_predicate_t)(const cdfg_t* cdfg, cdfg_item_id_t node_id);

static err_t node_find_input_by_predicate(
    const cdfg_t* cdfg,
    cdfg_item_id_t node_id,
    cdfg_edge_kind_t edge_kind,
    node_predicate_t predicate,
    cdfg_item_id_t* out_found_node_id
) {
    err_t err = SUCCESS;

    cdfg_item_id_t found_node_id = CDFG_ITEM_ID_INVALID;
    for (size_t i = 0; i < cdfg->edges_amount; i++) {
        const cdfg_edge_t* edge = &cdfg->edge_storage[i];
        // make sure that the edge has the right kind
        if (edge->kind != edge_kind) {
            continue;
        }

        // make sure that the edge points to our node
        if (edge->to_node != node_id) {
            continue;
        }

        // make sure that the predicate holds for the src node
        if (!predicate(cdfg, edge->from_node)) {
            continue;
        }

        // make sure that we only found one such item.
        CHECK(found_node_id == CDFG_ITEM_ID_INVALID);

        found_node_id = edge->from_node;
    }

    *out_found_node_id = found_node_id;

cleanup:
    return err;
}

static bool node_is_zero_imm(const cdfg_t* cdfg, cdfg_item_id_t node_id) {
    const cdfg_node_t* from_node = &cdfg->node_storage[node_id];
    return from_node->kind == CDFG_NODE_KIND_IMM && from_node->content.imm.value == 0;
}

static bool node_is_sub(const cdfg_t* cdfg, cdfg_item_id_t node_id) {
    const cdfg_node_t* from_node = &cdfg->node_storage[node_id];
    return from_node->kind == CDFG_NODE_KIND_CALC &&
           from_node->content.calc.calculation == CDFG_CALCULATION_SUB;
}

static err_t optimize_sub_equals_zero(cdfg_t* cdfg, bool* did_anything) {
    err_t err = SUCCESS;

    for (size_t cur_node_id = 0; cur_node_id < cdfg->nodes_amount; cur_node_id++) {
        cdfg_node_t* node = &cdfg->node_storage[cur_node_id];
        if (node->kind != CDFG_NODE_KIND_CALC) {
            continue;
        }
        if (node->content.calc.calculation != CDFG_CALCULATION_EQUALS) {
            continue;
        }

        // the current node is an equals node.

        // we need one of the inputs to be a zero immediate operand.
        cdfg_item_id_t zero_imm_node_id = CDFG_ITEM_ID_INVALID;
        CHECK_RETHROW(node_find_input_by_predicate(
            cdfg,
            cur_node_id,
            CDFG_EDGE_KIND_DATA_FLOW,
            node_is_zero_imm,
            &zero_imm_node_id
        ));
        if (zero_imm_node_id == CDFG_ITEM_ID_INVALID) {
            continue;
        }

        // we need another one of the inputs to be a sub operation.
        cdfg_item_id_t sub_node_id = CDFG_ITEM_ID_INVALID;
        CHECK_RETHROW(node_find_input_by_predicate(
            cdfg,
            cur_node_id,
            CDFG_EDGE_KIND_DATA_FLOW,
            node_is_sub,
            &sub_node_id
        ));
        if (sub_node_id == CDFG_ITEM_ID_INVALID) {
            continue;
        }

        // doing `x - y == 0` is like doing `x == y`, so we want to create an equals node with the
        // same operands as the sub node.
        cdfg_item_id_t sub_input_node_ids[2] = {};
        CHECK_RETHROW(binop_node_find_data_inputs(cdfg, sub_node_id, sub_input_node_ids));

        cdfg_item_id_t optimized_eq_node_id = CDFG_ITEM_ID_INVALID;
        CHECK_RETHROW(make_binop_node(
            cdfg,
            CDFG_CALCULATION_EQUALS,
            sub_input_node_ids[0],
            sub_input_node_ids[1],
            &optimized_eq_node_id
        ));

        node_replace_usages(cdfg, cur_node_id, optimized_eq_node_id);

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

err_t cdfg_build(cdfg_builder_t* builder, const cfg_t* cfg, pis_endianness_t endianness) {
    err_t err = SUCCESS;

    // initialize the builder
    builder->endianness = endianness;
    builder->cfg = cfg;
    cdfg_reset(&builder->cdfg);

    while (1) {
        bool processed_any_blocks = false;
        for (size_t i = 0; i < cfg->blocks_amount; i++) {
            if (builder->block_states[i].was_processed) {
                // this block was already processed.
                continue;
            }
            // prepare the initial op state for the block
            bool can_process_block = false;
            CHECK_RETHROW(prepare_block_initial_op_state(builder, i, &can_process_block));

            if (!can_process_block) {
                // we can't yet process this block, since some of the blocks that are needed to
                // process this one have not been processed yet, so skip it for now.
                continue;
            }

            // process the block
            CHECK_RETHROW(process_block(builder, i));
            processed_any_blocks = true;
        }

        if (!processed_any_blocks) {
            break;
        }
    }

    // make sure that all blocks were properly processed
    for (size_t i = 0; i < cfg->blocks_amount; i++) {
        CHECK_TRACE(
            builder->block_states[i].was_processed,
            "block %lu was not processed while building the CDFG",
            i
        );
    }

cleanup:
    return err;
}

static void cdfg_dump_node_desc(const cdfg_node_t* node) {
    switch (node->kind) {
        case CDFG_NODE_KIND_ENTRY:
            TRACE_NO_NEWLINE("entry");
            break;
        case CDFG_NODE_KIND_FINISH:
            TRACE_NO_NEWLINE("finish");
            break;
        case CDFG_NODE_KIND_VAR:
            TRACE_NO_NEWLINE(
                "var_off_0x%lx_sz_%u",
                node->content.var.reg_offset,
                pis_size_to_bytes(node->content.var.reg_size)
            );
            break;
        case CDFG_NODE_KIND_IMM:
            TRACE_NO_NEWLINE("imm_0x%lx", node->content.imm.value);
            break;
        case CDFG_NODE_KIND_CALC:
            TRACE_NO_NEWLINE("calc_%s", cdfg_calculation_to_str(node->content.calc.calculation));
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
    }
}

static void cdfg_dump_node(const cdfg_t* cdfg, cdfg_item_id_t node_id) {
    TRACE_NO_NEWLINE("id_%u_", node_id);
    cdfg_dump_node_desc(&cdfg->node_storage[node_id]);
}

/// dumps a DOT representation of the CDFG to stdout.
void cdfg_dump_dot(const cdfg_t* cdfg) {
    TRACE("digraph {");

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

    for (size_t i = 0; i < cdfg->edges_amount; i++) {
        const cdfg_edge_t* edge = &cdfg->edge_storage[i];
        if (edge->from_node == CDFG_ITEM_ID_INVALID) {
            // the edge is vacant.
            continue;
        }
        cdfg_dump_node(cdfg, edge->from_node);
        TRACE_NO_NEWLINE(" -> ");
        cdfg_dump_node(cdfg, edge->to_node);
        TRACE();
    }
    TRACE("}");
}
