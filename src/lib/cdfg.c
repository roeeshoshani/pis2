#include "cdfg.h"
#include "endianness.h"
#include "errors.h"
#include "except.h"
#include "operand_size.h"
#include "pis.h"
#include "trace.h"
#include <string.h>

typedef err_t (*opcode_handler_t)(cdfg_builder_t* builder, const pis_insn_t* insn);

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

/// returns an immediate node with the given immediate value, either by creating one or by reusing
/// an existing one.
static err_t make_imm_node(cdfg_t* cdfg, u64 value, cdfg_item_id_t* out_node_id) {
    err_t err = SUCCESS;

    cdfg_item_id_t node_id = find_imm_node(cdfg, value);

    if (node_id == CDFG_ITEM_ID_INVALID) {
        // no existing node, create a new one.
        CHECK_RETHROW(next_node_id(cdfg, &node_id));

        cdfg_node_t* node = &cdfg->node_storage[node_id];
        node->content.imm.value = value;
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

static err_t make_store_node(cdfg_t* cdfg, cdfg_item_id_t* out_node_id) {
    err_t err = SUCCESS;

    cdfg_item_id_t node_id = CDFG_ITEM_ID_INVALID;
    CHECK_RETHROW(next_node_id(cdfg, &node_id));

    cdfg->node_storage[node_id] = (cdfg_node_t) {
        .kind = CDFG_NODE_KIND_STORE,
        .content = {},
    };

    *out_node_id = node_id;
cleanup:
    return err;
}

static err_t make_load_node(cdfg_t* cdfg, cdfg_item_id_t* out_node_id) {
    err_t err = SUCCESS;

    cdfg_item_id_t node_id = CDFG_ITEM_ID_INVALID;
    CHECK_RETHROW(next_node_id(cdfg, &node_id));

    cdfg->node_storage[node_id] = (cdfg_node_t) {
        .kind = CDFG_NODE_KIND_LOAD,
        .content = {},
    };

    *out_node_id = node_id;
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

    cdfg_item_id_t node_id = CDFG_ITEM_ID_INVALID;
    CHECK_RETHROW(next_node_id(cdfg, &node_id));

    cdfg->node_storage[node_id] = (cdfg_node_t) {
        .kind = CDFG_NODE_KIND_ENTRY,
        .content = {},
    };

    *out_node_id = node_id;
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

static err_t calc_extracted_byte_operand(
    const pis_operand_t* operand, size_t byte_index, pis_operand_t* out_byte_operand
) {
    err_t err = SUCCESS;
    pis_addr_t cur_byte_addr = {};
    CHECK_RETHROW(pis_addr_add(&operand->addr, byte_index, &cur_byte_addr));
    *out_byte_operand = PIS_OPERAND(cur_byte_addr, PIS_SIZE_1);
cleanup:
    return err;
}

/// calculates the shift amount by which a value needs to be shifted to extract the byte at the
/// given index from it.
static err_t extract_byte_shift_amount(
    size_t byte_index, size_t value_size_in_bytes, pis_endianness_t endianness, size_t* shift_amount
) {
    err_t err = SUCCESS;

    size_t value_size_in_bits = value_size_in_bytes * 8;
    size_t bit_index = byte_index * 8;

    switch (endianness) {
        case PIS_ENDIANNESS_LITTLE:
            *shift_amount = bit_index;
            break;
        case PIS_ENDIANNESS_BIG:
            *shift_amount = value_size_in_bits - 8 - bit_index;
            break;
        default:
            UNREACHABLE();
    }

cleanup:
    return err;
}

/// builds a node which represents the extraction of the byte at the given index from the value
/// represented by the given node id.
static err_t extract_byte(
    cdfg_builder_t* builder,
    cdfg_item_id_t value_node_id,
    size_t value_size_in_bytes,
    size_t byte_index,
    cdfg_item_id_t* out_node_id
) {
    err_t err = SUCCESS;

    size_t shift_amount = 0;
    CHECK_RETHROW(extract_byte_shift_amount(
        byte_index,
        value_size_in_bytes,
        builder->endianness,
        &shift_amount
    ));

    cdfg_item_id_t shift_amount_node_id = CDFG_ITEM_ID_INVALID;
    CHECK_RETHROW(make_imm_node(&builder->cdfg, shift_amount, &shift_amount_node_id));

    cdfg_item_id_t shifted_val_node_id = CDFG_ITEM_ID_INVALID;
    CHECK_RETHROW(make_binop_node(
        &builder->cdfg,
        CDFG_CALCULATION_SHIFT_RIGHT,
        value_node_id,
        shift_amount_node_id,
        &shifted_val_node_id
    ));

    cdfg_item_id_t mask_node_id = CDFG_ITEM_ID_INVALID;
    CHECK_RETHROW(make_imm_node(&builder->cdfg, 0xff, &mask_node_id));

    cdfg_item_id_t masked_val_node_id = CDFG_ITEM_ID_INVALID;
    CHECK_RETHROW(make_binop_node(
        &builder->cdfg,
        CDFG_CALCULATION_AND,
        shifted_val_node_id,
        mask_node_id,
        &masked_val_node_id
    ));

    *out_node_id = masked_val_node_id;

cleanup:
    return err;
}

/// left-shifts the given byte value node id such that it is placed at the requested byte index in
/// the reconstructed value.
static err_t reconstruct_byte(
    cdfg_builder_t* builder,
    cdfg_item_id_t byte_value_node_id,
    size_t value_size_in_bytes,
    size_t byte_index,
    cdfg_item_id_t* out_node_id
) {
    err_t err = SUCCESS;

    size_t shift_amount = 0;
    CHECK_RETHROW(extract_byte_shift_amount(
        byte_index,
        value_size_in_bytes,
        builder->endianness,
        &shift_amount
    ));

    cdfg_item_id_t shift_amount_node_id = CDFG_ITEM_ID_INVALID;
    CHECK_RETHROW(make_imm_node(&builder->cdfg, shift_amount, &shift_amount_node_id));

    cdfg_item_id_t shifted_val_node_id = CDFG_ITEM_ID_INVALID;
    CHECK_RETHROW(make_binop_node(
        &builder->cdfg,
        CDFG_CALCULATION_SHIFT_LEFT,
        byte_value_node_id,
        shift_amount_node_id,
        &shifted_val_node_id
    ));

    *out_node_id = shifted_val_node_id;

cleanup:
    return err;
}

/// breaks the specified op state slot to byte-by-byte slots.
static err_t break_op_state_slot_to_bytes(cdfg_builder_t* builder, cdfg_item_id_t slot_id) {
    err_t err = SUCCESS;
    cdfg_op_state_slot_t* slot = &builder->op_state.slots[slot_id];
    if (slot->operand.size == PIS_SIZE_1) {
        // the operand is already a single byte, so we don't need to do anything.
        SUCCESS_CLEANUP();
    }

    // copy out the content of the slot as we are about to overwrite it.
    cdfg_op_state_slot_t orig_slot = *slot;

    // extract each of the bytes of the operand into its own slot.
    u32 bytes = pis_size_to_bytes(orig_slot.operand.size);
    for (size_t i = 0; i < bytes; i++) {
        // first, choose the slot in which we will store this byte
        cdfg_item_id_t cur_byte_slot_id;
        if (i == 0) {
            // the first byte is stored in the original slot
            cur_byte_slot_id = slot_id;
        } else {
            // we allocate a new slots for the rest of the bytes
            CHECK_RETHROW(next_op_state_slot_id(&builder->op_state, &cur_byte_slot_id));
        }

        // calculate the byte value
        cdfg_item_id_t cur_byte_value_node_id = CDFG_ITEM_ID_INVALID;
        CHECK_RETHROW(
            extract_byte(builder, orig_slot.value_node_id, bytes, i, &cur_byte_value_node_id)
        );

        // calculate the operand that represents the byte value
        pis_operand_t cur_byte_operand = {};
        CHECK_RETHROW(calc_extracted_byte_operand(&orig_slot.operand, i, &cur_byte_operand));

        // store it in the slot
        builder->op_state.slots[cur_byte_slot_id] = (cdfg_op_state_slot_t) {
            .operand = cur_byte_operand,
            .value_node_id = cur_byte_value_node_id,
        };
    }
cleanup:
    return err;
}

/// break all op state slots that intersect with the given operand to individual bytes.
static err_t
    break_intersecting_slots_to_bytes(cdfg_builder_t* builder, const pis_operand_t* operand) {
    err_t err = SUCCESS;

    for (size_t i = 0; i < builder->op_state.used_slots_amount; i++) {
        const cdfg_op_state_slot_t* slot = &builder->op_state.slots[i];
        if (slot->value_node_id == CDFG_ITEM_ID_INVALID) {
            // this slot is vacant.
            continue;
        }
        if (pis_operands_intersect(operand, &slot->operand)) {
            CHECK_RETHROW(break_op_state_slot_to_bytes(builder, i));
        }
    }

cleanup:
    return err;
}

static err_t make_var_node(
    cdfg_builder_t* builder, const pis_operand_t* reg_operand, cdfg_item_id_t* out_node_id
) {
    err_t err = SUCCESS;

    CHECK(reg_operand->addr.space == PIS_SPACE_REG);

    cdfg_item_id_t node_id = CDFG_ITEM_ID_INVALID;
    CHECK_RETHROW(next_node_id(&builder->cdfg, &node_id));
    builder->cdfg.node_storage[node_id] = (cdfg_node_t) {
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

    *out_node_id = node_id;
cleanup:
    return err;
}

/// read a register operand byte by byte. this is used when no exact match operand it found for the
/// register operand, and it requires partial reads.
static err_t read_reg_operand_byte_by_byte(
    cdfg_builder_t* builder, const pis_operand_t* operand, cdfg_item_id_t* out_node_id
) {
    err_t err = SUCCESS;

    // first, break apart all existing operands that intersect with this operand to byte-by-byte
    // operands.
    CHECK_RETHROW(break_intersecting_slots_to_bytes(builder, operand));

    cdfg_item_id_t reconstructed_val_node_id = CDFG_ITEM_ID_INVALID;

    u32 bytes = pis_size_to_bytes(operand->size);
    for (size_t i = 0; i < bytes; i++) {
        // calculate the operand that represents the byte value
        pis_operand_t cur_byte_operand = {};
        CHECK_RETHROW(calc_extracted_byte_operand(operand, i, &cur_byte_operand));

        // calculate the byte value of the current byte
        cdfg_item_id_t cur_byte_val_node_id =
            read_operand_exact(&builder->op_state, &cur_byte_operand);
        if (cur_byte_val_node_id == CDFG_ITEM_ID_INVALID) {
            // this byte is uninitialized, create a variable for it.
            CHECK_RETHROW(make_var_node(builder, &cur_byte_operand, &cur_byte_val_node_id));
        }

        cdfg_item_id_t cur_byte_reconstructed_node_id = CDFG_ITEM_ID_INVALID;
        CHECK_RETHROW(reconstruct_byte(
            builder,
            cur_byte_val_node_id,
            bytes,
            i,
            &cur_byte_reconstructed_node_id
        ));

        // append the current reconstructed byte to the full reconstructed value.
        if (reconstructed_val_node_id == CDFG_ITEM_ID_INVALID) {
            reconstructed_val_node_id = cur_byte_reconstructed_node_id;
        } else {
            // bitwise or the currnet byte into the full reconstructed value
            cdfg_item_id_t ored_values_node_id = CDFG_ITEM_ID_INVALID;
            CHECK_RETHROW(make_binop_node(
                &builder->cdfg,
                CDFG_CALCULATION_OR,
                reconstructed_val_node_id,
                cur_byte_reconstructed_node_id,
                &ored_values_node_id
            ));

            reconstructed_val_node_id = ored_values_node_id;
        }
    }

    CHECK(reconstructed_val_node_id != CDFG_ITEM_ID_INVALID);
    *out_node_id = reconstructed_val_node_id;

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
        CHECK_RETHROW(make_var_node(builder, operand, &node_id));

        // now add a slot in the op state to point to it
        CHECK_RETHROW(make_op_state_slot(&builder->op_state, operand, node_id));

        *out_node_id = node_id;
    } else {
        // node is either fully initialized or partially initialized.
        cdfg_item_id_t exact_match_node_id = read_operand_exact(&builder->op_state, operand);
        if (exact_match_node_id != CDFG_ITEM_ID_INVALID) {
            // found an exact match for the node, use it.
            *out_node_id = exact_match_node_id;
        } else {
            // no exact match for the node. this means that the node requires partial reading.
            // implementing this is really complicated as it must be able to combine multiple
            // relevant op state slots, and it must be able to represent partially uninitialized
            // regions in the resulting value, since it might be partially initialized.
            //
            // instead of doing this, we are breaking all slots related to this operand to
            // byte-by-byte slots and then read it byte-by-byte, which is much simpler than handling
            // all edge cases of partial reads.
            CHECK_RETHROW(read_reg_operand_byte_by_byte(builder, operand, out_node_id));
        }
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

/// write to a partially initialized register operand.
static err_t write_reg_operand_partially_init(
    cdfg_builder_t* builder, const pis_operand_t* operand, cdfg_item_id_t value_node_id
) {
    err_t err = SUCCESS;

    // first, break all existing slots that intersect with this operand to bytes.
    CHECK_RETHROW(break_intersecting_slots_to_bytes(builder, operand));

    // now write the operand byte-by-byte
    u32 bytes = pis_size_to_bytes(operand->size);
    for (size_t i = 0; i < bytes; i++) {
        // calculate the value of the current byte
        cdfg_item_id_t cur_byte_val_node_id = CDFG_ITEM_ID_INVALID;
        CHECK_RETHROW(extract_byte(builder, value_node_id, bytes, i, &cur_byte_val_node_id));

        // calculate the operand of the current byte
        pis_operand_t cur_byte_operand = {};
        CHECK_RETHROW(calc_extracted_byte_operand(operand, i, &cur_byte_operand));

        cdfg_item_id_t cur_byte_slot_id = find_slot_exact(&builder->op_state, &cur_byte_operand);
        if (cur_byte_slot_id != CDFG_ITEM_ID_INVALID) {
            // found an existing slot. overwrite its value with the new value.
            builder->op_state.slots[cur_byte_slot_id].value_node_id = cur_byte_val_node_id;
        } else {
            // no existing slot. just add a new slot which contains the new value for this operand.
            CHECK_RETHROW(
                make_op_state_slot(&builder->op_state, &cur_byte_operand, cur_byte_val_node_id)
            );
        }
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
        if (is_operand_fully_uninit(&builder->op_state, operand)) {
            // operand is completely uninitialized. just add a new slot which contains the new value
            // for this operand.
            CHECK_RETHROW(make_op_state_slot(&builder->op_state, operand, value_node_id));
        } else {
            // operand is partially initialized.
            CHECK_RETHROW(write_reg_operand_partially_init(builder, operand, value_node_id));
        }
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

static err_t opcode_handler_move(cdfg_builder_t* builder, const pis_insn_t* insn) {
    err_t err = SUCCESS;
    CHECK_CODE(insn->operands_amount == 2, PIS_ERR_OPCODE_WRONG_OPERANDS_AMOUNT);

    // check operand sizes
    CHECK_CODE(insn->operands[0].size == insn->operands[1].size, PIS_ERR_OPERAND_SIZE_MISMATCH);

    cdfg_item_id_t src_node_id = CDFG_ITEM_ID_INVALID;
    CHECK_RETHROW(read_operand(builder, &insn->operands[1], &src_node_id));

    CHECK_RETHROW(write_operand(builder, &insn->operands[0], src_node_id));
cleanup:
    return err;
}

static err_t opcode_handler_zero_extend(cdfg_builder_t* builder, const pis_insn_t* insn) {
    err_t err = SUCCESS;
    CHECK_CODE(insn->operands_amount == 2, PIS_ERR_OPCODE_WRONG_OPERANDS_AMOUNT);

    // check operand sizes
    CHECK_CODE(insn->operands[0].size > insn->operands[1].size, PIS_ERR_OPERAND_SIZE_MISMATCH);

    cdfg_item_id_t src_node_id = CDFG_ITEM_ID_INVALID;
    CHECK_RETHROW(read_operand(builder, &insn->operands[1], &src_node_id));

    CHECK_RETHROW(write_operand(builder, &insn->operands[0], src_node_id));
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

static opcode_handler_t g_opcode_handlers_table[PIS_OPCODES_AMOUNT] = {
    [PIS_OPCODE_ADD] = opcode_handler_add,
    [PIS_OPCODE_MOVE] = opcode_handler_move,
    [PIS_OPCODE_STORE] = opcode_handler_store,
    [PIS_OPCODE_LOAD] = opcode_handler_load,
    [PIS_OPCODE_ZERO_EXTEND] = opcode_handler_zero_extend,
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

err_t cdfg_build(cdfg_builder_t* builder, const cfg_t* cfg, pis_endianness_t endianness) {
    err_t err = SUCCESS;

    // initialize the builder
    builder->endianness = endianness;
    builder->op_state.used_slots_amount = 0;
    cdfg_reset(&builder->cdfg);

    // create the entry node
    CHECK_RETHROW(make_entry_node(&builder->cdfg, &builder->op_state.last_cf_node_id));

    // TODO: how do we handle the flow here? for now i just lift the first block...
    const cfg_block_t* block = &cfg->block_storage[0];
    CHECK(block->units_amount > 0);

    const cfg_unit_t* block_units = &cfg->unit_storage[block->first_unit_id];
    for (size_t unit_idx = 0; unit_idx < block->units_amount; unit_idx++) {
        const cfg_unit_t* unit = &block_units[unit_idx];
        const pis_insn_t* unit_insns = &cfg->insn_storage[unit->first_insn_id];
        for (size_t insn_idx = 0; insn_idx < unit->insns_amount; insn_idx++) {
            const pis_insn_t* insn = &unit_insns[insn_idx];
            CHECK_RETHROW(process_insn(builder, insn));
        }
    }

cleanup:
    return err;
}

/// dumps a DOT representation of the CDFG to stdout.
void cdfg_dump_dot(cdfg_t* cdfg) {
    TRACE("graph {");
    for (size_t i = 0; i < cdfg->edges_amount; i++) {
        cdfg_edge_t* edge = &cdfg->edge_storage[i];
        TRACE("%u -> %u", edge->from_node, edge->to_node);
    }
    TRACE("}");
}
