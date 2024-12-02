#include "query.h"

err_t cdfg_find_inputs(
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

err_t cdfg_find_binop_inputs(
    const cdfg_t* cdfg, cdfg_node_id_t node_id, cdfg_node_id_t input_node_ids[2]
) {
    err_t err = SUCCESS;

    CHECK_RETHROW(cdfg_find_inputs(cdfg, node_id, CDFG_EDGE_KIND_DATA_FLOW, input_node_ids, 2));

cleanup:
    return err;
}

err_t cdfg_find_1_of_2_inputs(
    const cdfg_t* cdfg,
    cdfg_node_id_t node_id,
    cdfg_node_predicate_t predicate,
    u64 ctx,
    cdfg_find_1_of_2_inputs_res_t* result
) {
    err_t err = SUCCESS;

    cdfg_node_id_t inputs[2] = {};
    CHECK_RETHROW(cdfg_find_binop_inputs(cdfg, node_id, inputs));

    bool is_first_input_matching = false;
    CHECK_RETHROW(predicate(cdfg, inputs[0], ctx, &is_first_input_matching));
    if (is_first_input_matching) {
        result->found = true;
        result->matching_input = inputs[0];
        result->other_input = inputs[1];
        SUCCESS_CLEANUP();
    }

    bool is_second_input_matching = false;
    CHECK_RETHROW(predicate(cdfg, inputs[1], ctx, &is_second_input_matching));
    if (is_second_input_matching) {
        result->found = true;
        result->matching_input = inputs[1];
        result->other_input = inputs[0];
        SUCCESS_CLEANUP();
    }

    result->found = false;
    result->matching_input.id = CDFG_ITEM_ID_INVALID;
    result->other_input.id = CDFG_ITEM_ID_INVALID;

cleanup:
    return err;
}

err_t cdfg_find_one_input(
    const cdfg_t* cdfg,
    cdfg_node_id_t node_id,
    cdfg_edge_kind_t edge_kind,
    cdfg_node_predicate_t predicate,
    u64 ctx,
    cdfg_node_id_t* out_node_id
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
        bool is_matching = false;
        CHECK_RETHROW(predicate(cdfg, edge->from_node, ctx, &is_matching));
        if (!is_matching) {
            continue;
        }

        if (found_node_id.id != CDFG_ITEM_ID_INVALID) {
            // if we found more than one match, return as if there was no match at all
            found_node_id.id = CDFG_ITEM_ID_INVALID;
            break;
        }

        found_node_id = edge->from_node;
    }

    *out_node_id = found_node_id;

cleanup:
    return err;
}

err_t cdfg_node_is_param(const cdfg_t* cdfg, cdfg_node_id_t node_id, u64 ctx, bool* is_matching) {
    size_t param_index = (size_t) ctx;

    const cdfg_node_t* node = &cdfg->node_storage[node_id.id];

    *is_matching =
        node->kind == CDFG_NODE_KIND_VAR &&
        node->content.var.reg_region.offset == cdfg->arch->params[param_index]->region.offset;

    return SUCCESS;
}

err_t cdfg_detect_phi_loop(
    const cdfg_t* cdfg, cdfg_node_id_t node_id, cdfg_detect_phi_loop_res_t* result
) {
    err_t err = SUCCESS;

    result->is_phi_loop = false;

    const cdfg_node_t* node = &cdfg->node_storage[node_id.id];
    if (node->kind != CDFG_NODE_KIND_PHI) {
        SUCCESS_CLEANUP();
    }
    if (node->content.phi.inputs_amount != 2) {
        SUCCESS_CLEANUP();
    }

    // a loop phi node has one input which is an add node to make it loop, and another input which
    // is the initial value.
    cdfg_find_1_of_2_inputs_res_t find_phi_add_res = {};
    CHECK_RETHROW(cdfg_find_1_of_2_inputs(
        cdfg,
        node_id,
        cdfg_node_is_calc,
        CDFG_CALCULATION_ADD,
        &find_phi_add_res
    ));
    if (!find_phi_add_res.found) {
        SUCCESS_CLEANUP();
    }

    cdfg_node_id_t add_node_id = find_phi_add_res.matching_input;
    cdfg_node_id_t initial_value_node_id = find_phi_add_res.other_input;

    cdfg_node_id_t add_input_node_ids[2] = {};
    CHECK_RETHROW(cdfg_find_binop_inputs(cdfg, add_node_id, add_input_node_ids));

    // the add node should have the phi node as one of its inputs, and the other input is the
    // increment value.
    cdfg_node_id_t increment_value_node_id;
    if (add_input_node_ids[0].id == node_id.id) {
        increment_value_node_id = add_input_node_ids[1];
    } else if (add_input_node_ids[1].id == node_id.id) {
        increment_value_node_id = add_input_node_ids[0];
    } else {
        SUCCESS_CLEANUP();
    }

    *result = (cdfg_detect_phi_loop_res_t) {
        .is_phi_loop = true,
        .initial_value_node_id = initial_value_node_id,
        .increment_value_node_id = increment_value_node_id,
        .add_node_id = add_node_id,
    };

cleanup:
    return err;
}

err_t cdfg_node_is_phi_loop(
    const cdfg_t* cdfg, cdfg_node_id_t node_id, u64 ctx, bool* is_matching
) {
    err_t err = SUCCESS;

    cdfg_detect_phi_loop_res_t* res = (cdfg_detect_phi_loop_res_t*) ctx;
    CHECK_RETHROW(cdfg_detect_phi_loop(cdfg, node_id, res));

    *is_matching = res->is_phi_loop;

cleanup:
    return err;
}

err_t cdfg_node_is_imm(const cdfg_t* cdfg, cdfg_node_id_t node_id, u64 ctx, bool* is_matching) {
    u64 desired_imm_value = ctx;
    const cdfg_node_t* node = &cdfg->node_storage[node_id.id];
    *is_matching =
        (node->kind == CDFG_NODE_KIND_IMM && node->content.imm.value == desired_imm_value);
    return SUCCESS;
}

err_t cdfg_node_is_calc(const cdfg_t* cdfg, cdfg_node_id_t node_id, u64 ctx, bool* is_matching) {
    cdfg_calculation_t desired_calc = ctx;
    const cdfg_node_t* node = &cdfg->node_storage[node_id.id];
    *is_matching =
        (node->kind == CDFG_NODE_KIND_CALC && node->content.calc.calculation == desired_calc);
    return SUCCESS;
}

cdfg_edge_id_t cdfg_find_first_matching_edge(
    const cdfg_t* cdfg, const cdfg_find_first_matching_edge_params_t* params
) {
    cdfg_edge_id_t found_id = {.id = CDFG_ITEM_ID_INVALID};
    for (size_t i = 0; i < cdfg->edges_amount; i++) {
        const cdfg_edge_t* edge = &cdfg->edge_storage[i];
        bool is_matching = true;
        if (params->check_kind && edge->kind != params->kind) {
            is_matching = false;
        } else if (params->check_from_node && edge->from_node.id != params->from_node.id) {
            is_matching = false;
        } else if (params->check_to_node && edge->to_node.id != params->to_node.id) {
            is_matching = false;
        } else if (params->check_to_node_input_index &&
                   edge->to_node_input_index != params->to_node_input_index) {
            is_matching = false;
        }
        if (is_matching) {
            found_id.id = i;
            break;
        }
    }

    return found_id;
}

err_t cdfg_node_is_of_kind(const cdfg_t* cdfg, cdfg_node_id_t node_id, u64 ctx, bool* is_matching) {
    cdfg_node_kind_t desired_kind = ctx;
    const cdfg_node_t* node = &cdfg->node_storage[node_id.id];
    *is_matching = (node->kind == desired_kind);
    return SUCCESS;
}
