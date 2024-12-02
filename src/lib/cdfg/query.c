#include "query.h"

err_t cdfg_find_inputs(
    const cdfg_t* cdfg,
    cdfg_node_id_t node_id,
    cdfg_edge_kind_t edge_kind,
    cdfg_input_t* inputs,
    size_t inputs_amount
) {
    err_t err = SUCCESS;

    size_t cur_inputs_amount = 0;

    for (size_t i = 0; i < inputs_amount; i++) {
        inputs[i].node_id.id = CDFG_ITEM_ID_INVALID;
        inputs[i].edge_id.id = CDFG_ITEM_ID_INVALID;
    }

    for (size_t i = 0; i < cdfg->edges_amount; i++) {
        const cdfg_edge_t* edge = &cdfg->edge_storage[i];

        if (edge->to_node.id != node_id.id || edge->kind != edge_kind) {
            continue;
        }

        CHECK(edge->from_node.id != CDFG_ITEM_ID_INVALID);

        CHECK(edge->to_node_input_index < inputs_amount);

        cdfg_input_t* input = &inputs[edge->to_node_input_index];

        CHECK(input->node_id.id == CDFG_ITEM_ID_INVALID);

        input->node_id = edge->from_node;
        input->edge_id.id = i;

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

err_t cdfg_find_2_inputs(const cdfg_t* cdfg, cdfg_node_id_t node_id, cdfg_input_t inputs[2]) {
    err_t err = SUCCESS;

    CHECK_RETHROW(cdfg_find_inputs(cdfg, node_id, CDFG_EDGE_KIND_DATA_FLOW, inputs, 2));

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

    cdfg_input_t inputs[2] = {};
    CHECK_RETHROW(cdfg_find_2_inputs(cdfg, node_id, inputs));

    bool is_first_input_matching = false;
    CHECK_RETHROW(predicate(cdfg, inputs[0].node_id, ctx, &is_first_input_matching));
    if (is_first_input_matching) {
        result->found = true;
        result->matching_input = inputs[0];
        result->other_input = inputs[1];
        SUCCESS_CLEANUP();
    }

    bool is_second_input_matching = false;
    CHECK_RETHROW(predicate(cdfg, inputs[1].node_id, ctx, &is_second_input_matching));
    if (is_second_input_matching) {
        result->found = true;
        result->matching_input = inputs[1];
        result->other_input = inputs[0];
        SUCCESS_CLEANUP();
    }

    result->found = false;
    result->matching_input.node_id.id = CDFG_ITEM_ID_INVALID;
    result->matching_input.edge_id.id = CDFG_ITEM_ID_INVALID;
    result->other_input.node_id.id = CDFG_ITEM_ID_INVALID;
    result->other_input.edge_id.id = CDFG_ITEM_ID_INVALID;

cleanup:
    return err;
}

err_t cdfg_find_one_input(
    const cdfg_t* cdfg,
    cdfg_node_id_t node_id,
    cdfg_edge_kind_t edge_kind,
    cdfg_node_predicate_t predicate,
    u64 ctx,
    cdfg_input_t* out_found_input
) {
    err_t err = SUCCESS;

    out_found_input->node_id.id = CDFG_ITEM_ID_INVALID;
    out_found_input->edge_id.id = CDFG_ITEM_ID_INVALID;

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

        if (out_found_input->node_id.id != CDFG_ITEM_ID_INVALID) {
            // if we found more than one match, return as if there was no match at all
            out_found_input->node_id.id = CDFG_ITEM_ID_INVALID;
            out_found_input->edge_id.id = CDFG_ITEM_ID_INVALID;
            break;
        }

        out_found_input->node_id = edge->from_node;
        out_found_input->edge_id.id = i;
    }

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

    cdfg_input_t add_node = find_phi_add_res.matching_input;
    cdfg_input_t initial_value = find_phi_add_res.other_input;

    // the add node should have the phi node as one of its inputs, and the other input is the
    // increment value.
    cdfg_find_1_of_2_inputs_res_t find_add_phi_input_res = {};
    CHECK_RETHROW(cdfg_find_1_of_2_inputs(
        cdfg,
        add_node.node_id,
        cdfg_node_is_node_id,
        node_id.id,
        &find_add_phi_input_res
    ));

    if (!find_add_phi_input_res.found) {
        SUCCESS_CLEANUP();
    }

    *result = (cdfg_detect_phi_loop_res_t) {
        .is_phi_loop = true,
        .initial_value = initial_value,
        .increment_value = find_add_phi_input_res.other_input,
        .add_node = add_node,
    };

cleanup:
    return err;
}

err_t cdfg_detect_imm_phi_loop(
    const cdfg_t* cdfg, cdfg_node_id_t node_id, cdfg_detect_imm_phi_loop_res_t* result
) {
    err_t err = SUCCESS;

    result->is_imm_phi_loop = false;

    cdfg_detect_phi_loop_res_t detect_res = {};
    CHECK_RETHROW(cdfg_detect_phi_loop(cdfg, node_id, &detect_res));

    if (!detect_res.is_phi_loop) {
        SUCCESS_CLEANUP();
    }

    const cdfg_node_t* initial_value_node =
        &cdfg->node_storage[detect_res.initial_value.node_id.id];
    if (initial_value_node->kind != CDFG_NODE_KIND_IMM) {
        SUCCESS_CLEANUP();
    }

    const cdfg_node_t* increment_value_node =
        &cdfg->node_storage[detect_res.increment_value.node_id.id];
    if (increment_value_node->kind != CDFG_NODE_KIND_IMM) {
        SUCCESS_CLEANUP();
    }

    *result = (cdfg_detect_imm_phi_loop_res_t) {
        .is_imm_phi_loop = true,
        .add_node = detect_res.add_node,
        .initial_value = initial_value_node->content.imm.value,
        .initial_value_input = detect_res.initial_value,
        .increment_value = increment_value_node->content.imm.value,
        .increment_value_input = detect_res.increment_value,
    };

cleanup:
    return err;
}

err_t cdfg_node_is_phi_loop(
    const cdfg_t* cdfg, cdfg_node_id_t node_id, u64 ctx, bool* is_matching
) {
    err_t err = SUCCESS;

    cdfg_detect_phi_loop_res_t* res = (cdfg_detect_phi_loop_res_t*) ctx;

    cdfg_detect_phi_loop_res_t detect_phi_res = {};
    CHECK_RETHROW(cdfg_detect_phi_loop(cdfg, node_id, &detect_phi_res));

    if (detect_phi_res.is_phi_loop) {
        *is_matching = true;
        *res = detect_phi_res;
    }

cleanup:
    return err;
}

err_t cdfg_node_is_imm_phi_loop(
    const cdfg_t* cdfg, cdfg_node_id_t node_id, u64 ctx, bool* is_matching
) {
    err_t err = SUCCESS;

    cdfg_detect_imm_phi_loop_res_t* res = (cdfg_detect_imm_phi_loop_res_t*) ctx;

    cdfg_detect_imm_phi_loop_res_t detect_imm_phi_res = {};
    CHECK_RETHROW(cdfg_detect_imm_phi_loop(cdfg, node_id, &detect_imm_phi_res));

    if (detect_imm_phi_res.is_imm_phi_loop) {
        *is_matching = true;
        *res = detect_imm_phi_res;
    }

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

err_t cdfg_node_is_node_id(const cdfg_t* cdfg, cdfg_node_id_t node_id, u64 ctx, bool* is_matching) {
    UNUSED(cdfg);
    *is_matching = (node_id.id == ctx);
    return SUCCESS;
}
