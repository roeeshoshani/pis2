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

err_t cdfg_find_binop_input(
    const cdfg_t* cdfg,
    cdfg_node_id_t node_id,
    cdfg_node_predicate_t predicate,
    cdfg_binop_input_find_res_t* result
) {
    err_t err = SUCCESS;

    cdfg_node_id_t inputs[2] = {};
    CHECK_RETHROW(cdfg_find_binop_inputs(cdfg, node_id, inputs));

    if (predicate(cdfg, inputs[0])) {
        result->found = true;
        result->matching_input = inputs[0];
        result->other_input = inputs[1];
    } else if (predicate(cdfg, inputs[1])) {
        result->found = true;
        result->matching_input = inputs[1];
        result->other_input = inputs[0];
    } else {
        result->found = false;
        result->matching_input.id = CDFG_ITEM_ID_INVALID;
        result->other_input.id = CDFG_ITEM_ID_INVALID;
    }

cleanup:
    return err;
}

cdfg_node_id_t cdfg_find_input(
    const cdfg_t* cdfg,
    cdfg_node_id_t node_id,
    cdfg_edge_kind_t edge_kind,
    cdfg_node_predicate_t predicate
) {
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

        if (found_node_id.id != CDFG_ITEM_ID_INVALID) {
            // if we found more than one match, return as if there was no match at all
            found_node_id.id = CDFG_ITEM_ID_INVALID;
            break;
        }

        found_node_id = edge->from_node;
    }
    return found_node_id;
}

bool cdfg_node_is_param(const cdfg_t* cdfg, cdfg_node_id_t node_id, size_t param_index) {
    const cdfg_node_t* node = &cdfg->node_storage[node_id.id];
    return node->kind == CDFG_NODE_KIND_VAR &&
           node->content.var.reg_region.offset == cdfg->arch->params[param_index]->region.offset;
}

bool cdfg_node_is_first_param(const cdfg_t* cdfg, cdfg_node_id_t node_id) {
    return cdfg_node_is_param(cdfg, node_id, 0);
}

bool cdfg_node_is_second_param(const cdfg_t* cdfg, cdfg_node_id_t node_id) {
    return cdfg_node_is_param(cdfg, node_id, 1);
}

bool cdfg_node_is_third_param(const cdfg_t* cdfg, cdfg_node_id_t node_id) {
    return cdfg_node_is_param(cdfg, node_id, 2);
}

bool cdfg_node_is_fourth_param(const cdfg_t* cdfg, cdfg_node_id_t node_id) {
    return cdfg_node_is_param(cdfg, node_id, 3);
}

bool cdfg_node_is_imm(const cdfg_t* cdfg, cdfg_node_id_t node_id) {
    const cdfg_node_t* node = &cdfg->node_storage[node_id.id];
    return node->kind == CDFG_NODE_KIND_IMM;
}
