#pragma once

#include "../types.h"
#include "../except.h"
#include "../cdfg.h"

typedef bool (*cdfg_node_predicate_t)(const cdfg_t* cdfg, cdfg_node_id_t node_id);

typedef struct {
    bool found;
    cdfg_node_id_t matching_input;
    cdfg_node_id_t other_input;
} cdfg_binop_input_find_res_t;

err_t cdfg_find_inputs(
    const cdfg_t* cdfg,
    cdfg_node_id_t node_id,
    cdfg_edge_kind_t edge_kind,
    cdfg_node_id_t* input_node_ids,
    size_t inputs_amount
);

err_t cdfg_find_binop_inputs(
    const cdfg_t* cdfg, cdfg_node_id_t node_id, cdfg_node_id_t input_node_ids[2]
);

err_t cdfg_find_binop_input(
    const cdfg_t* cdfg,
    cdfg_node_id_t node_id,
    cdfg_node_predicate_t predicate,
    cdfg_binop_input_find_res_t* result
);

cdfg_node_id_t cdfg_find_input(
    const cdfg_t* cdfg,
    cdfg_node_id_t node_id,
    cdfg_edge_kind_t edge_kind,
    cdfg_node_predicate_t predicate
);

bool cdfg_node_is_param(const cdfg_t* cdfg, cdfg_node_id_t node_id, size_t param_index);

bool cdfg_node_is_first_param(const cdfg_t* cdfg, cdfg_node_id_t node_id);
bool cdfg_node_is_second_param(const cdfg_t* cdfg, cdfg_node_id_t node_id);
bool cdfg_node_is_third_param(const cdfg_t* cdfg, cdfg_node_id_t node_id);
bool cdfg_node_is_fourth_param(const cdfg_t* cdfg, cdfg_node_id_t node_id);

bool cdfg_node_is_imm(const cdfg_t* cdfg, cdfg_node_id_t node_id);
