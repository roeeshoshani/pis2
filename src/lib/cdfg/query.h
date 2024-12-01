#pragma once

#include "../types.h"
#include "../except.h"
#include "../cdfg.h"

typedef err_t (*cdfg_node_predicate_t)(const cdfg_t* cdfg, cdfg_node_id_t node_id, u64 ctx, bool* is_matching);

typedef struct {
    bool found;
    cdfg_node_id_t matching_input;
    cdfg_node_id_t other_input;
} cdfg_binop_input_find_res_t;

typedef struct {
    bool check_kind;
    cdfg_edge_kind_t kind;

    bool check_from_node;
    cdfg_node_id_t from_node;

    bool check_to_node;
    cdfg_node_id_t to_node;

    bool check_to_node_input_index;
    size_t to_node_input_index;
} cdfg_find_first_matching_edge_params_t;

typedef struct {
    bool is_phi_loop;

    cdfg_node_id_t initial_value_node_id;
    u64 initial_value;

    cdfg_node_id_t increment_value_node_id;
    u64 increment_value;

    cdfg_node_id_t add_node_id;
} cdfg_detect_phi_loop_res_t;

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
    u64 ctx,
    cdfg_binop_input_find_res_t* result
);

err_t cdfg_find_one_input(
    const cdfg_t* cdfg,
    cdfg_node_id_t node_id,
    cdfg_edge_kind_t edge_kind,
    cdfg_node_predicate_t predicate,
    u64 ctx,
    cdfg_node_id_t* out_node_id
);

err_t cdfg_node_is_param(const cdfg_t* cdfg, cdfg_node_id_t node_id, u64 ctx, bool* is_matching);

err_t cdfg_node_is_imm(const cdfg_t* cdfg, cdfg_node_id_t node_id, u64 ctx, bool* is_matching);

err_t cdfg_node_is_imm_value(
    const cdfg_t* cdfg, cdfg_node_id_t node_id, u64 ctx, bool* is_matching
);

err_t cdfg_node_is_calc(const cdfg_t* cdfg, cdfg_node_id_t node_id, u64 ctx, bool* is_matching);

cdfg_edge_id_t
    cdfg_find_first_matching_edge(const cdfg_t* cdfg, const cdfg_find_first_matching_edge_params_t* params);
