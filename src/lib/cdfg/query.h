#pragma once

#include "../types.h"
#include "../cdfg.h"

typedef err_t (*cdfg_node_predicate_t)(const cdfg_t* cdfg, cdfg_node_id_t node_id, u64 ctx, bool* is_matching);

typedef struct {
    cdfg_node_id_t node_id;
    cdfg_edge_id_t edge_id;
} cdfg_input_t;

typedef struct {
    bool found;
    cdfg_input_t matching_input;
    cdfg_input_t other_input;
} cdfg_find_1_of_2_inputs_res_t;

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

    /// the initial value input to the phi node
    cdfg_input_t initial_value;

    /// the add node as an input to the phi node
    cdfg_input_t add_node;

    /// the increment value input to the add node
    cdfg_input_t increment_value;
} cdfg_detect_phi_loop_res_t;

typedef struct {
    bool is_imm_phi_loop;

    /// the initial value input to the phi node
    cdfg_input_t initial_value_input;
    u64 initial_value;

    /// the add node as an input to the phi node
    cdfg_input_t add_node;

    /// the increment value input to the add node
    cdfg_input_t increment_value_input;
    u64 increment_value;
} cdfg_detect_imm_phi_loop_res_t;

err_t cdfg_find_inputs(
    const cdfg_t* cdfg,
    cdfg_node_id_t node_id,
    cdfg_edge_kind_t edge_kind,
    cdfg_input_t* inputs,
    size_t inputs_amount
);

err_t cdfg_find_2_inputs(
    const cdfg_t* cdfg, cdfg_node_id_t node_id, cdfg_input_t inputs[2]
);

err_t cdfg_find_1_of_2_inputs(
    const cdfg_t* cdfg,
    cdfg_node_id_t node_id,
    cdfg_node_predicate_t predicate,
    u64 ctx,
    cdfg_find_1_of_2_inputs_res_t* result
);

err_t cdfg_find_one_input(
    const cdfg_t* cdfg,
    cdfg_node_id_t node_id,
    cdfg_edge_kind_t edge_kind,
    cdfg_node_predicate_t predicate,
    u64 ctx,
    cdfg_input_t* out_found_input
);

err_t cdfg_node_is_param(const cdfg_t* cdfg, cdfg_node_id_t node_id, u64 ctx, bool* is_matching);

err_t cdfg_detect_phi_loop(
    const cdfg_t* cdfg, cdfg_node_id_t node_id, cdfg_detect_phi_loop_res_t* result
);

err_t cdfg_detect_imm_phi_loop(
    const cdfg_t* cdfg, cdfg_node_id_t node_id, cdfg_detect_imm_phi_loop_res_t* result
);

err_t cdfg_node_is_phi_loop(
    const cdfg_t* cdfg, cdfg_node_id_t node_id, u64 ctx, bool* is_matching
);

err_t cdfg_node_is_imm_phi_loop(
    const cdfg_t* cdfg, cdfg_node_id_t node_id, u64 ctx, bool* is_matching
);

err_t cdfg_node_is_imm(
    const cdfg_t* cdfg, cdfg_node_id_t node_id, u64 ctx, bool* is_matching
);

err_t cdfg_node_is_calc(const cdfg_t* cdfg, cdfg_node_id_t node_id, u64 ctx, bool* is_matching);

cdfg_edge_id_t
    cdfg_find_first_matching_edge(const cdfg_t* cdfg, const cdfg_find_first_matching_edge_params_t* params);

err_t cdfg_node_is_of_kind(const cdfg_t* cdfg, cdfg_node_id_t node_id, u64 ctx, bool* is_matching);

err_t cdfg_node_is_node_id(const cdfg_t* cdfg, cdfg_node_id_t node_id, u64 ctx, bool* is_matching);
