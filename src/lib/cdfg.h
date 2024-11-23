#pragma once

#include "cfg.h"
#include "except.h"
#include "pis.h"
#include "types.h"

#define CDFG_MAX_NODES 1024
#define CDFG_MAX_EDGES 1024

#define CDFG_OP_STATE_MAX_SLOTS 1024

#define CDFG_ITEM_ID_MAX (UINT16_MAX)
#define CDFG_ITEM_ID_INVALID (CFG_ITEM_ID_MAX)

typedef u16 cdfg_item_id_t;

typedef enum {
    CDFG_NODE_KIND_VAR,
    CDFG_NODE_KIND_IMM,
} cdfg_node_kind_t;

typedef struct {
} cdfg_node_var_t;

typedef struct {
    u64 value;
} cdfg_node_imm_t;

typedef union {
    cdfg_node_var_t var;
    cdfg_node_imm_t imm;
} cdfg_node_content_t;

/// represents a single node in the CDFG
typedef struct {
    cdfg_node_kind_t kind;
    cdfg_node_content_t content;
} cdfg_node_t;

/// represents a single edge in the CDFG
typedef struct {
    cdfg_item_id_t from_node;
    cdfg_item_id_t to_node;
} cdfg_edge_t;

/// a control data flow graph.
typedef struct {
    cdfg_node_t node_storage[CDFG_MAX_NODES];
    size_t nodes_amount;

    cdfg_edge_t edge_storage[CDFG_MAX_EDGES];
    size_t edges_amount;
} cdfg_t;

/// a single slot in the operands state. represents the value of a single operand.
typedef struct {
    /// the operand whose value is represented in this slot.
    pis_operand_t operand;

    /// the node which represents the current value of the operand.
    cdfg_item_id_t value_node_id;
} cdfg_op_state_slot_t;

/// the state of all operands at a single point in time.
typedef struct {
    cdfg_op_state_slot_t slots[CDFG_OP_STATE_MAX_SLOTS];
    size_t used_slots_amount;
} cdfg_op_state_t;

/// a CDFG builder.
typedef struct {
    /// the built CDFG.
    cdfg_t cdfg;
} cdfg_builder_t;

err_t cdfg_build(cdfg_builder_t* builder, const cfg_t* cfg);
