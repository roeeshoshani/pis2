#pragma once

#include "cfg.h"
#include "endianness.h"
#include "except.h"
#include "operand_size.h"
#include "pis.h"
#include "types.h"

#define CDFG_MAX_NODES 1024
#define CDFG_MAX_EDGES 1024

#define CDFG_OP_STATE_MAX_SLOTS 1024

#define CDFG_ITEM_ID_MAX (UINT16_MAX)
#define CDFG_ITEM_ID_INVALID (CFG_ITEM_ID_MAX)

typedef u16 cdfg_item_id_t;

/// the kind of a CDFG node.
typedef enum {
    CDFG_NODE_KIND_VAR,
    CDFG_NODE_KIND_IMM,
    CDFG_NODE_KIND_CALC,
} __attribute__((packed)) cdfg_node_kind_t;

/// the operation performed by a CDFG operation node.
typedef enum {
    CDFG_CALCULATION_AND,
    CDFG_CALCULATION_ADD,
    CDFG_CALCULATION_OR,
    CDFG_CALCULATION_SHIFT_RIGHT,
    CDFG_CALCULATION_SHIFT_LEFT,
} __attribute__((packed)) cdfg_calculation_t;

/// a CDFG variable node. this is used to represent an access to a register without previous
/// initialization of it. used for example to represent arguments to functions.
typedef struct {
    /// the offset in the register space of the register access that this variable represents.
    u64 reg_offset;

    /// the size of the register access that this variable represents.
    pis_size_t reg_size;
} __attribute__((packed)) cdfg_var_node_t;

/// a CDFG immediate value.
typedef struct {
    u64 value;
} __attribute__((packed)) cdfg_imm_node_t;

/// a CDFG calculation node.
typedef struct {
    /// the calculation that is performed by this node.
    cdfg_calculation_t calculation;
} __attribute__((packed)) cdfg_calc_node_t;

/// the content of a CDFG node.
typedef union {
    cdfg_var_node_t var;
    cdfg_imm_node_t imm;
    cdfg_calc_node_t calc;
} __attribute__((packed)) cdfg_node_content_t;

/// represents a single node in the CDFG
typedef struct {
    cdfg_node_kind_t kind;
    cdfg_node_content_t content;
} __attribute__((packed)) cdfg_node_t;

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

    /// the current operands state.
    cdfg_op_state_t op_state;

    /// the endianness of the lifted code.
    pis_endianness_t endianness;
} cdfg_builder_t;

err_t cdfg_build(cdfg_builder_t* builder, const cfg_t* cfg, pis_endianness_t endianness);
