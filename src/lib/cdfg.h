#pragma once

#include "cfg.h"
#include "endianness.h"
#include "except.h"
#include "operand_size.h"
#include "pis.h"
#include "types.h"

#define CDFG_MAX_NODES 8192
#define CDFG_MAX_EDGES 16384

#define CDFG_OP_STATE_MAX_SLOTS 128

#define CDFG_ITEM_ID_MAX (UINT16_MAX)
#define CDFG_ITEM_ID_INVALID (CDFG_ITEM_ID_MAX)

#define CDFG_CALCULATION(_)                                                                        \
    _(CDFG_CALCULATION_AND, )                                                                      \
    _(CDFG_CALCULATION_ADD, )                                                                      \
    _(CDFG_CALCULATION_SUB, )                                                                      \
    _(CDFG_CALCULATION_OR, )                                                                       \
    _(CDFG_CALCULATION_XOR, )                                                                      \
    _(CDFG_CALCULATION_PARITY, )                                                                   \
    _(CDFG_CALCULATION_SHIFT_RIGHT, )                                                              \
    _(CDFG_CALCULATION_SHIFT_RIGHT_SIGNED, )                                                       \
    _(CDFG_CALCULATION_SHIFT_LEFT, )                                                               \
    _(CDFG_CALCULATION_UNSIGNED_LESS_THAN, )                                                       \
    _(CDFG_CALCULATION_UNSIGNED_MUL, )                                                             \
    _(CDFG_CALCULATION_SIGNED_LESS_THAN, )                                                         \
    _(CDFG_CALCULATION_NEG, )                                                                      \
    _(CDFG_CALCULATION_COND_NEGATE, )                                                              \
    _(CDFG_CALCULATION_EQUALS, )
STR_ENUM(cdfg_calculation, CDFG_CALCULATION, __attribute__((packed)));

typedef u16 cdfg_item_id_t;

/// the kind of a CDFG node.
typedef enum {
    CDFG_NODE_KIND_VAR,
    CDFG_NODE_KIND_IMM,
    CDFG_NODE_KIND_CALC,
    CDFG_NODE_KIND_STORE,
    CDFG_NODE_KIND_LOAD,
    CDFG_NODE_KIND_ENTRY,
    CDFG_NODE_KIND_IF,
    CDFG_NODE_KIND_REGION,
    CDFG_NODE_KIND_PHI,
} __attribute__((packed)) cdfg_node_kind_t;

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

/// a CDFG region node.
typedef struct {
    /// the amount of control flow paths that are combined by this region node.
    size_t inputs_amount;
} __attribute__((packed)) cdfg_region_node_t;

/// a CDFG phi node.
typedef struct {
    /// the amount of different values that are combined by this phi node.
    size_t inputs_amount;
} __attribute__((packed)) cdfg_phi_node_t;

/// the content of a CDFG node.
typedef union {
    cdfg_var_node_t var;
    cdfg_imm_node_t imm;
    cdfg_calc_node_t calc;
    cdfg_region_node_t region;
    cdfg_phi_node_t phi;
} __attribute__((packed)) cdfg_node_content_t;

/// represents a single node in the CDFG
typedef struct {
    cdfg_node_kind_t kind;
    cdfg_node_content_t content;
} __attribute__((packed)) cdfg_node_t;

typedef enum {
    CDFG_EDGE_KIND_DATA_FLOW,
    CDFG_EDGE_KIND_CONTROL_FLOW,
} __attribute__((packed)) cdfg_edge_kind_t;

/// represents a single edge in the CDFG
typedef struct {
    /// the kind of node.
    cdfg_edge_kind_t kind : 1;

    /// which of the inputs of the destination node does this edge represent?
    u8 to_node_input_index : 7;

    /// the source node.
    cdfg_item_id_t from_node;

    /// the destination node.
    cdfg_item_id_t to_node;
} __attribute__((packed)) cdfg_edge_t;

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
} __attribute__((packed)) cdfg_op_state_slot_t;

/// the state of all operands at a single point in time.
typedef struct {
    cdfg_op_state_slot_t slots[CDFG_OP_STATE_MAX_SLOTS];
    size_t used_slots_amount;

    /// the id of the last control flow node.
    cdfg_item_id_t last_cf_node_id;
} cdfg_op_state_t;

/// the state of a CFG block in the process of building the CDFG.
typedef struct {
    /// was this block already processed?
    bool was_processed;

    /// the op state at the end of this block.
    cdfg_op_state_t final_state;
} cdfg_block_state_t;

/// a CDFG builder.
typedef struct {
    /// the built CDFG.
    cdfg_t cdfg;

    /// the CFG that is used to build the CDFG.
    const cfg_t* cfg;

    /// the state of each cfg block.
    cdfg_block_state_t block_states[CFG_MAX_BLOCKS];

    /// the current operands state.
    cdfg_op_state_t op_state;

    /// the endianness of the lifted code.
    pis_endianness_t endianness;
} cdfg_builder_t;

void cdfg_reset(cdfg_t* cdfg);

err_t cdfg_build(cdfg_builder_t* builder, const cfg_t* cfg, pis_endianness_t endianness);

void cdfg_dump_dot(const cdfg_t* cdfg);
