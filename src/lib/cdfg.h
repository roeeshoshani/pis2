#pragma once

#include "cfg.h"
#include "except.h"
#include "types.h"

#define CDFG_MAX_NODES 1024
#define CDFG_MAX_EDGES 1024

#define CDFG_ITEM_ID_MAX (UINT16_MAX)
#define CDFG_ITEM_ID_INVALID (CFG_ITEM_ID_MAX)

typedef u16 cdfg_item_id_t;

typedef enum {
    CDFG_NODE_KIND_VARIABLE,
} cdfg_node_kind_t;

/// represents a single node in the CDFG
typedef struct {
    cdfg_node_kind_t kind;
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

/// a CDFG builder.
typedef struct {
    /// the built CDFG.
    cdfg_t cdfg;
} cdfg_builder_t;

err_t cdfg_build(cdfg_builder_t* builder, const cfg_t* cfg);
