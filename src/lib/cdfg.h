#pragma once

#include "types.h"

#define PIS_CDFG_MAX_NODES 1024
#define PIS_CDFG_MAX_EDGES 1024

#define PIS_CDFG_ITEM_ID_MAX (UINT16_MAX)
#define PIS_CDFG_ITEM_ID_INVALID (PIS_CFG_ITEM_ID_MAX)

typedef u16 pis_cdfg_item_id_t;

typedef enum {
  PIS_CDFG_NODE_KIND_VARIABLE,
} cdfg_node_kind_t;

/// represents a single node in the CDFG
typedef struct {
} cdfg_node_t;

/// represents a single edge in the CDFG
typedef struct {
  pis_cdfg_item_id_t from_node;
  pis_cdfg_item_id_t to_node;
} cdfg_edge_t;

typedef struct {
  cdfg_node_t node_storage[PIS_CDFG_MAX_NODES];
  size_t nodes_amount;

  cdfg_edge_t edge_storage[PIS_CDFG_MAX_EDGES];
  size_t edges_amount;
} cdfg_t;
