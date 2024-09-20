#pragma once

#include "pis.h"

typedef enum {
  TMP_ID_MODRM_RM_ADDR,
  TMP_ID_SIB_INDEX,
} tmp_id_t;

extern const pis_addr_t g_modrm_rm_tmp_addr;

extern const pis_addr_t g_sib_index_tmp_addr;
