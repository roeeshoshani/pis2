#pragma once

#include "pis.h"

/// an enum used to assign a unique id to temporaries that have special purposes in calculations.
/// this is used to keep the offsets used in the temporary space managed, to prevent collisions.
typedef enum {
    TMP_ID_MODRM_RM_ADDR,
    TMP_ID_SIB_INDEX,
    TMP_ID_SRC_OP_1,
    TMP_ID_SRC_OP_2,
    TMP_ID_SRC_OP_3,
    TMP_ID_CALC_RES,
    TMP_ID_PARITY_FLAG_LOW_BYTE,
} tmp_id_t;

extern const pis_addr_t g_modrm_rm_tmp_addr;

extern const pis_addr_t g_sib_index_tmp_addr;

extern const pis_addr_t g_src_op_1_tmp_addr;

extern const pis_addr_t g_src_op_2_tmp_addr;

extern const pis_addr_t g_src_op_3_tmp_addr;

extern const pis_addr_t g_calc_res_tmp_addr;

extern const pis_addr_t g_parity_flag_low_byte_tmp_addr;

extern const pis_operand_t g_parity_flag_low_byte_tmp;
