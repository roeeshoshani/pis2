#include "tmps.h"
#include "pis.h"

#define TMP(ID) PIS_ADDR(PIS_SPACE_TMP, ID * 8)

const pis_addr_t g_modrm_rm_tmp_addr = TMP(TMP_ID_MODRM_RM_ADDR);

const pis_addr_t g_sib_index_tmp_addr = TMP(TMP_ID_SIB_INDEX);

const pis_addr_t g_src_op_1_tmp_addr = TMP(TMP_ID_SRC_OP_1);

const pis_addr_t g_src_op_2_tmp_addr = TMP(TMP_ID_SRC_OP_2);

const pis_addr_t g_src_op_3_tmp_addr = TMP(TMP_ID_SRC_OP_3);

const pis_addr_t g_calc_res_tmp_addr = TMP(TMP_ID_CALC_RES);

const pis_addr_t g_parity_flag_low_byte_tmp_addr = TMP(TMP_ID_PARITY_FLAG_LOW_BYTE);

const pis_operand_t g_parity_flag_low_byte_tmp =
    PIS_OPERAND(TMP(TMP_ID_PARITY_FLAG_LOW_BYTE), PIS_OPERAND_SIZE_1);
