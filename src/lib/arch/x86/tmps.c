#include "tmps.h"
#include "pis.h"

#define TMP(ID) PIS_ADDR(PIS_SPACE_TMP, ID * 8)

const pis_addr_t g_modrm_rm_tmp_addr = TMP(TMP_ID_MODRM_RM_ADDR);

const pis_addr_t g_sib_index_tmp_addr = TMP(TMP_ID_SIB_INDEX);

const pis_addr_t g_read_modify_write_tmp_addr = TMP(TMP_ID_READ_MODIFY_WRITE);

const pis_addr_t g_parity_flag_low_byte_tmp_addr = TMP(TMP_ID_PARITY_FLAG_LOW_BYTE);

const pis_operand_t g_parity_flag_low_byte_tmp =
    PIS_OPERAND(TMP(TMP_ID_PARITY_FLAG_LOW_BYTE), PIS_OPERAND_SIZE_1);
