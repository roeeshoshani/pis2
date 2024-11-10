#include "tmp.h"

err_t tmp_alloc(tmp_allocator_t* tmp_allocator, pis_operand_size_t size, pis_operand_t* new_tmp) {
    err_t err = SUCCESS;
    pis_operand_t result = PIS_OPERAND_TMP(tmp_allocator->cur_tmp_offset, size);

    u64 size_in_bytes = pis_operand_size_to_bytes(size);

    // make sure that we will not overflow
    CHECK_CODE(tmp_allocator->cur_tmp_offset <= UINT64_MAX - size_in_bytes, PIS_ERR_TOO_MANY_TMPS);

    tmp_allocator->cur_tmp_offset += size_in_bytes;

    *new_tmp = result;
cleanup:
    return err;
}
