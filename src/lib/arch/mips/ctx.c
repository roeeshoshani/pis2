#include "ctx.h"

err_t pis_mips_lift(
    const pis_mips_ctx_t* ctx,
    const u8* machine_code,
    size_t machine_code_len,
    u64 machine_code_addr,
    pis_lift_result_t* result
) {
    err_t err = SUCCESS;
cleanup:
    return err;
}
