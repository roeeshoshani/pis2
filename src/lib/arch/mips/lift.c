#include "lift.h"

err_t pis_mips_lift(
    const pis_mips_ctx_t* ctx,
    cursor_t* machine_code,
    u64 machine_code_addr,
    pis_lift_result_t* result
) {
    err_t err = SUCCESS;

    UNUSED(ctx);
    UNUSED(machine_code);
    UNUSED(machine_code_addr);
    UNUSED(result);

    goto cleanup;

cleanup:
    return err;
}
