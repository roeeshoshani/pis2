#include "lift.h"

err_t pis_mips_lift(pis_lift_args_t* args, const pis_mips_cpuinfo_t* cpuinfo) {
    err_t err = SUCCESS;

    u32 insn = 0;
    CHECK_RETHROW(cursor_next_4(&args->machine_code, &insn, cpuinfo->endianness));

    UNUSED(args);
    UNUSED(cpuinfo);

    goto cleanup;

cleanup:
    return err;
}
