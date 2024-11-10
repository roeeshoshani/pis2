#include "lift.h"

err_t pis_mips_lift(pis_lift_args_t* args, const pis_mips_cpuinfo_t* cpuinfo) {
    err_t err = SUCCESS;

    UNUSED(args);
    UNUSED(cpuinfo);

    goto cleanup;

cleanup:
    return err;
}
