#pragma once

#include "except.h"
#include "pis.h"
#include "types.h"

typedef enum {
    PIS_X86_CPUMODE_32_BIT,
    PIS_X86_CPUMODE_64_BIT,
} pis_x86_cpumode_t;

typedef struct {
    pis_x86_cpumode_t cpumode;
} pis_x86_ctx_t;

err_t pis_x86_lift(
    const pis_x86_ctx_t* ctx,
    const u8* machine_code,
    size_t machine_code_len,
    u64 machine_code_addr,
    pis_lift_result_t* result
);
