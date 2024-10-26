#pragma once

#include "except.h"
#include "pis.h"
#include "types.h"
#include "distorm/include/distorm.h"

typedef enum {
    PIS_X86_CPUMODE_16_BIT = Decode16Bits,
    PIS_X86_CPUMODE_32_BIT = Decode32Bits,
    PIS_X86_CPUMODE_64_BIT = Decode64Bits,
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
