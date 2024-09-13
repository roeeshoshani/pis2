#pragma once

#include "except.h"
#include "pis.h"
#include "types.h"

typedef enum {
    PIS_X86_CPUMODE_16_BIT,
    PIS_X86_CPUMODE_32_BIT,
    PIS_X86_CPUMODE_64_BIT,
} pis_x86_cpumode_t;

/// the default operand size of a segment. this represents the `D/B` flag of the
/// segment descriptor.
typedef enum {
    PIS_X86_SEGMENT_DEFAULT_SIZE_16,
    PIS_X86_SEGMENT_DEFAULT_SIZE_32,
} pis_x86_segment_default_size_t;

typedef struct {
    pis_x86_cpumode_t cpumode;
    pis_x86_segment_default_size_t code_segment_default_size;
    pis_x86_segment_default_size_t stack_segment_default_size;
} pis_x86_ctx_t;

err_t pis_x86_lift(
    const pis_x86_ctx_t* ctx, const u8* machine_code, size_t machine_code_len,
    pis_lift_result_t* result
);
