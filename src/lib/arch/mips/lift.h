#pragma once

#include "../../except.h"
#include "../../pis.h"
#include "../../types.h"
#include "../../cursor.h"

typedef struct {
  pis_endianness_t endianness;
} pis_mips_ctx_t;

err_t pis_mips_lift(
    const pis_mips_ctx_t* ctx,
    cursor_t* machine_code,
    u64 machine_code_addr,
    pis_lift_result_t* result
);
