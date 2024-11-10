#pragma once

#include "cursor.h"
#include "pis.h"

typedef struct {
    cursor_t machine_code;
    u64 machine_code_addr;
    pis_lift_result_t result;
} pis_lift_args_t;
