#pragma once

#include "endianness.h"
#include "lifter.h"

typedef struct {
    pis_lifter_t lifter;
    pis_endianness_t endianness;
    const pis_operand_t* return_value;
} pis_arch_def_t;
