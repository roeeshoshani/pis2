#pragma once

#include "endianness.h"
#include "lifter.h"
#include "reg.h"

typedef struct {
    pis_lifter_t lifter;
    pis_endianness_t endianness;
    const pis_reg_t* return_value;
    const pis_reg_t* args[4];
} pis_arch_def_t;
