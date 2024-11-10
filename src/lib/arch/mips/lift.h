#pragma once

#include "../../cursor.h"
#include "../../except.h"
#include "../../lift_args.h"
#include "../../pis.h"
#include "../../types.h"

typedef struct {
    pis_endianness_t endianness;
} pis_mips_cpuinfo_t;

err_t pis_mips_lift(pis_lift_args_t* args, const pis_mips_cpuinfo_t* cpuinfo);
