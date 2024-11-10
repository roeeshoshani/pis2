#pragma once

#include "../../except.h"
#include "../../pis.h"
#include "../../types.h"
#include "../../cursor.h"
#include "../../lift_args.h"

typedef struct {
  pis_endianness_t endianness;
} pis_mips_cpuinfo_t;

err_t pis_mips_lift(pis_lift_args_t* args, const pis_mips_cpuinfo_t* cpuinfo);
