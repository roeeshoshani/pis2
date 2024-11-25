#pragma once

#include "../../except.h"
#include "../../lift_args.h"
#include "../../arch_def.h"
#include "cpuinfo.h"

err_t pis_mips_lift(pis_lift_args_t* args, const pis_mips_cpuinfo_t* cpuinfo);

err_t pis_lifter_mipsbe32r1(pis_lift_args_t* args);

err_t pis_lifter_mipsel32r1(pis_lift_args_t* args);

extern const pis_arch_def_t pis_arch_def_mipsbe32r1;

extern const pis_arch_def_t pis_arch_def_mipsel32r1;
