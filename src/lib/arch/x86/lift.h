#pragma once

#include "../../cursor.h"
#include "../../except.h"
#include "../../lift_args.h"
#include "../../pis.h"
#include "../../types.h"
#include "cpumode.h"

err_t pis_x86_lift(pis_lift_args_t* args, pis_x86_cpumode_t cpumode);
