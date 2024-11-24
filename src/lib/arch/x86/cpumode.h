#pragma once

#include "../../operand_size.h"

typedef enum {
    PIS_X86_CPUMODE_32_BIT,
    PIS_X86_CPUMODE_64_BIT,
} pis_x86_cpumode_t;

pis_size_t pis_x86_cpumode_get_operand_size(pis_x86_cpumode_t cpumode);
