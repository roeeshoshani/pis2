#pragma once

#include "../../endianness.h"

typedef enum {
    MIPS_REVISION_1,
} mips_rev_t;

typedef struct {
    pis_endianness_t endianness;
    mips_rev_t rev;
} pis_mips_cpuinfo_t;
