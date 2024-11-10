#pragma once

#include "types.h"

typedef enum {
    PIS_ENDIANNESS_LITTLE,
    PIS_ENDIANNESS_BIG,
} pis_endianness_t;

pis_endianness_t pis_endianness_native();

void pis_endianness_swap_bytes_if_needed(pis_endianness_t endianness, u8* bytes, size_t len);
