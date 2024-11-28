#pragma once

#include "types.h"
#include "size.h"

/// a type used to represent an offset inside a memory space.
typedef u16 pis_off_t;

/// a region in a memory space.
typedef struct {
    pis_off_t offset;
    pis_size_t size;
} PACKED pis_region_t;

void pis_region_dump(pis_region_t region);

bool pis_region_contains(pis_region_t region, pis_region_t sub_region);

bool pis_regions_equal(pis_region_t a, pis_region_t b);

bool pis_regions_intersect(pis_region_t a, pis_region_t b);
