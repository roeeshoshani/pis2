#include "space.h"
#include "trace.h"

void pis_region_dump(pis_region_t region) {
    TRACE_NO_NEWLINE("[0x%x]:%u", region.offset, pis_size_to_bytes(region.size));
}

bool pis_region_contains(pis_region_t region, pis_region_t sub_region) {
    pis_off_t region_start = region.offset;
    pis_off_t region_end = region_start + pis_size_to_bytes(region.size);

    pis_off_t sub_region_start = sub_region.offset;
    pis_off_t sub_region_end = sub_region_start + pis_size_to_bytes(sub_region.size);

    return sub_region_start >= region_start && sub_region_end <= region_end;
}

bool pis_regions_equal(pis_region_t a, pis_region_t b) {
    return a.offset == b.offset && a.size == b.size;
}

bool pis_regions_intersect(pis_region_t a, pis_region_t b) {
    pis_off_t region_a_start = a.offset;
    pis_off_t region_a_end = region_a_start + pis_size_to_bytes(a.size);

    pis_off_t region_b_start = b.offset;
    pis_off_t region_b_end = region_b_start + pis_size_to_bytes(b.size);

    return region_a_start < region_b_end && region_b_start < region_a_end;
}
