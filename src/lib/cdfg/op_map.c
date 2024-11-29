#include "op_map.h"
#include <string.h>

void cdfg_op_map_reset(cdfg_op_map_t* map) {
    memset(map, 0, sizeof(*map));
}

/// must only be called on well initialized slots.
static pis_region_t slot_get_region(cdfg_op_map_slot_t slot) {
    return (pis_region_t) {
        .offset = slot.offset,

        // assuming that the slot is well initialized, its size value should be a valid pis size
        // value.
        .size = (pis_size_t) slot.size,
    };
}

typedef enum {
    SEARCH_RES_KIND_PARTIALLY_OVERLAPPING,
    SEARCH_RES_KIND_FOUND_EXACT_MATCH_SLOT,
    SEARCH_RES_KIND_FOUND_CONTAINER_SLOT,
    SEARCH_RES_KIND_FOUND_CONTAINED_SLOTS,
    SEARCH_RES_KIND_NO_MATCH,
} search_res_kind_t;

typedef struct {
    search_res_kind_t kind;
    size_t container_slot_index;
} search_res_t;

static err_t
    search_region(const cdfg_op_map_t* map, pis_region_t region, search_res_t* search_res) {
    err_t err = SUCCESS;

    bool found_equal_slot = false;

    bool found_container_slot = false;
    size_t container_slot_index = 0;

    bool found_contained_slot = false;

    bool found_partially_overlapping = false;

    for (size_t i = 0; i < map->used_slots_amount; i++) {
        const cdfg_op_map_slot_t* slot = &map->slots[i];
        if (slot->size == CDFG_OP_MAP_SIZE_INVALID) {
            // slot is vacant.
            continue;
        }
        pis_region_t slot_region = slot_get_region(*slot);
        if (!pis_regions_intersect(region, slot_region)) {
            // this slot is irrelevant.
            continue;
        }

        // the region of the slot intersects with the accessed region.
        if (pis_regions_equal(region, slot_region)) {
            // the regions are equal.

            // we expect to find only one slot that is equal to the accessed region, otherwise we
            // have duplicates in our map, which should never happen.
            CHECK(!found_equal_slot);
            found_equal_slot = true;
        } else if (pis_region_contains(slot_region, region)) {
            // the region covered by this slot already contains the accessed region.

            // we expect to find only one slot whose region contains the accessed region, otherwise
            // we have intersecting regions in our map, which should never happen.
            CHECK(!found_container_slot);
            found_container_slot = true;
            container_slot_index = i;
        } else if (pis_region_contains(region, slot_region)) {
            // the new accessed region contains the region that is covered by this slot.
            // there can be multiple slots contained in the accessed region.
            found_contained_slot = true;
        } else {
            // the regions are partially overlapping.
            // there can be multiple slots that are partially overlapping with the accessed region.
            found_partially_overlapping = true;
        }
    }
    if (found_partially_overlapping) {
        // if we found any partially overlapping slot, then this access is part of a partially
        // overlapping access.

        // if this region is an overlapping region, we don't expect to find a perfectly matching
        // region inside of the map. that would be an inconsistency.
        CHECK(!found_equal_slot);

        search_res->kind = SEARCH_RES_KIND_PARTIALLY_OVERLAPPING;
    } else if (found_equal_slot) {
        // we don't expect any other type of intersection with any other slot.
        CHECK(!found_container_slot && !found_contained_slot);

        search_res->kind = SEARCH_RES_KIND_FOUND_EXACT_MATCH_SLOT;
    } else if (found_container_slot) {
        // we don't expect any other type of intersection with any other slot.
        CHECK(!found_contained_slot);

        search_res->kind = SEARCH_RES_KIND_FOUND_CONTAINER_SLOT;
        search_res->container_slot_index = container_slot_index;
    } else if (found_contained_slot) {
        search_res->kind = SEARCH_RES_KIND_FOUND_CONTAINED_SLOTS;
    } else {
        // no slot interesects with this region.
        search_res->kind = SEARCH_RES_KIND_NO_MATCH;
    }

cleanup:
    return err;
}

static void invalidate_all_slots_interesecting_with(cdfg_op_map_t* map, pis_region_t region) {
    for (size_t i = 0; i < map->used_slots_amount; i++) {
        cdfg_op_map_slot_t* slot = &map->slots[i];
        if (slot->size == CDFG_OP_MAP_SIZE_INVALID) {
            // slot is vacant.
            continue;
        }
        pis_region_t slot_region = slot_get_region(*slot);
        if (pis_regions_intersect(region, slot_region)) {
            slot->size = CDFG_OP_MAP_SIZE_INVALID;
        }
    }
}

static err_t map_find_empty_slot(cdfg_op_map_t* map, size_t* out_slot_index) {
    err_t err = SUCCESS;

    size_t slot_index = (size_t) -1;

    for (size_t i = 0; i < CDFG_OP_MAP_MAX_SLOTS; i++) {
        if (map->slots[i].size == CDFG_OP_MAP_SIZE_INVALID) {
            slot_index = i;
            break;
        }
    }

    CHECK(slot_index != (size_t) -1);

    if (slot_index + 1 > map->used_slots_amount) {
        map->used_slots_amount = slot_index + 1;
    }

    *out_slot_index = slot_index;

cleanup:
    return err;
}

static err_t map_add_region(cdfg_op_map_t* map, pis_region_t region) {
    err_t err = SUCCESS;

    size_t slot_index = 0;
    CHECK_RETHROW(map_find_empty_slot(map, &slot_index));

    cdfg_op_map_slot_t* slot = &map->slots[slot_index];
    slot->offset = region.offset;
    slot->size = (cdfg_op_map_size_t) region.size;

cleanup:
    return err;
}

/// updates the operands map according to an access to some operand in it.
err_t cdfg_op_map_update(cdfg_op_map_t* map, pis_region_t accessed_region) {
    err_t err = SUCCESS;

    search_res_t search_res = {};
    CHECK_RETHROW(search_region(map, accessed_region, &search_res));

    switch (search_res.kind) {
        case SEARCH_RES_KIND_PARTIALLY_OVERLAPPING:
            // if this node is part of a partially overlapping access, invalidate all slots that
            // intersect with it, as they are now all also part of this overlapping access.
            invalidate_all_slots_interesecting_with(map, accessed_region);
            break;
        case SEARCH_RES_KIND_FOUND_EXACT_MATCH_SLOT:
            // we found a slot which exactly matches this region, so we don't need to update the
            // map here.
            break;
        case SEARCH_RES_KIND_FOUND_CONTAINER_SLOT:
            // we found a slot which already contains this accessed region, so we don't need to
            // update the map here.
            break;
        case SEARCH_RES_KIND_FOUND_CONTAINED_SLOTS:
            // we found some slots that are contained in this accessed region.

            // first, invalidate all the slots that are contained in this accessed region.
            invalidate_all_slots_interesecting_with(map, accessed_region);

            // then, just add the new region. it contains all the slots that we previously
            // invalidated.
            CHECK_RETHROW(map_add_region(map, accessed_region));
            break;
        case SEARCH_RES_KIND_NO_MATCH:
            // no slot intersected with the accessed region, so just add it to the map as is.
            CHECK_RETHROW(map_add_region(map, accessed_region));
            break;
    }
cleanup:
    return err;
}

/// finds the largest enclosing region of the given region in the operand map.
err_t cdfg_op_map_largest_enclosing(
    const cdfg_op_map_t* map, pis_region_t region, bool* out_found, pis_region_t* out_region
) {
    err_t err = SUCCESS;

    search_res_t search_res = {};
    CHECK_RETHROW(search_region(map, region, &search_res));

    switch (search_res.kind) {
        case SEARCH_RES_KIND_PARTIALLY_OVERLAPPING:
            // no container region for partially overlapping regions
            *out_found = false;
            break;
        case SEARCH_RES_KIND_FOUND_EXACT_MATCH_SLOT:
            // found an exact match. the container region is the region itself.
            *out_region = region;
            *out_found = true;
            break;
        case SEARCH_RES_KIND_FOUND_CONTAINER_SLOT: {
            // found a slot which contains this region.
            const cdfg_op_map_slot_t* slot = &map->slots[search_res.container_slot_index];
            *out_region = (pis_region_t) {
                .offset = slot->offset,

                // assuming that the slot is valid, its size should be a valid pis size
                .size = (pis_size_t) slot->size,
            };
            *out_found = true;
            break;
        }
        case SEARCH_RES_KIND_FOUND_CONTAINED_SLOTS:
            // the provided region contains multiple slots. assuming that we have previously
            // iterated over all of the code and processed all operand accesses, this should never
            // happen.
            CHECK_FAIL();
            break;
        case SEARCH_RES_KIND_NO_MATCH:
            // no such region in the map.
            *out_found = false;
            break;
    }

cleanup:
    return err;
}
