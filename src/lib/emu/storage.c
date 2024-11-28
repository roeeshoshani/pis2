#include "storage.h"
#include "../errors.h"
#include "../except.h"
#include "../pis.h"
#include "../utils.h"

/// the slot index value used to represent the fact that a macthing slot was not found
#define SLOT_INDEX_NOT_FOUND ((size_t) -1)

err_t pis_emu_storage_allocate_slot(pis_emu_storage_t* storage, pis_emu_storage_slot_t** slot) {
    err_t err = SUCCESS;

    CHECK_CODE(storage->used_slots_amount < ARRAY_SIZE(storage->slots), PIS_ERR_EMU_OUT_OF_STORAGE);

    *slot = &storage->slots[storage->used_slots_amount];
    storage->used_slots_amount++;

cleanup:
    return err;
}

err_t pis_emu_storage_find(
    const pis_emu_storage_t* storage, pis_var_t var, size_t* found_slot_index
) {
    err_t err = SUCCESS;

    *found_slot_index = SLOT_INDEX_NOT_FOUND;

    for (size_t i = 0; i < storage->used_slots_amount; i++) {
        const pis_emu_storage_slot_t* slot = &storage->slots[i];

        if (pis_vars_intersect(var, slot->var)) {
            CHECK(pis_vars_equal(var, slot->var));
            *found_slot_index = i;
        }
    }

cleanup:
    return err;
}

err_t pis_emu_storage_write(pis_emu_storage_t* storage, pis_var_t var, u64 value) {
    err_t err = SUCCESS;

    size_t existing_slot_index = 0;
    CHECK_RETHROW(pis_emu_storage_find(storage, var, &existing_slot_index));

    if (existing_slot_index != SLOT_INDEX_NOT_FOUND) {
        storage->slots[existing_slot_index].value = value;
    } else {
        pis_emu_storage_slot_t* slot = NULL;
        CHECK_RETHROW(pis_emu_storage_allocate_slot(storage, &slot));

        slot->var = var;
        slot->value = value;
    }

cleanup:
    return err;
}

err_t pis_emu_storage_read(const pis_emu_storage_t* storage, pis_var_t var, u64* value) {
    err_t err = SUCCESS;

    size_t existing_slot_index = 0;
    CHECK_RETHROW(pis_emu_storage_find(storage, var, &existing_slot_index));

    CHECK_TRACE_CODE(
        existing_slot_index != SLOT_INDEX_NOT_FOUND,
        PIS_ERR_EMU_READ_UNINIT,
        "reading uninitialized storage at %s[0x%x]:%u",
        pis_var_space_to_str(var.space),
        var.offset,
        pis_size_to_bytes(var.size)
    );

    *value = storage->slots[existing_slot_index].value;

cleanup:
    return err;
}
