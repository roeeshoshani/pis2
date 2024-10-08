#include "mem_storage.h"
#include "errors.h"
#include "except.h"
#include "utils.h"

err_t pis_emu_mem_storage_allocate_slot(
    pis_emu_mem_storage_t* storage, pis_emu_mem_storage_slot_t** slot
) {
    err_t err = SUCCESS;

    CHECK_CODE(storage->used_slots_amount < ARRAY_SIZE(storage->slots), PIS_ERR_EMU_OUT_OF_STORAGE);

    *slot = &storage->slots[storage->used_slots_amount];
    storage->used_slots_amount++;

cleanup:
    return err;
}

pis_emu_mem_storage_slot_t*
    pis_emu_mem_storage_find_slot_by_addr(pis_emu_mem_storage_t* storage, u64 addr) {
    for (size_t i = 0; i < storage->used_slots_amount; i++) {
        if (storage->slots[i].addr == addr) {
            return &storage->slots[i];
        }
    }
    return NULL;
}

const pis_emu_mem_storage_slot_t*
    pis_emu_mem_storage_find_slot_by_addr_const(const pis_emu_mem_storage_t* storage, u64 addr) {
    for (size_t i = 0; i < storage->used_slots_amount; i++) {
        if (storage->slots[i].addr == addr) {
            return &storage->slots[i];
        }
    }
    return NULL;
}

err_t pis_emu_mem_storage_write_byte(pis_emu_mem_storage_t* storage, u64 addr, u8 byte_value) {
    err_t err = SUCCESS;

    pis_emu_mem_storage_slot_t* existing_slot =
        pis_emu_mem_storage_find_slot_by_addr(storage, addr);
    if (existing_slot != NULL) {
        existing_slot->byte_value = byte_value;
    } else {
        pis_emu_mem_storage_slot_t* slot = NULL;
        CHECK_RETHROW(pis_emu_mem_storage_allocate_slot(storage, &slot));

        slot->addr = addr;
        slot->byte_value = byte_value;
    }

cleanup:
    return err;
}

err_t pis_emu_mem_storage_read_byte(
    const pis_emu_mem_storage_t* storage, u64 addr, u8* byte_value
) {
    err_t err = SUCCESS;

    const pis_emu_mem_storage_slot_t* slot =
        pis_emu_mem_storage_find_slot_by_addr_const(storage, addr);
    CHECK_CODE(slot != NULL, PIS_ERR_EMU_READ_UNINIT);

    *byte_value = slot->byte_value;

cleanup:
    return err;
}
