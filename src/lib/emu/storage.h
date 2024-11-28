#pragma once

#include "../pis.h"

#define EMU_STORAGE_SLOTS_AMOUNT (8192)

typedef struct {
    pis_var_t var;
    u64 value;
} PACKED pis_emu_storage_slot_t;

typedef struct {
    pis_emu_storage_slot_t slots[EMU_STORAGE_SLOTS_AMOUNT];
    size_t used_slots_amount;
} pis_emu_storage_t;

err_t pis_emu_storage_allocate_slot(pis_emu_storage_t* storage, pis_emu_storage_slot_t** slot);

err_t pis_emu_storage_find(
    const pis_emu_storage_t* storage, pis_var_t var, size_t* found_slot_index
);

err_t pis_emu_storage_write(pis_emu_storage_t* storage, pis_var_t var, u64 value);

err_t pis_emu_storage_read(const pis_emu_storage_t* storage, pis_var_t var, u64* value);
