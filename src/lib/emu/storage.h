#pragma once

#include "pis.h"

#define EMU_STORAGE_SLOTS_AMOUNT (8192)

typedef struct {
    pis_addr_t addr;
    u8 byte_value;
} pis_emu_storage_slot_t;

typedef struct {
    pis_emu_storage_slot_t slots[EMU_STORAGE_SLOTS_AMOUNT];
    size_t used_slots_amount;
} pis_emu_storage_t;

err_t pis_emu_storage_allocate_slot(pis_emu_storage_t* storage, pis_emu_storage_slot_t** slot);

pis_emu_storage_slot_t*
    pis_emu_storage_find_slot_by_addr(pis_emu_storage_t* storage, const pis_addr_t* addr);

const pis_emu_storage_slot_t* pis_emu_storage_find_slot_by_addr_const(
    const pis_emu_storage_t* storage, const pis_addr_t* addr
);

err_t pis_emu_storage_write_byte(pis_emu_storage_t* storage, const pis_addr_t* addr, u8 byte_value);

err_t pis_emu_storage_read_byte(
    const pis_emu_storage_t* storage, const pis_addr_t* addr, u8* byte_value
);
