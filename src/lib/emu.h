#pragma once

#include "emu/mem_storage.h"
#include "emu/storage.h"
#include "pis.h"

typedef struct {
    pis_emu_storage_t storage;
    pis_emu_mem_storage_t mem_storage;
    pis_endianness_t endianness;
    bool did_jump;
    u64 jump_addr;
} pis_emu_t;

void pis_emu_init(pis_emu_t* emu, pis_endianness_t endianness);

err_t pis_emu_read_operand(const pis_emu_t* emu, const pis_operand_t* operand, u64* operand_value);

err_t pis_emu_write_operand(pis_emu_t* emu, const pis_operand_t* operand, u64 value);

err_t pis_emu_read_mem_value(
    const pis_emu_t* emu, u64 addr, pis_operand_size_t value_size, u64* value
);

err_t pis_emu_write_mem_value(pis_emu_t* emu, u64 addr, u64 value, pis_operand_size_t value_size);

err_t pis_emu_read_operand_signed(
    const pis_emu_t* emu, const pis_operand_t* operand, i64* operand_value
);

err_t pis_emu_run(pis_emu_t* emu, const pis_lift_result_t* lift_result);
