#pragma once

#include "emu/mem_storage.h"
#include "emu/storage.h"
#include "pis.h"
#include "reg.h"

typedef struct {
    pis_emu_storage_t storage;
    pis_emu_mem_storage_t mem_storage;
    pis_endianness_t endianness;
    bool did_jump;
    u64 jump_addr;
} pis_emu_t;

void pis_emu_init(pis_emu_t* emu, pis_endianness_t endianness);

err_t pis_emu_read_op(const pis_emu_t* emu, const pis_op_t* op, u64* value);

err_t pis_emu_read_reg(const pis_emu_t* emu, pis_reg_t reg, u64* value);

err_t pis_emu_write_op(pis_emu_t* emu, const pis_op_t* op, u64 value);

err_t pis_emu_write_reg(pis_emu_t* emu, pis_reg_t reg, u64 value);

err_t pis_emu_read_mem_value(const pis_emu_t* emu, u64 addr, pis_size_t value_size, u64* value);

err_t pis_emu_write_mem_value(pis_emu_t* emu, u64 addr, u64 value, pis_size_t value_size);

err_t pis_emu_read_op_signed(const pis_emu_t* emu, const pis_op_t* op, i64* value);

err_t pis_emu_run(pis_emu_t* emu, const pis_lift_res_t* lift_res);
