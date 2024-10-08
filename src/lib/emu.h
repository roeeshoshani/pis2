#pragma once

#include "emu/mem_storage.h"
#include "emu/storage.h"
#include "pis.h"

typedef struct {
    pis_emu_storage_t storage;
    pis_emu_mem_storage_t mem_storage;
    pis_endianness_t endianness;
} pis_emu_t;

err_t pis_emu_run(pis_emu_t* emu, const pis_lift_result_t* lift_result);
