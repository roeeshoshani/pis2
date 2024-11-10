#pragma once

#include "../../tmp.h"
#include "cpumode.h"
#include "prefixes.h"

typedef struct {
    pis_lift_args_t* args;
    prefixes_t prefixes;
    pis_x86_cpumode_t cpumode;
    tmp_allocator_t tmp_allocator;
    pis_operand_size_t addr_size;
    pis_operand_size_t stack_addr_size;
    pis_operand_t sp;
    bool has_modrm;
    uint8_t modrm_byte;
} ctx_t;
