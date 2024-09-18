#pragma once

#include "ctx.h"
#include "lift_ctx.h"
#include "pis.h"
#include "prefixes.h"
#include "regs.h"

pis_operand_size_t cpumode_get_operand_size(pis_x86_cpumode_t cpumode);

pis_operand_size_t
    get_effective_operand_size(pis_x86_cpumode_t cpumode, const prefixes_t* prefixes, bool default_to_64_bit);

pis_operand_size_t get_effective_addr_size(pis_x86_cpumode_t cpumode, const prefixes_t* prefixes);

pis_operand_size_t get_effective_stack_addr_size(pis_x86_cpumode_t cpumode);

pis_operand_t get_sp_operand(pis_x86_cpumode_t cpumode);
