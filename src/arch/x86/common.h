#pragma once

#include "arch/x86/ctx.h"
#include "lift_ctx.h"
#include "pis.h"
#include "prefixes.h"

pis_operand_size_t cpumode_get_operand_size(pis_x86_cpumode_t cpumode);

pis_operand_size_t get_effective_operand_size(
    const lift_ctx_t* ctx, const prefixes_t* prefixes
);

pis_operand_size_t get_effective_addr_size(
    const lift_ctx_t* ctx, const prefixes_t* prefixes
);
