#include "common.h"
#include "arch/x86/ctx.h"
#include "arch/x86/prefixes.h"
#include "arch/x86/regs.h"
#include "pis.h"

pis_operand_size_t cpumode_get_operand_size(pis_x86_cpumode_t cpumode) {
    switch (cpumode) {
    case PIS_X86_CPUMODE_64_BIT:
        return PIS_OPERAND_SIZE_8;
    case PIS_X86_CPUMODE_32_BIT:
        return PIS_OPERAND_SIZE_4;
    case PIS_X86_CPUMODE_16_BIT:
        return PIS_OPERAND_SIZE_2;
    default:
        // unreachable
        return PIS_OPERAND_SIZE_1;
    }
}

pis_operand_size_t
    get_effective_operand_size(const post_prefixes_ctx_t* ctx, bool default_to_64_bit) {
    bool has_size_override =
        prefixes_contain_legacy_prefix(ctx->prefixes, LEGACY_PREFIX_OPERAND_SIZE_OVERRIDE);

    switch (ctx->lift_ctx->pis_x86_ctx->cpumode) {
    case PIS_X86_CPUMODE_16_BIT:
        return has_size_override ? PIS_OPERAND_SIZE_4 : PIS_OPERAND_SIZE_2;
    case PIS_X86_CPUMODE_32_BIT:
        return has_size_override ? PIS_OPERAND_SIZE_2 : PIS_OPERAND_SIZE_4;
    case PIS_X86_CPUMODE_64_BIT:
        if (ctx->prefixes->rex.is_present && ctx->prefixes->rex.w) {
            return PIS_OPERAND_SIZE_8;
        } else {
            if (default_to_64_bit) {
                return has_size_override ? PIS_OPERAND_SIZE_2 : PIS_OPERAND_SIZE_8;
            } else {
                return has_size_override ? PIS_OPERAND_SIZE_2 : PIS_OPERAND_SIZE_4;
            }
        }
    default:
        // unreachable
        return PIS_OPERAND_SIZE_1;
    }
}

pis_operand_size_t get_effective_addr_size(const post_prefixes_ctx_t* ctx) {
    bool has_size_override =
        prefixes_contain_legacy_prefix(ctx->prefixes, LEGACY_PREFIX_ADDRESS_SIZE_OVERRIDE);

    switch (ctx->lift_ctx->pis_x86_ctx->cpumode) {
    case PIS_X86_CPUMODE_16_BIT:
        return has_size_override ? PIS_OPERAND_SIZE_4 : PIS_OPERAND_SIZE_2;
    case PIS_X86_CPUMODE_32_BIT:
        return has_size_override ? PIS_OPERAND_SIZE_2 : PIS_OPERAND_SIZE_4;
    case PIS_X86_CPUMODE_64_BIT:
        return has_size_override ? PIS_OPERAND_SIZE_4 : PIS_OPERAND_SIZE_8;
    default:
        // unreachable
        return PIS_OPERAND_SIZE_1;
    }
}

pis_operand_size_t get_effective_stack_addr_size(const post_prefixes_ctx_t* ctx) {
    return cpumode_get_operand_size(ctx->lift_ctx->pis_x86_ctx->cpumode);
}

pis_operand_t get_sp_operand(const post_prefixes_ctx_t* ctx) {
    return reg_get_operand(
        (reg_t) {.encoding = 0b100},
        get_effective_stack_addr_size(ctx),
        ctx->prefixes
    );
}
