#include "common.h"
#include "arch/x86/ctx.h"
#include "arch/x86/prefixes.h"
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

pis_operand_size_t get_effective_operand_size(const lift_ctx_t* ctx, const prefixes_t* prefixes) {
    bool has_size_override =
        prefixes_contain_legacy_prefix(prefixes, LEGACY_PREFIX_OPERAND_SIZE_OVERRIDE);

    switch (ctx->pis_x86_ctx->cpumode) {
    case PIS_X86_CPUMODE_16_BIT:
        return has_size_override ? PIS_OPERAND_SIZE_4 : PIS_OPERAND_SIZE_2;
    case PIS_X86_CPUMODE_32_BIT:
        switch (ctx->pis_x86_ctx->code_segment_default_size) {
        case PIS_X86_SEGMENT_DEFAULT_SIZE_32:
            return has_size_override ? PIS_OPERAND_SIZE_2 : PIS_OPERAND_SIZE_4;
        case PIS_X86_SEGMENT_DEFAULT_SIZE_16:
            return has_size_override ? PIS_OPERAND_SIZE_4 : PIS_OPERAND_SIZE_2;
        default:
            // unreachable
            return PIS_OPERAND_SIZE_1;
        }
    case PIS_X86_CPUMODE_64_BIT:
        if (prefixes->rex.is_present && prefixes->rex.w) {
            return PIS_OPERAND_SIZE_8;
        } else {
            return has_size_override ? PIS_OPERAND_SIZE_2 : PIS_OPERAND_SIZE_4;
        }
    default:
        // unreachable
        return PIS_OPERAND_SIZE_1;
    }
}

pis_operand_size_t get_effective_addr_size(const lift_ctx_t* ctx, const prefixes_t* prefixes) {
    bool has_size_override =
        prefixes_contain_legacy_prefix(prefixes, LEGACY_PREFIX_ADDRESS_SIZE_OVERRIDE);

    switch (ctx->pis_x86_ctx->cpumode) {
    case PIS_X86_CPUMODE_16_BIT:
        return has_size_override ? PIS_OPERAND_SIZE_4 : PIS_OPERAND_SIZE_2;
    case PIS_X86_CPUMODE_32_BIT:
        switch (ctx->pis_x86_ctx->code_segment_default_size) {
        case PIS_X86_SEGMENT_DEFAULT_SIZE_32:
            return has_size_override ? PIS_OPERAND_SIZE_2 : PIS_OPERAND_SIZE_4;
        case PIS_X86_SEGMENT_DEFAULT_SIZE_16:
            return has_size_override ? PIS_OPERAND_SIZE_4 : PIS_OPERAND_SIZE_2;
        default:
            // unreachable
            return PIS_OPERAND_SIZE_1;
        }
    case PIS_X86_CPUMODE_64_BIT:
        return has_size_override ? PIS_OPERAND_SIZE_4 : PIS_OPERAND_SIZE_8;
    default:
        // unreachable
        return PIS_OPERAND_SIZE_1;
    }
}
