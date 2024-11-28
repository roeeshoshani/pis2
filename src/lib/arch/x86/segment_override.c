#include "segment_override.h"
#include "regs.h"

bool insn_has_segment_override(ctx_t* ctx, pis_op_t* segment_base) {
    pis_reg_t segment_base_reg;
    bool has_segment_override = false;

    // check the group 2 legacy prefix, and if it is a segment override prefix, extract the operand
    // address of the segment base register operand.
    switch (ctx->prefixes.legacy.by_group[LEGACY_PREFIX_GROUP_2]) {
        case LEGACY_PREFIX_CS_SEGMENT_OR_BRANCH_NOT_TAKEN:
            segment_base_reg = X86_CS_BASE;
            has_segment_override = true;
            break;
        case LEGACY_PREFIX_SS_SEGMENT:
            segment_base_reg = X86_SS_BASE;
            has_segment_override = true;
            break;
        case LEGACY_PREFIX_DS_SEGMENT_OR_BRANCH_TAKEN:
            segment_base_reg = X86_DS_BASE;
            has_segment_override = true;
            break;
        case LEGACY_PREFIX_ES_SEGMENT:
            segment_base_reg = X86_ES_BASE;
            has_segment_override = true;
            break;
        case LEGACY_PREFIX_FS_SEGMENT:
            segment_base_reg = X86_FS_BASE;
            has_segment_override = true;
            break;
        case LEGACY_PREFIX_GS_SEGMENT:
            segment_base_reg = X86_GS_BASE;
            has_segment_override = true;
            break;
        default:
            break;
    }

    // if the instruction has a segment override, return the segment base operand to the caller
    if (has_segment_override) {
        *segment_base = PIS_OPERAND_REG(segment_base_reg.region.offset, ctx->addr_size);
    }

    return has_segment_override;
}
