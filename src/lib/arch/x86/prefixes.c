#include "prefixes.h"
#include "../../errors.h"
#include "../../except.h"
#include "../../utils.h"
#include "ctx.h"
#include "lift_ctx.h"

/// returns the group of the given legacy prefix.
/// if the provided value is not a valid legacy prefix, returns `LEGACY_PREFIX_GROUP_INVALID`.
static legacy_prefix_group_t legacy_prefix_get_group(legacy_prefix_t prefix) {
    switch (prefix) {
        case LEGACY_PREFIX_LOCK:
        case LEGACY_PREFIX_REPNZ_OR_BND:
        case LEGACY_PREFIX_REPZ_OR_REP:
            return LEGACY_PREFIX_GROUP_1;

        case LEGACY_PREFIX_CS_SEGMENT_OR_BRANCH_NOT_TAKEN:
        case LEGACY_PREFIX_SS_SEGMENT:
        case LEGACY_PREFIX_DS_SEGMENT_OR_BRANCH_TAKEN:
        case LEGACY_PREFIX_ES_SEGMENT:
        case LEGACY_PREFIX_FS_SEGMENT:
        case LEGACY_PREFIX_GS_SEGMENT:
            return LEGACY_PREFIX_GROUP_2;
        case LEGACY_PREFIX_OPERAND_SIZE_OVERRIDE:
            return LEGACY_PREFIX_GROUP_3;
        case LEGACY_PREFIX_ADDRESS_SIZE_OVERRIDE:
            return LEGACY_PREFIX_GROUP_4;
        default:
            return LEGACY_PREFIX_GROUP_INVALID;
    }
}

static err_t parse_legacy_prefixes(lift_ctx_t* ctx, legacy_prefixes_t* parsed_prefixes) {
    err_t err = SUCCESS;
    legacy_prefixes_t prefixes = {};

    while (!cursor_eof(ctx->machine_code)) {
        u8 cur_byte = 0;
        CHECK_RETHROW(cursor_peek_1(ctx->machine_code, &cur_byte));

        legacy_prefix_t cur_prefix = (legacy_prefix_t) cur_byte;

        legacy_prefix_group_t group = legacy_prefix_get_group(cur_prefix);
        if (group == LEGACY_PREFIX_GROUP_INVALID) {
            // the current byte is not a legacy prefix, so we are done parsing legacy prefixes.
            break;
        }

        // make sure that we don't have 2 prefixes of the same group.
        legacy_prefix_t existing_prefix = prefixes.by_group[group];
        CHECK_TRACE_CODE(
            // allow using the same prefix multiple times, which basically has no effect.
            // this is sometimes used by the compiler to generate NOPs of arbitrary lengths.
            existing_prefix == LEGACY_PREFIX_INVALID || existing_prefix == cur_prefix,
            PIS_ERR_X86_2_LEGACY_PREFIXES_OF_SAME_GROUP,
            "prefix 0x%x and prefix 0x%x are of the same group %d",
            existing_prefix,
            cur_prefix,
            group
        );

        prefixes.by_group[group] = cur_prefix;
        cursor_advance(ctx->machine_code, 1);
    }

    *parsed_prefixes = prefixes;

cleanup:
    return err;
}

static err_t parse_rex_prefix(lift_ctx_t* ctx, rex_prefix_t* rex_prefix) {
    err_t err = SUCCESS;

    // REX prefix is only relevant for 64-bit mode
    if (ctx->pis_x86_ctx->cpumode != PIS_X86_CPUMODE_64_BIT) {
        SUCCESS_CLEANUP();
    }

    u8 cur_byte = 0;
    CHECK_RETHROW(cursor_peek_1(ctx->machine_code, &cur_byte));

    if ((cur_byte & 0xf0) == 0x40) {
        // the byte is a REX prefix
        *rex_prefix = (rex_prefix_t) {
            .is_present = true,
            .w = GET_BIT_VALUE(cur_byte, 3),
            .r = GET_BIT_VALUE(cur_byte, 2),
            .x = GET_BIT_VALUE(cur_byte, 1),
            .b = GET_BIT_VALUE(cur_byte, 0),
        };
        cursor_advance(ctx->machine_code, 1);
    } else {
        *rex_prefix = (rex_prefix_t) {};
    }

cleanup:
    return err;
}

err_t parse_prefixes(lift_ctx_t* ctx, prefixes_t* prefixes) {
    err_t err = SUCCESS;

    CHECK_RETHROW(parse_legacy_prefixes(ctx, &prefixes->legacy));

    CHECK_RETHROW(parse_rex_prefix(ctx, &prefixes->rex));

cleanup:
    return err;
}

bool prefixes_contain_legacy_prefix(const prefixes_t* prefixes, legacy_prefix_t contains) {
    for (size_t i = 0; i < LEGACY_PREFIX_GROUP_AMOUNT; i++) {
        if (prefixes->legacy.by_group[i] == contains) {
            return true;
        }
    }
    return false;
}

u8 apply_rex_bit_to_reg_encoding(u8 reg_encoding, u8 rex_bit) {
    return reg_encoding | (rex_bit << 3);
}

u8 apply_rex_to_opcode_reg_encoding(u8 reg_encoding, const prefixes_t* prefixes) {
    // the REX.B bit is an extension to the register encoded in an opcode
    return apply_rex_bit_to_reg_encoding(reg_encoding, prefixes->rex.b);
}
