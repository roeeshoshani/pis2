#pragma once

#include "../../except.h"
#include "../../pis.h"
#include "../../types.h"
#include "../../lift_args.h"
#include "cpumode.h"

typedef enum {
    // group 1
    LEGACY_PREFIX_LOCK = 0xf0,
    LEGACY_PREFIX_REPNZ_OR_BND = 0xf2,
    LEGACY_PREFIX_REPZ_OR_REP = 0xf3,

    // group 2
    LEGACY_PREFIX_CS_SEGMENT_OR_BRANCH_NOT_TAKEN = 0x2e,
    LEGACY_PREFIX_SS_SEGMENT = 0x36,
    LEGACY_PREFIX_DS_SEGMENT_OR_BRANCH_TAKEN = 0x3e,
    LEGACY_PREFIX_ES_SEGMENT = 0x26,
    LEGACY_PREFIX_FS_SEGMENT = 0x64,
    LEGACY_PREFIX_GS_SEGMENT = 0x65,

    // group 3
    LEGACY_PREFIX_OPERAND_SIZE_OVERRIDE = 0x66,

    // group 4
    LEGACY_PREFIX_ADDRESS_SIZE_OVERRIDE = 0x67,

    // invalid
    LEGACY_PREFIX_INVALID = 0x0,
} legacy_prefix_t;

typedef enum {
    LEGACY_PREFIX_GROUP_1,
    LEGACY_PREFIX_GROUP_2,
    LEGACY_PREFIX_GROUP_3,
    LEGACY_PREFIX_GROUP_4,
    LEGACY_PREFIX_GROUP_AMOUNT,
    LEGACY_PREFIX_GROUP_INVALID = LEGACY_PREFIX_GROUP_AMOUNT,
} legacy_prefix_group_t;

typedef struct {
    legacy_prefix_t by_group[LEGACY_PREFIX_GROUP_AMOUNT];
} legacy_prefixes_t;

typedef struct {
    bool is_present;
    u8 w;
    u8 r;
    u8 x;
    u8 b;
} rex_prefix_t;

typedef struct {
    legacy_prefixes_t legacy;
    rex_prefix_t rex;
} prefixes_t;

err_t parse_prefixes(pis_lift_args_t* args, pis_x86_cpumode_t cpumode, prefixes_t* prefixes);

bool prefixes_contain_legacy_prefix(const prefixes_t* prefixes, legacy_prefix_t contains);

u8 apply_rex_bit_to_reg_encoding(u8 reg_encoding, u8 rex_bit);

u8 apply_rex_to_opcode_reg_encoding(u8 reg_encoding, const prefixes_t* prefixes);
