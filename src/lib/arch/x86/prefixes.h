#pragma once

#include "except.h"
#include "lift_ctx.h"
#include "pis.h"
#include "types.h"

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

typedef struct {
    /// the operand size for instructions that default to using 64 bit operands
    pis_operand_size_t insn_default_64_bit;
    /// the operand size for instructions that don't default to using 64 bit operands
    pis_operand_size_t insn_default_not_64_bit;
} effective_operand_sizes_t;

typedef struct {
    lift_ctx_t* lift_ctx;
    const prefixes_t* prefixes;
    pis_operand_size_t addr_size;
    effective_operand_sizes_t operand_sizes;
    bool has_modrm;
    uint8_t modrm_byte;
} insn_ctx_t;

err_t parse_prefixes(lift_ctx_t* ctx, prefixes_t* prefixes);

bool prefixes_contain_legacy_prefix(const prefixes_t* prefixes, legacy_prefix_t contains);

u8 apply_rex_bit_to_reg_encoding(u8 reg_encoding, u8 rex_bit);

u8 apply_rex_to_opcode_reg_encoding(u8 reg_encoding, const prefixes_t* prefixes);
