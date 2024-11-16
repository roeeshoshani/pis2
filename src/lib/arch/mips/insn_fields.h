#pragma once

#include "../../types.h"
#include "../../utils.h"

#define MIPS_MAX_OPCODE_VALUE ((1 << 6) - 1)
#define MIPS_MAX_FUNCTION_VALUE ((1 << 5) - 1)

static inline u8 insn_field_opcode(u32 insn) {
    return GET_BITS(insn, 26, 6);
}

static inline u8 insn_field_rs(u32 insn) {
    return GET_BITS(insn, 21, 5);
}

static inline u8 insn_field_rt(u32 insn) {
    return GET_BITS(insn, 16, 5);
}

static inline u16 insn_field_imm_raw(u32 insn) {
    return GET_BITS(insn, 0, 16);
}

static inline u32 insn_field_imm_sext(u32 insn) {
    return (u32) (i32) (i16) insn_field_imm_raw(insn);
}

static inline u32 insn_field_imm_zext(u32 insn) {
    return insn_field_imm_raw(insn);
}

static inline u32 insn_field_imm_ext(u32 insn, imm_ext_kind_t ext_kind) {
    switch (ext_kind) {
        case IMM_EXT_KIND_SIGN_EXTEND:
            return insn_field_imm_sext(insn);
        case IMM_EXT_KIND_ZERO_EXTEND:
            return insn_field_imm_zext(insn);
        default:
            // unreachable
            return 0;
    }
}

static inline u32 insn_field_instr_index(u32 insn) {
    return GET_BITS(insn, 0, 26);
}

static inline u8 insn_field_rd(u32 insn) {
    return GET_BITS(insn, 11, 5);
}

static inline u8 insn_field_sa(u32 insn) {
    return GET_BITS(insn, 6, 5);
}

static inline u8 insn_field_function(u32 insn) {
    return GET_BITS(insn, 0, 5);
}
