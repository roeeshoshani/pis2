#pragma once

#include "../../types.h"
#include "../../utils.h"

#define MIPS_MAX_OPCODE_VALUE ((1 << 6) - 1)

static inline u8 insn_field_opcode(u32 insn) {
    return GET_BITS(insn, 26, 6);
}

static inline u8 insn_field_rs(u32 insn) {
    return GET_BITS(insn, 21, 5);
}

static inline u8 insn_field_rt(u32 insn) {
    return GET_BITS(insn, 16, 5);
}

static inline u16 insn_field_offset(u32 insn) {
    return GET_BITS(insn, 0, 16);
}

static inline u16 insn_field_immediate(u32 insn) {
    return GET_BITS(insn, 0, 16);
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
