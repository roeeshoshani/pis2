#pragma once

#include "../../types.h"

typedef struct {
    u8 opcode;
    u8 rs;
    u8 rt;
    u16 offset;
} insn_i_type_t;

typedef struct {
    u8 opcode;
    u32 instr_index;
} insn_j_type_t;

typedef struct {
    u8 opcode;
    u8 rs;
    u8 rt;
    u8 rd;
    u8 sa;
    u8 function;
} insn_r_type_t;

insn_i_type_t insn_i_type_decode(u32 insn);

insn_j_type_t insn_j_type_decode(u32 insn);

insn_r_type_t insn_r_type_decode(u32 insn);
