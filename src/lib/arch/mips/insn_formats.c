#include "insn_formats.h"

#include "../../utils.h"

insn_i_type_t insn_i_type_decode(u32 insn) {
    return (insn_i_type_t) {
        .opcode = GET_BITS(insn, 26, 6),
        .rs = GET_BITS(insn, 21, 5),
        .rt = GET_BITS(insn, 16, 5),
        .offset = GET_BITS(insn, 0, 16),
    };
}

insn_j_type_t insn_j_type_decode(u32 insn) {
    return (insn_j_type_t) {
        .opcode = GET_BITS(insn, 26, 6),
        .instr_index = GET_BITS(insn, 0, 26),
    };
}

insn_r_type_t insn_r_type_decode(u32 insn) {
    return (insn_r_type_t) {
        .opcode = GET_BITS(insn, 26, 6),
        .rs = GET_BITS(insn, 21, 5),
        .rt = GET_BITS(insn, 16, 5),
        .rd = GET_BITS(insn, 11, 5),
        .sa = GET_BITS(insn, 6, 5),
        .function = GET_BITS(insn, 0, 5),
    };
}
