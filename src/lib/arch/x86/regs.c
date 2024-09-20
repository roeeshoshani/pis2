#include "regs.h"
#include "pis.h"

DEFINE_REG_OPERANDS(
    0, 8, 8, RAX, RCX, RDX, RBX, RSP, RBP, RSI, RDI, R8, R9, R10, R11, R12, R13, R14, R15
);

DEFINE_REG_OPERANDS(
    0, 8, 4, EAX, ECX, EDX, EBX, ESP, EBP, ESI, EDI, R8D, R9D, R10D, R11D, R12D, R13D, R14D, R15D
);

DEFINE_REG_OPERANDS(
    0, 8, 2, AX, CX, DX, BX, SP, BP, SI, DI, R8W, R9W, R10W, R11W, R12W, R13W, R14W, R15W
);

pis_operand_t
    reg_get_operand(u8 reg_encoding, pis_operand_size_t operand_size, const prefixes_t* prefixes) {
    if (operand_size == PIS_OPERAND_SIZE_1 && !prefixes->rex.is_present && reg_encoding >= 4 &&
        reg_encoding <= 7) {
        // this is an access to the high part of a gpr, for example `AH`.

        // find the encoding of the base register which is accessed, for example for `AH` this will
        // be `RAX`.
        u8 base_reg_encoding = reg_encoding - 4;

        // go to the start of the base register, and add 1 to get the higher byte
        return PIS_OPERAND_REG(base_reg_encoding * 8 + 1, operand_size);
    }
    // regular register access
    return PIS_OPERAND_REG(reg_encoding * 8, operand_size);
}
