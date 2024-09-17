#include "regs.h"
#include "pis.h"

DEFINE_REG_OPERANDS(
    0, 8, 8, rax, rcx, rdx, rbx, rsp, rbp, rsi, rdi, r8, r9, r10, r11, r12, r13, r14, r15
);

DEFINE_REG_OPERANDS(
    0, 8, 4, eax, ecx, edx, ebx, esp, ebp, esi, edi, r8d, r9d, r10d, r11d, r12d, r13d, r14d, r15d
);

DEFINE_REG_OPERANDS(
    0, 8, 2, ax, cx, dx, bx, sp, bp, si, di, r8w, r9w, r10w, r11w, r12w, r13w, r14w, r15w
);

pis_operand_t
    reg_get_operand(reg_t reg, pis_operand_size_t operand_size, const prefixes_t* prefixes) {
    if (operand_size == PIS_OPERAND_SIZE_1 && !prefixes->rex.is_present && reg.encoding >= 4 &&
        reg.encoding <= 7) {
        // this is an access to the high part of a gpr, for example `AH`.

        // find the encoding of the base register which is accessed, for example for `AH` this will
        // be `RAX`.
        u8 base_reg_encoding = reg.encoding - 4;

        // go to the start of the base register, and add 1 to get the higher byte
        return PIS_OPERAND_REG(base_reg_encoding * 8 + 1, operand_size);
    }
    // regular register access
    return PIS_OPERAND_REG(reg.encoding * 8, operand_size);
}
