#include "regs.h"

DEFINE_REG_OPERANDS(
    0, 8, 8, rax, rcx, rdx, rbx, rsp, rbp, rsi, rdi, r8, r9, r10, r11, r12, r13, r14, r15
);

const pis_operand_t* pis_reg_get_operand(reg_t reg) {
    // TODO: implement this
    UNUSED(reg);
    return NULL;
}
