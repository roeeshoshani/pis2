#pragma once

#include "pis.h"
#include "recursive_macros.h"

typedef struct {
    u8 encoding;
} reg_t;

DECLARE_REG_OPERANDS(rax, rcx, rdx, rbx, rsp, rbp, rsi, rdi, r8, r9, r10, r11, r12, r13, r14, r15);

const pis_operand_t* pis_reg_get_operand(reg_t reg);
