#pragma once

#include "pis.h"
#include "recursive_macros.h"

typedef enum {
    REG_RAX,
    REG_RCX,
    REG_RDX,
    REG_RBX,
    REG_RSP_OR_AH,
    REG_RBP_OR_CH,
    REG_RSI_OR_DH,
    REG_RDI_OR_BH,
    REG_AMOUNT,
    REG_MAX = REG_AMOUNT - 1,
} reg_t;

DECLARE_REG_OPERANDS(rax, rcx, rdx, rbx, rsp, rbp, rsi, rdi, r8, r9, r10, r11, r12, r13, r14, r15);
