#pragma once

#include "pis.h"
#include "prefixes.h"

typedef struct {
    u8 encoding;
} reg_t;

DECLARE_REG_OPERANDS(rax, rcx, rdx, rbx, rsp, rbp, rsi, rdi, r8, r9, r10, r11, r12, r13, r14, r15);

pis_operand_t
    reg_get_operand(reg_t reg, pis_operand_size_t operand_size, const prefixes_t* prefixes);
