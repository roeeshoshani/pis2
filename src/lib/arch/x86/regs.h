#pragma once

#include "pis.h"
#include "prefixes.h"

typedef struct {
    u8 encoding;
} reg_t;

DECLARE_REG_OPERANDS(rax, rcx, rdx, rbx, rsp, rbp, rsi, rdi, r8, r9, r10, r11, r12, r13, r14, r15);
DECLARE_REG_OPERANDS(eax, ecx, edx, ebx, esp, ebp, esi, edi, r8d, r9d, r10d, r11d, r12d, r13d, r14d, r15d);
DECLARE_REG_OPERANDS(ax, cx, dx, bx, sp, bp, si, di, r8w, r9w, r10w, r11w, r12w, r13w, r14w, r15w);

pis_operand_t
    reg_get_operand(reg_t reg, pis_operand_size_t operand_size, const prefixes_t* prefixes);
