#pragma once

#include "pis.h"
#include "prefixes.h"

DECLARE_REG_OPERANDS(RAX, RCX, RDX, RBX, RSP, RBP, RSI, RDI, R8, R9, R10, R11, R12, R13, R14, R15);
DECLARE_REG_OPERANDS(
    EAX, ECX, EDX, EBX, ESP, EBP, ESI, EDI, R8D, R9D, R10D, R11D, R12D, R13D, R14D, R15D
);
DECLARE_REG_OPERANDS(AX, CX, DX, BX, SP, BP, SI, DI, R8W, R9W, R10W, R11W, R12W, R13W, R14W, R15W);

DECLARE_REG_OPERANDS(
    AL, CL, DL, BL, SPL, BPL, SIL, DIL, R8B, R9B, R10B, R11B, R12B, R13B, R14B, R15B
);

DECLARE_REG_OPERANDS(AH, CH, DH, BH);

DECLARE_REG_OPERANDS(
    RFLAGS,
    EFLAGS,
    FLAGS_CF,
    FLAGS_PF,
    FLAGS_AF,
    FLAGS_ZF,
    FLAGS_SF,
    FLAGS_TF,
    FLAGS_IF,
    FLAGS_DF,
    FLAGS_OF,
    FLAGS_IOPL,
    FLAGS_NT,
    FLAGS_RF,
    FLAGS_VM,
    FLAGS_AC,
    FLAGS_VIF,
    FLAGS_VIP,
    FLAGS_ID
);

pis_operand_t
    reg_get_operand(u8 reg_encoding, pis_operand_size_t operand_size, const prefixes_t* prefixes);
