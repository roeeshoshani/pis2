#pragma once

#include "../../pis.h"
#include "ctx.h"
#include "prefixes.h"

DECLARE_REG_OPERANDS(
    X86_RAX,
    X86_RCX,
    X86_RDX,
    X86_RBX,
    X86_RSP,
    X86_RBP,
    X86_RSI,
    X86_RDI,
    X86_R8,
    X86_R9,
    X86_R10,
    X86_R11,
    X86_R12,
    X86_R13,
    X86_R14,
    X86_R15
);
DECLARE_REG_OPERANDS(
    X86_EAX,
    X86_ECX,
    X86_EDX,
    X86_EBX,
    X86_ESP,
    X86_EBP,
    X86_ESI,
    X86_EDI,
    X86_R8D,
    X86_R9D,
    X86_R10D,
    X86_R11D,
    X86_R12D,
    X86_R13D,
    X86_R14D,
    X86_R15D
);
DECLARE_REG_OPERANDS(
    X86_AX,
    X86_CX,
    X86_DX,
    X86_BX,
    X86_SP,
    X86_BP,
    X86_SI,
    X86_DI,
    X86_R8W,
    X86_R9W,
    X86_R10W,
    X86_R11W,
    X86_R12W,
    X86_R13W,
    X86_R14W,
    X86_R15W
);

DECLARE_REG_OPERANDS(
    X86_AL,
    X86_CL,
    X86_DL,
    X86_BL,
    X86_SPL,
    X86_BPL,
    X86_SIL,
    X86_DIL,
    X86_R8B,
    X86_R9B,
    X86_R10B,
    X86_R11B,
    X86_R12B,
    X86_R13B,
    X86_R14B,
    X86_R15B
);

DECLARE_REG_OPERANDS(X86_AH, X86_CH, X86_DH, X86_BH);

DECLARE_REG_OPERANDS(
    X86_RFLAGS,
    X86_EFLAGS,
    X86_FLAGS_CF,
    X86_FLAGS_PF,
    X86_FLAGS_AF,
    X86_FLAGS_ZF,
    X86_FLAGS_SF,
    X86_FLAGS_TF,
    X86_FLAGS_IF,
    X86_FLAGS_DF,
    X86_FLAGS_OF,
    X86_FLAGS_IOPL,
    X86_FLAGS_NT,
    X86_FLAGS_RF,
    X86_FLAGS_VM,
    X86_FLAGS_AC,
    X86_FLAGS_VIF,
    X86_FLAGS_VIP,
    X86_FLAGS_ID
);

pis_operand_t
    reg_get_operand(u8 reg_encoding, pis_size_t operand_size, const prefixes_t* prefixes);

err_t write_gpr(const ctx_t* ctx, const pis_operand_t* gpr, const pis_operand_t* value);
