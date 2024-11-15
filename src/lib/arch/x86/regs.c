#include "regs.h"
#include "../../pis.h"
#include "ctx.h"

#define FLAGS_REG_OFFSET (0x1000)

DEFINE_REG_OPERANDS(
    0,
    8,
    PIS_SIZE_8,
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

DEFINE_REG_OPERANDS(
    0,
    8,
    PIS_SIZE_4,
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

DEFINE_REG_OPERANDS(
    0,
    8,
    PIS_SIZE_2,
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

DEFINE_REG_OPERANDS(
    0,
    8,
    PIS_SIZE_1,
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

DEFINE_REG_OPERANDS(1, 8, PIS_SIZE_1, X86_AH, X86_CH, X86_DH, X86_BH);

DEFINE_REG_OPERAND(X86_RFLAGS, FLAGS_REG_OFFSET, PIS_SIZE_8);
DEFINE_REG_OPERAND(X86_EFLAGS, FLAGS_REG_OFFSET, PIS_SIZE_4);
DEFINE_REG_OPERAND(X86_FLAGS_CF, FLAGS_REG_OFFSET + 0, PIS_SIZE_1);
DEFINE_REG_OPERAND(X86_FLAGS_PF, FLAGS_REG_OFFSET + 2, PIS_SIZE_1);
DEFINE_REG_OPERAND(X86_FLAGS_AF, FLAGS_REG_OFFSET + 4, PIS_SIZE_1);
DEFINE_REG_OPERAND(X86_FLAGS_ZF, FLAGS_REG_OFFSET + 6, PIS_SIZE_1);
DEFINE_REG_OPERAND(X86_FLAGS_SF, FLAGS_REG_OFFSET + 7, PIS_SIZE_1);
DEFINE_REG_OPERAND(X86_FLAGS_TF, FLAGS_REG_OFFSET + 8, PIS_SIZE_1);
DEFINE_REG_OPERAND(X86_FLAGS_IF, FLAGS_REG_OFFSET + 9, PIS_SIZE_1);
DEFINE_REG_OPERAND(X86_FLAGS_DF, FLAGS_REG_OFFSET + 10, PIS_SIZE_1);
DEFINE_REG_OPERAND(X86_FLAGS_OF, FLAGS_REG_OFFSET + 11, PIS_SIZE_1);
DEFINE_REG_OPERAND(X86_FLAGS_IOPL, FLAGS_REG_OFFSET + 12, PIS_SIZE_2);
DEFINE_REG_OPERAND(X86_FLAGS_NT, FLAGS_REG_OFFSET + 14, PIS_SIZE_1);
DEFINE_REG_OPERAND(X86_FLAGS_RF, FLAGS_REG_OFFSET + 16, PIS_SIZE_1);
DEFINE_REG_OPERAND(X86_FLAGS_VM, FLAGS_REG_OFFSET + 17, PIS_SIZE_1);
DEFINE_REG_OPERAND(X86_FLAGS_AC, FLAGS_REG_OFFSET + 18, PIS_SIZE_1);
DEFINE_REG_OPERAND(X86_FLAGS_VIF, FLAGS_REG_OFFSET + 19, PIS_SIZE_1);
DEFINE_REG_OPERAND(X86_FLAGS_VIP, FLAGS_REG_OFFSET + 20, PIS_SIZE_1);
DEFINE_REG_OPERAND(X86_FLAGS_ID, FLAGS_REG_OFFSET + 21, PIS_SIZE_1);

pis_operand_t
    reg_get_operand(u8 reg_encoding, pis_size_t operand_size, const prefixes_t* prefixes) {
    if (operand_size == PIS_SIZE_1 && !prefixes->rex.is_present && reg_encoding >= 4 &&
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


err_t write_gpr(const ctx_t* ctx, const pis_operand_t* gpr, const pis_operand_t* value) {
    err_t err = SUCCESS;
    PIS_EMIT(&ctx->args->result, PIS_INSN2(PIS_OPCODE_MOVE, *gpr, *value));

    // writes to 32 bit gprs zero out the upper half of the 64 bit gpr.
    if (gpr->size == PIS_SIZE_4) {
        pis_operand_t gpr64 = PIS_OPERAND(gpr->addr, PIS_SIZE_8);
        PIS_EMIT(&ctx->args->result, PIS_INSN2(PIS_OPCODE_ZERO_EXTEND, gpr64, *gpr));
    }
cleanup:
    return err;
}
