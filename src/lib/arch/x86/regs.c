#include "regs.h"
#include "pis.h"

#define FLAGS_REG_OFFSET (0x1000)

DEFINE_REG_OPERANDS(
    0,
    8,
    PIS_OPERAND_SIZE(8),
    RAX,
    RCX,
    RDX,
    RBX,
    RSP,
    RBP,
    RSI,
    RDI,
    R8,
    R9,
    R10,
    R11,
    R12,
    R13,
    R14,
    R15
);

DEFINE_REG_OPERANDS(
    0,
    8,
    PIS_OPERAND_SIZE(4),
    EAX,
    ECX,
    EDX,
    EBX,
    ESP,
    EBP,
    ESI,
    EDI,
    R8D,
    R9D,
    R10D,
    R11D,
    R12D,
    R13D,
    R14D,
    R15D
);

DEFINE_REG_OPERANDS(
    0,
    8,
    PIS_OPERAND_SIZE(2),
    AX,
    CX,
    DX,
    BX,
    SP,
    BP,
    SI,
    DI,
    R8W,
    R9W,
    R10W,
    R11W,
    R12W,
    R13W,
    R14W,
    R15W
);

DEFINE_REG_OPERANDS(
    0,
    8,
    PIS_OPERAND_SIZE(1),
    AL,
    CL,
    DL,
    BL,
    SPL,
    BPL,
    SIL,
    DIL,
    R8B,
    R9B,
    R10B,
    R11B,
    R12B,
    R13B,
    R14B,
    R15B
);

DEFINE_REG_OPERANDS(1, 8, PIS_OPERAND_SIZE(1), AH, CH, DH, BH);

DEFINE_REG_OPERAND(RFLAGS, FLAGS_REG_OFFSET, PIS_OPERAND_SIZE(8));
DEFINE_REG_OPERAND(EFLAGS, FLAGS_REG_OFFSET, PIS_OPERAND_SIZE(4));
DEFINE_REG_OPERAND(FLAGS_CF, FLAGS_REG_OFFSET + 0, PIS_OPERAND_SIZE(1));
DEFINE_REG_OPERAND(FLAGS_PF, FLAGS_REG_OFFSET + 2, PIS_OPERAND_SIZE(1));
DEFINE_REG_OPERAND(FLAGS_AF, FLAGS_REG_OFFSET + 4, PIS_OPERAND_SIZE(1));
DEFINE_REG_OPERAND(FLAGS_ZF, FLAGS_REG_OFFSET + 6, PIS_OPERAND_SIZE(1));
DEFINE_REG_OPERAND(FLAGS_SF, FLAGS_REG_OFFSET + 7, PIS_OPERAND_SIZE(1));
DEFINE_REG_OPERAND(FLAGS_TF, FLAGS_REG_OFFSET + 8, PIS_OPERAND_SIZE(1));
DEFINE_REG_OPERAND(FLAGS_IF, FLAGS_REG_OFFSET + 9, PIS_OPERAND_SIZE(1));
DEFINE_REG_OPERAND(FLAGS_DF, FLAGS_REG_OFFSET + 10, PIS_OPERAND_SIZE(1));
DEFINE_REG_OPERAND(FLAGS_OF, FLAGS_REG_OFFSET + 11, PIS_OPERAND_SIZE(1));
DEFINE_REG_OPERAND(FLAGS_IOPL, FLAGS_REG_OFFSET + 12, PIS_OPERAND_SIZE(2));
DEFINE_REG_OPERAND(FLAGS_NT, FLAGS_REG_OFFSET + 14, PIS_OPERAND_SIZE(1));
DEFINE_REG_OPERAND(FLAGS_RF, FLAGS_REG_OFFSET + 16, PIS_OPERAND_SIZE(1));
DEFINE_REG_OPERAND(FLAGS_VM, FLAGS_REG_OFFSET + 17, PIS_OPERAND_SIZE(1));
DEFINE_REG_OPERAND(FLAGS_AC, FLAGS_REG_OFFSET + 18, PIS_OPERAND_SIZE(1));
DEFINE_REG_OPERAND(FLAGS_VIF, FLAGS_REG_OFFSET + 19, PIS_OPERAND_SIZE(1));
DEFINE_REG_OPERAND(FLAGS_VIP, FLAGS_REG_OFFSET + 20, PIS_OPERAND_SIZE(1));
DEFINE_REG_OPERAND(FLAGS_ID, FLAGS_REG_OFFSET + 21, PIS_OPERAND_SIZE(1));

pis_operand_t
    reg_get_operand(u8 reg_encoding, pis_operand_size_t operand_size, const prefixes_t* prefixes) {
    if (operand_size.bytes == 1 && !prefixes->rex.is_present && reg_encoding >= 4 &&
        reg_encoding <= 7) {
        // this is an access to the high part of a gpr, for example `AH`.

        // find the encoding of the base register which is accessed, for example for `AH` this
        // will be `RAX`.
        u8 base_reg_encoding = reg_encoding - 4;

        // go to the start of the base register, and add 1 to get the higher byte
        return PIS_OPERAND_REG(base_reg_encoding * 8 + 1, operand_size);
    }
    // regular register access
    return PIS_OPERAND_REG(reg_encoding * 8, operand_size);
}


err_t write_gpr(
    const post_prefixes_ctx_t* ctx, const pis_operand_t* gpr, const pis_operand_t* value
) {
    err_t err = SUCCESS;
    LIFT_CTX_EMIT(ctx->lift_ctx, PIS_INSN2(PIS_OPCODE_MOVE, *gpr, *value));

    // writes to 32 bit gprs zero out the upper half of the 64 bit gpr.
    if (gpr->size.bytes == 4) {
        pis_operand_t gpr64 = PIS_OPERAND(gpr->addr, PIS_OPERAND_SIZE(8));
        LIFT_CTX_EMIT(ctx->lift_ctx, PIS_INSN2(PIS_OPCODE_ZERO_EXTEND, gpr64, *gpr));
    }
cleanup:
    return err;
}
