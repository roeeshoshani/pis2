#include "regs.h"
#include "except.h"
#include "pis.h"

#define FLAGS_REG_OFFSET (0x1000)

DEFINE_REG_OPERANDS(
    0,
    8,
    PIS_OPERAND_SIZE_8,
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
    PIS_OPERAND_SIZE_4,
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
    PIS_OPERAND_SIZE_2,
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
    PIS_OPERAND_SIZE_1,
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

DEFINE_REG_OPERANDS(1, 8, PIS_OPERAND_SIZE_1, AH, CH, DH, BH);

DEFINE_REG_OPERAND(RFLAGS, FLAGS_REG_OFFSET, PIS_OPERAND_SIZE_8);
DEFINE_REG_OPERAND(EFLAGS, FLAGS_REG_OFFSET, PIS_OPERAND_SIZE_4);
DEFINE_REG_OPERAND(FLAGS_CF, FLAGS_REG_OFFSET + 0, PIS_OPERAND_SIZE_1);
DEFINE_REG_OPERAND(FLAGS_PF, FLAGS_REG_OFFSET + 2, PIS_OPERAND_SIZE_1);
DEFINE_REG_OPERAND(FLAGS_AF, FLAGS_REG_OFFSET + 4, PIS_OPERAND_SIZE_1);
DEFINE_REG_OPERAND(FLAGS_ZF, FLAGS_REG_OFFSET + 6, PIS_OPERAND_SIZE_1);
DEFINE_REG_OPERAND(FLAGS_SF, FLAGS_REG_OFFSET + 7, PIS_OPERAND_SIZE_1);
DEFINE_REG_OPERAND(FLAGS_TF, FLAGS_REG_OFFSET + 8, PIS_OPERAND_SIZE_1);
DEFINE_REG_OPERAND(FLAGS_IF, FLAGS_REG_OFFSET + 9, PIS_OPERAND_SIZE_1);
DEFINE_REG_OPERAND(FLAGS_DF, FLAGS_REG_OFFSET + 10, PIS_OPERAND_SIZE_1);
DEFINE_REG_OPERAND(FLAGS_OF, FLAGS_REG_OFFSET + 11, PIS_OPERAND_SIZE_1);
DEFINE_REG_OPERAND(FLAGS_IOPL, FLAGS_REG_OFFSET + 12, PIS_OPERAND_SIZE_2);
DEFINE_REG_OPERAND(FLAGS_NT, FLAGS_REG_OFFSET + 14, PIS_OPERAND_SIZE_1);
DEFINE_REG_OPERAND(FLAGS_RF, FLAGS_REG_OFFSET + 16, PIS_OPERAND_SIZE_1);
DEFINE_REG_OPERAND(FLAGS_VM, FLAGS_REG_OFFSET + 17, PIS_OPERAND_SIZE_1);
DEFINE_REG_OPERAND(FLAGS_AC, FLAGS_REG_OFFSET + 18, PIS_OPERAND_SIZE_1);
DEFINE_REG_OPERAND(FLAGS_VIF, FLAGS_REG_OFFSET + 19, PIS_OPERAND_SIZE_1);
DEFINE_REG_OPERAND(FLAGS_VIP, FLAGS_REG_OFFSET + 20, PIS_OPERAND_SIZE_1);
DEFINE_REG_OPERAND(FLAGS_ID, FLAGS_REG_OFFSET + 21, PIS_OPERAND_SIZE_1);

err_t reg_get_operand(u8 reg_index, pis_operand_t* operand) {
    err_t err = SUCCESS;
    if (reg_index < 16) {
        // 64-bit GPR
        *operand = PIS_OPERAND_REG(reg_index * 8, PIS_OPERAND_SIZE_8);
    } else if (reg_index < 32) {
        // 32-bit GPR

        // convert the index to a zero based index
        reg_index -= 16;

        *operand = PIS_OPERAND_REG(reg_index * 8, PIS_OPERAND_SIZE_4);
    } else if (reg_index < 48) {
        // 16-bit GPR

        // convert the index to a zero based index
        reg_index -= 32;

        *operand = PIS_OPERAND_REG(reg_index * 8, PIS_OPERAND_SIZE_2);
    } else if (reg_index < 52) {
        // 8-bit GPR low (e.g AL)

        // convert the index to a zero based index
        reg_index -= 48;

        *operand = PIS_OPERAND_REG(reg_index * 8, PIS_OPERAND_SIZE_1);
    } else if (reg_index < 56) {
        // 8-bit GPR high (e.g AH)

        // convert the index to a zero based index
        reg_index -= 52;

        *operand = PIS_OPERAND_REG(reg_index * 8 + 1, PIS_OPERAND_SIZE_1);
    } else if (reg_index < 64) {
        // 8-bit GPR low of r8-r15 regs (e.g R8B)

        // convert the index to a zero based index
        reg_index -= 56;

        // use the r8-r15 regs
        reg_index += 8;

        *operand = PIS_OPERAND_REG(reg_index * 8, PIS_OPERAND_SIZE_1);
    } else if (reg_index < 68) {
        // 8-bit GPR low of sp-di regs (e.g R8B)

        // convert the index to a zero based index
        reg_index -= 64;

        // use the sp-di regs
        reg_index += 4;

        *operand = PIS_OPERAND_REG(reg_index * 8, PIS_OPERAND_SIZE_1);
    } else {
        TODO();
    }
cleanup:
    return err;
}
