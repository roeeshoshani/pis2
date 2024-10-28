#include "types.h"

typedef enum {
    /// invalid value
    OPCODE_ENCODING_INVALID,

    /// xxx r16/r32/r64
    /// opcode reg encoding
    /// default operand size is 64-bits
    OPCODE_ENCODING_R,

    /// xxx r16/r32/r64, imm16/imm32/imm64
    /// opcode reg encoding
    /// default operand size is 32-bits
    OPCODE_ENCODING_R_IMM,

    /// xxx imm16/imm32
    /// immediate is sign extended to operand size
    /// default operand size is 64-bits
    OPCODE_ENCODING_IMM,

    /// xxx imm8
    /// immediate is sign extended to operand size
    /// default operand size is 64-bits
    OPCODE_ENCODING_IMM8,

    /// xxx rax/eax/ax, r64/r32/r16
    /// opcode reg encoding
    /// default operand size is 32-bits
    OPCODE_ENCODING_AX_R,

    /// xxx rm64/rm32/rm16, r64/r32/r16
    /// default operand size is 32-bits
    OPCODE_ENCODING_RM_R,

    /// xxx r64/r32/r16, rm64/rm32/rm16
    /// default operand size is 32-bits
    OPCODE_ENCODING_R_RM,

    /// xxx r64/r32/r16, rm64/rm32/rm16, imm8
    /// immediate is sign extended to operand size
    /// default operand size is 32-bits
    OPCODE_ENCODING_R_RM_IMM8,

    /// xxx r64/r32/r16, rm64/rm32/rm16, imm32/imm32/imm16
    /// immediate is sign extended to operand size
    /// default operand size is 32-bits
    OPCODE_ENCODING_R_RM_IMM,

    /// xxx rm64/rm32/rm16
    /// default operand size is 32-bits
    OPCODE_ENCODING_RM_DEF_32,

    /// xxx rm64/rm32/rm16
    /// default operand size is 64-bits
    OPCODE_ENCODING_RM_DEF_64,

    /// xxx r64/r32/r16, rm32/rm32/r16
    /// used for zero/sign extension
    /// default operand size is 32-bits
    OPCODE_ENCODING_R_64_32_16_RM_32_32_16,

    /// xxx rm64/rm32/r16, r64/r32/r16, imm8
    /// immediate is zero extended to operand size
    /// default operand size is 32-bits
    OPCODE_ENCODING_RM_R_IMM8,

    /// xxx rm64/rm32/r16, r64/r32/r16, cl
    /// cl is zero extended to operand size
    /// default operand size is 32-bits
    OPCODE_ENCODING_RM_R_CL,

    /// xxx r64/r32/r32, rm16/rm16/r8
    /// used for zero/sign extension
    /// default operand size is 32-bits
    OPCODE_ENCODING_R_64_32_32_RM_16_16_8,

    /// xxx r64/r32/r16, rm8
    /// used for zero/sign extension
    /// default operand size is 32-bits
    OPCODE_ENCODING_R_EXT_RM8,

    /// xxx rm8, r8
    /// operand size is always 8-bits
    OPCODE_ENCODING_RM8_R8,

    /// xxx r8, rm8
    /// operand size is always 8-bits
    OPCODE_ENCODING_R8_RM8,

    /// xxx al, imm8
    /// operand size is always 8-bits
    OPCODE_ENCODING_AL_IMM8,

    /// xxx rax/eax/ax, imm32/imm32/imm16
    /// immediate is sign extended to operand size
    /// default operand size is 32-bits
    OPCODE_ENCODING_AX_IMM,

    /// xxx rm8, imm8
    /// operand size is always 8-bits
    OPCODE_ENCODING_RM8_IMM8,

    /// xxx r8, imm8
    /// operand size is always 8-bits
    OPCODE_ENCODING_R8_IMM8,

    /// xxx rm8
    /// operand size is always 8-bits
    OPCODE_ENCODING_RM8,

    /// xxx rm32/rm32/rm16
    /// default operand size is 32-bits
    OPCODE_ENCODING_RM,

    /// xxx rm64/rm32/rm16, imm32/imm32/imm16
    /// immediate is sign extended to operand size
    /// default operand size is 32-bits
    OPCODE_ENCODING_RM_IMM,

    /// xxx rm8, 1
    /// operand size is always 8-bits
    OPCODE_ENCODING_RM8_1,

    /// xxx rm64/rm32/rm16, 1
    /// default operand size is 32-bits
    OPCODE_ENCODING_RM_1,

    /// xxx rm64/rm32/rm16, cl
    /// cl is zero extended to operand size
    /// default operand size is 32-bits
    OPCODE_ENCODING_RM_CL,

    /// xxx rm64/rm32/rm16, imm8
    /// immediate is sign extended to operand size
    /// default operand size is 32-bits
    OPCODE_ENCODING_RM_IMM8_SEXT,

    /// xxx rm64/rm32/rm16, imm8
    /// immediate is zero extended to operand size
    /// default operand size is 32-bits
    OPCODE_ENCODING_RM_IMM8_ZEXT,

    /// xxx r64/r32/r16, m64/m32/m16
    /// modrm rm must be a memory operand
    /// used for LEA
    /// default operand size is 32-bits
    OPCODE_ENCODING_R_M,

    /// xxx rel32/rel32/rel16
    /// default operand size is 32-bits
    OPCODE_ENCODING_REL,

    /// xxx rel8
    /// operand size is always 8-bits
    OPCODE_ENCODING_REL8,

    /// xxx al, moffset8
    /// operand size is always 8-bits
    OPCODE_ENCODING_AL_MOFFSET8,

    /// xxx moffset8, al
    /// operand size is always 8-bits
    OPCODE_ENCODING_MOFFSET8_AL,

    /// xxx rax/eax/ax, moffset64/moffset32/moffset16
    /// default operand size is 32-bits
    OPCODE_ENCODING_AX_MOFFSET,

    /// xxx moffset64/moffset32/moffset16, rax/eax/ax
    /// default operand size is 32-bits
    OPCODE_ENCODING_MOFFSET_AX,

    /// instruction has no operands
    OPCODE_ENCODING_NO_OPERANDS,

    /// the opcode should be determined by looking at the modrm reg field
    OPCODE_ENCODING_MODRM_REG_OPCODE_EXT,
} opcode_encoding_t;

typedef enum {
    /// invalid value
    OPCODE_MNEMONIC_INVALID,

    OPCODE_MNEMONIC_ADD,
    OPCODE_MNEMONIC_ADC,
    OPCODE_MNEMONIC_AND,
    OPCODE_MNEMONIC_OR,
    OPCODE_MNEMONIC_XOR,
    OPCODE_MNEMONIC_SBB,
    OPCODE_MNEMONIC_SUB,
    OPCODE_MNEMONIC_CMP,
    OPCODE_MNEMONIC_INC,
    OPCODE_MNEMONIC_DEC,
    OPCODE_MNEMONIC_PUSH,
    OPCODE_MNEMONIC_POP,
    OPCODE_MNEMONIC_IMUL,
    OPCODE_MNEMONIC_JCC,
    OPCODE_MNEMONIC_TEST,
    OPCODE_MNEMONIC_XCHG,
    OPCODE_MNEMONIC_MOV,
    OPCODE_MNEMONIC_LEA,
    OPCODE_MNEMONIC_NOP,
    OPCODE_MNEMONIC_CBW_CWDE_CDQE,
    OPCODE_MNEMONIC_CWD_CDQ_CQO,
} opcode_mnemonic_t;

typedef struct {
    u8 mnemonic;
    u8 encoding;
} opcode_info_t;

/// most binary operators follow the same pattern in their encodings. this macro implements this
/// common pattern. the encodings span 6 different opcode bytes
#define STANDARD_BINARY_OPERATOR_INFOS(MNEMONIC)                                                   \
    {MNEMONIC, OPCODE_ENCODING_RM8_R8}, {MNEMONIC, OPCODE_ENCODING_RM_R},                          \
        {MNEMONIC, OPCODE_ENCODING_R8_RM8}, {MNEMONIC, OPCODE_ENCODING_R_RM},                      \
        {MNEMONIC, OPCODE_ENCODING_AL_IMM8}, {                                                     \
        MNEMONIC, OPCODE_ENCODING_AX_IMM                                                           \
    }

/// opcode reg instructions require 8 entires with the same values to cover all opcode values.
/// this macro is a helper for repeating that entry 8 times.
#define OPCODE_INFOS_OPCODE_REG(MNEMONIC, ENCODING)                                                \
    {MNEMONIC, ENCODING}, {MNEMONIC, ENCODING}, {MNEMONIC, ENCODING}, {MNEMONIC, ENCODING},        \
        {MNEMONIC, ENCODING}, {MNEMONIC, ENCODING}, {MNEMONIC, ENCODING}, {                        \
        MNEMONIC, ENCODING                                                                         \
    }

/// opcode condition instructions require 16 entires with the same values to cover all opcode
/// values. this macro is a helper for repeating that entry 16 times.
#define OPCODE_INFOS_COND(MNEMONIC, ENCODING)                                                      \
    {MNEMONIC, ENCODING}, {MNEMONIC, ENCODING}, {MNEMONIC, ENCODING}, {MNEMONIC, ENCODING},        \
        {MNEMONIC, ENCODING}, {MNEMONIC, ENCODING}, {MNEMONIC, ENCODING}, {MNEMONIC, ENCODING},    \
        {MNEMONIC, ENCODING}, {MNEMONIC, ENCODING}, {MNEMONIC, ENCODING}, {MNEMONIC, ENCODING},    \
        {MNEMONIC, ENCODING}, {MNEMONIC, ENCODING}, {MNEMONIC, ENCODING}, {                        \
        MNEMONIC, ENCODING                                                                         \
    }

/// an invalid opcode info structure
#define OPCODE_INFO_INVALID {OPCODE_MNEMONIC_INVALID, OPCODE_ENCODING_INVALID}

/// the opcode info for opcodes where the instruction is determined by looking at the modrm reg
/// field.
#define OPCODE_INFO_MODRM_REG_OPCODE_EXT                                                           \
    {OPCODE_MNEMONIC_INVALID, OPCODE_ENCODING_MODRM_REG_OPCODE_EXT}

const opcode_info_t first_byte_opcode_infos[256] = {
    // 0x00 - 0x05
    STANDARD_BINARY_OPERATOR_INFOS(OPCODE_MNEMONIC_ADD),
    // 0x06
    OPCODE_INFO_INVALID,
    // 0x07
    OPCODE_INFO_INVALID,
    // 0x08 - 0x0d
    STANDARD_BINARY_OPERATOR_INFOS(OPCODE_MNEMONIC_OR),
    // 0x0e
    OPCODE_INFO_INVALID,
    // 0x0f (2 byte opcode)
    OPCODE_INFO_INVALID,
    // 0x10 - 0x15
    STANDARD_BINARY_OPERATOR_INFOS(OPCODE_MNEMONIC_ADC),
    // 0x16
    OPCODE_INFO_INVALID,
    // 0x17
    OPCODE_INFO_INVALID,
    // 0x18 - 0x1d
    STANDARD_BINARY_OPERATOR_INFOS(OPCODE_MNEMONIC_SBB),
    // 0x1e
    OPCODE_INFO_INVALID,
    // 0x1f
    OPCODE_INFO_INVALID,
    // 0x20 - 0x25
    STANDARD_BINARY_OPERATOR_INFOS(OPCODE_MNEMONIC_AND),
    // 0x26
    OPCODE_INFO_INVALID,
    // 0x27
    OPCODE_INFO_INVALID,
    // 0x28 - 0x2d
    STANDARD_BINARY_OPERATOR_INFOS(OPCODE_MNEMONIC_SUB),
    // 0x2e
    OPCODE_INFO_INVALID,
    // 0x2f
    OPCODE_INFO_INVALID,
    // 0x30 - 0x35
    STANDARD_BINARY_OPERATOR_INFOS(OPCODE_MNEMONIC_XOR),
    // 0x36
    OPCODE_INFO_INVALID,
    // 0x37
    OPCODE_INFO_INVALID,
    // 0x38 - 0x3d
    STANDARD_BINARY_OPERATOR_INFOS(OPCODE_MNEMONIC_CMP),
    // 0x3e
    OPCODE_INFO_INVALID,
    // 0x3f
    OPCODE_INFO_INVALID,
    // 0x40 - 0x47
    OPCODE_INFOS_OPCODE_REG(OPCODE_MNEMONIC_INC, OPCODE_ENCODING_R),
    // 0x48 - 0x4f
    OPCODE_INFOS_OPCODE_REG(OPCODE_MNEMONIC_DEC, OPCODE_ENCODING_R),
    // 0x50 - 0x57
    OPCODE_INFOS_OPCODE_REG(OPCODE_MNEMONIC_PUSH, OPCODE_ENCODING_R),
    // 0x58 - 0x5f
    OPCODE_INFOS_OPCODE_REG(OPCODE_MNEMONIC_POP, OPCODE_ENCODING_R),
    // 0x60
    OPCODE_INFO_INVALID,
    // 0x61
    OPCODE_INFO_INVALID,
    // 0x62
    OPCODE_INFO_INVALID,
    // 0x63
    OPCODE_INFO_INVALID,
    // 0x64
    OPCODE_INFO_INVALID,
    // 0x65
    OPCODE_INFO_INVALID,
    // 0x66
    OPCODE_INFO_INVALID,
    // 0x67
    OPCODE_INFO_INVALID,
    // 0x68
    {OPCODE_MNEMONIC_PUSH, OPCODE_ENCODING_IMM},
    // 0x69
    {OPCODE_MNEMONIC_IMUL, OPCODE_ENCODING_R_RM_IMM},
    // 0x6a
    {OPCODE_MNEMONIC_PUSH, OPCODE_ENCODING_IMM8},
    // 0x6b
    {OPCODE_MNEMONIC_IMUL, OPCODE_ENCODING_R_RM_IMM8},
    // 0x6c
    OPCODE_INFO_INVALID,
    // 0x6d
    OPCODE_INFO_INVALID,
    // 0x6e
    OPCODE_INFO_INVALID,
    // 0x6f
    OPCODE_INFO_INVALID,
    // 0x70 - 0x7f
    OPCODE_INFOS_COND(OPCODE_MNEMONIC_JCC, OPCODE_ENCODING_REL8),
    // 0x80
    OPCODE_INFO_MODRM_REG_OPCODE_EXT,
    // 0x81
    OPCODE_INFO_MODRM_REG_OPCODE_EXT,
    // 0x82
    OPCODE_INFO_MODRM_REG_OPCODE_EXT,
    // 0x83
    OPCODE_INFO_MODRM_REG_OPCODE_EXT,
    // 0x84
    {OPCODE_MNEMONIC_TEST, OPCODE_ENCODING_RM8_R8},
    // 0x85
    {OPCODE_MNEMONIC_TEST, OPCODE_ENCODING_RM_R},
    // 0x86
    {OPCODE_MNEMONIC_XCHG, OPCODE_ENCODING_R8_RM8},
    // 0x87
    {OPCODE_MNEMONIC_XCHG, OPCODE_ENCODING_R_RM},
    // 0x88
    {OPCODE_MNEMONIC_MOV, OPCODE_ENCODING_RM8_R8},
    // 0x89
    {OPCODE_MNEMONIC_MOV, OPCODE_ENCODING_RM_R},
    // 0x8a
    {OPCODE_MNEMONIC_MOV, OPCODE_ENCODING_R8_RM8},
    // 0x8b
    {OPCODE_MNEMONIC_MOV, OPCODE_ENCODING_R_RM},
    // 0x8c
    OPCODE_INFO_INVALID,
    // 0x8d
    {OPCODE_MNEMONIC_LEA, OPCODE_ENCODING_R_M},
    // 0x8e
    OPCODE_INFO_INVALID,
    // 0x8f
    OPCODE_INFO_MODRM_REG_OPCODE_EXT,
    // 0x90 - 0x97
    OPCODE_INFOS_OPCODE_REG(OPCODE_MNEMONIC_XCHG, OPCODE_ENCODING_R),
    // 0x98
    {OPCODE_MNEMONIC_CBW_CWDE_CDQE, OPCODE_ENCODING_NO_OPERANDS},
    // 0x99
    {OPCODE_MNEMONIC_CWD_CDQ_CQO, OPCODE_ENCODING_NO_OPERANDS},
    // 0x9a
    OPCODE_INFO_INVALID,
    // 0x9b
    OPCODE_INFO_INVALID,
    // 0x9c
    OPCODE_INFO_INVALID,
    // 0x9d
    OPCODE_INFO_INVALID,
    // 0x9e
    OPCODE_INFO_INVALID,
    // 0x9f
    OPCODE_INFO_INVALID,
    // 0xa0
    {OPCODE_MNEMONIC_MOV, OPCODE_ENCODING_AL_MOFFSET8},
    // 0xa1
    {OPCODE_MNEMONIC_MOV, OPCODE_ENCODING_AX_MOFFSET},
    // 0xa2
    {OPCODE_MNEMONIC_MOV, OPCODE_ENCODING_MOFFSET8_AL},
    // 0xa3
    {OPCODE_MNEMONIC_MOV, OPCODE_ENCODING_MOFFSET_AX},
};
