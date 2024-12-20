#pragma once
#include <stdint.h>
#define X86_TABLES_INSN_MAX_OPS 3
typedef enum {
    MNEMONIC_ADD,
    MNEMONIC_UNSUPPORTED,
    MNEMONIC_OR,
    MNEMONIC_ADC,
    MNEMONIC_SBB,
    MNEMONIC_AND,
    MNEMONIC_SUB,
    MNEMONIC_XOR,
    MNEMONIC_CMP,
    MNEMONIC_INC,
    MNEMONIC_DEC,
    MNEMONIC_PUSH,
    MNEMONIC_POP,
    MNEMONIC_MOVSXD,
    MNEMONIC_IMUL,
    MNEMONIC_JCC,
    MNEMONIC_TEST,
    MNEMONIC_XCHG,
    MNEMONIC_MOV,
    MNEMONIC_LEA,
    MNEMONIC_NOP,
    MNEMONIC_MOVSX,
    MNEMONIC_CWD,
    MNEMONIC_MOVS,
    MNEMONIC_CMPS,
    MNEMONIC_STOS,
    MNEMONIC_LODS,
    MNEMONIC_SCAS,
    MNEMONIC_ROL,
    MNEMONIC_ROR,
    MNEMONIC_RCL,
    MNEMONIC_RCR,
    MNEMONIC_SHL,
    MNEMONIC_SHR,
    MNEMONIC_SAR,
    MNEMONIC_RET,
    MNEMONIC_CALL,
    MNEMONIC_JMP,
    MNEMONIC_HLT,
    MNEMONIC_CMC,
    MNEMONIC_NOT,
    MNEMONIC_NEG,
    MNEMONIC_MUL,
    MNEMONIC_DIV,
    MNEMONIC_IDIV,
    MNEMONIC_CLC,
    MNEMONIC_STC,
    MNEMONIC_CLI,
    MNEMONIC_STI,
    MNEMONIC_CLD,
    MNEMONIC_STD,
    MNEMONIC_ENDBR,
    MNEMONIC_CMOVCC,
    MNEMONIC_SETCC,
    MNEMONIC_BT,
    MNEMONIC_SHLD,
    MNEMONIC_SHRD,
    MNEMONIC_MOVZX,
    MNEMONIC_MODRM_REG_OPCODE_EXT,
    MNEMONIC_MAX = MNEMONIC_MODRM_REG_OPCODE_EXT,
} mnemonic_t;
typedef struct __attribute__((packed)) {
    uint8_t mnemonic : 6;
    uint8_t first_op_index : 7;
    uint8_t ops_amount : 2;
} regular_insn_info_t;
typedef union __attribute__((packed)) {
    uint8_t mnemonic : 6;
    regular_insn_info_t regular;
    struct __attribute__((packed)) {
        uint8_t mnemonic : 6;
        uint8_t modrm_reg_table_index : 5;
    } modrm_reg_opcode_ext;
} insn_info_t;
typedef enum {
    OP_SIZE_8,
    OP_SIZE_16,
    OP_SIZE_32,
    OP_SIZE_64,
    OP_SIZE_MAX = OP_SIZE_64,
} op_size_t;
typedef struct __attribute__((packed)) {
    uint8_t with_operand_size_override : 2;
    uint8_t mode_32 : 2;
    uint8_t mode_64 : 2;
    uint8_t mode_64_with_rex_w : 2;
} op_size_info_t;
typedef enum {
    OP_KIND_IMM,
    OP_KIND_SPECIFIC_IMM,
    OP_KIND_REG,
    OP_KIND_RM,
    OP_KIND_SPECIFIC_REG,
    OP_KIND_ZEXT_SPECIFIC_REG,
    OP_KIND_REL,
    OP_KIND_MEM_OFFSET,
    OP_KIND_IMPLICIT,
    OP_KIND_COND,
    OP_KIND_MAX = OP_KIND_COND,
} op_kind_t;
typedef enum {
    REG_ENC_MODRM,
    REG_ENC_OPCODE,
    REG_ENC_MAX = REG_ENC_OPCODE,
} reg_encoding_t;
typedef enum {
    SPECIFIC_REG_RAX,
    SPECIFIC_REG_RDX,
    SPECIFIC_REG_RCX,
    SPECIFIC_REG_MAX = SPECIFIC_REG_RCX,
} specific_reg_t;
typedef enum {
    SPECIFIC_IMM_ZERO,
    SPECIFIC_IMM_ONE,
    SPECIFIC_IMM_MAX = SPECIFIC_IMM_ONE,
} specific_imm_t;
typedef union __attribute__((packed)) {
    uint8_t kind : 4;
    struct __attribute__((packed)) {
        uint8_t kind : 4;
        uint8_t encoded_size_info_index : 3;
        uint8_t extended_size_info_index : 3;
        uint8_t extend_kind : 1;
    } imm;
    struct __attribute__((packed)) {
        uint8_t kind : 4;
        uint8_t operand_size_info_index : 3;
        uint8_t value : 1;
    } specific_imm;
    struct __attribute__((packed)) {
        uint8_t kind : 4;
        uint8_t size_info_index : 3;
        uint8_t encoding : 1;
    } reg;
    struct __attribute__((packed)) {
        uint8_t kind : 4;
        uint8_t size_info_index : 3;
    } rm;
    struct __attribute__((packed)) {
        uint8_t kind : 4;
        uint8_t size_info_index : 3;
        uint8_t reg : 2;
    } specific_reg;
    struct __attribute__((packed)) {
        uint8_t kind : 4;
        uint8_t size_info_index : 3;
        uint8_t extended_size_info_index : 3;
        uint8_t reg : 2;
    } zext_specific_reg;
    struct __attribute__((packed)) {
        uint8_t kind : 4;
        uint8_t size_info_index : 3;
    } rel;
    struct __attribute__((packed)) {
        uint8_t kind : 4;
        uint8_t mem_operand_size_info_index : 3;
    } mem_offset;
    struct __attribute__((packed)) {
        uint8_t kind : 4;
        uint8_t size_info_index : 3;
    } implicit;
    struct __attribute__((packed)) {
        uint8_t kind : 4;
    } cond;
} op_info_t;
typedef struct __attribute__((packed)) {
    regular_insn_info_t by_reg_value[8];
} modrm_reg_opcode_ext_table_t;
