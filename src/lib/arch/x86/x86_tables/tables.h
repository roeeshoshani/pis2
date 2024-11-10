const op_size_info_t op_size_infos_table[] = {
    {
        .with_operand_size_override = OP_SIZE_8,
        .mode_32 = OP_SIZE_8,
        .mode_64 = OP_SIZE_8,
        .mode_64_with_rex_w = OP_SIZE_8,
    },
    {
        .with_operand_size_override = OP_SIZE_16,
        .mode_32 = OP_SIZE_32,
        .mode_64 = OP_SIZE_32,
        .mode_64_with_rex_w = OP_SIZE_64,
    },
    {
        .with_operand_size_override = OP_SIZE_16,
        .mode_32 = OP_SIZE_32,
        .mode_64 = OP_SIZE_32,
        .mode_64_with_rex_w = OP_SIZE_32,
    },
    {
        .with_operand_size_override = OP_SIZE_16,
        .mode_32 = OP_SIZE_32,
        .mode_64 = OP_SIZE_64,
        .mode_64_with_rex_w = OP_SIZE_64,
    },
    {
        .with_operand_size_override = OP_SIZE_8,
        .mode_32 = OP_SIZE_16,
        .mode_64 = OP_SIZE_16,
        .mode_64_with_rex_w = OP_SIZE_32,
    },
    {
        .with_operand_size_override = OP_SIZE_16,
        .mode_32 = OP_SIZE_16,
        .mode_64 = OP_SIZE_16,
        .mode_64_with_rex_w = OP_SIZE_16,
    },
};
const op_info_t op_infos_table[] = {
    {
        .rm =
            {
                .kind = OP_KIND_RM,
                .size_info_index = 0,
            },
    },
    {
        .reg =
            {
                .kind = OP_KIND_REG,
                .size_info_index = 0,
                .encoding = REG_ENC_MODRM,
            },
    },
    {
        .rm =
            {
                .kind = OP_KIND_RM,
                .size_info_index = 1,
            },
    },
    {
        .reg =
            {
                .kind = OP_KIND_REG,
                .size_info_index = 1,
                .encoding = REG_ENC_MODRM,
            },
    },
    {
        .specific_reg =
            {
                .kind = OP_KIND_SPECIFIC_REG,
                .size_info_index = 0,
                .reg = SPECIFIC_REG_RAX,
            },
    },
    {
        .imm =
            {
                .kind = OP_KIND_IMM,
                .encoded_size_info_index = 0,
                .extended_size_info_index = 0,
                .extend_kind = IMM_EXT_SIGN_EXTEND,
            },
    },
    {
        .specific_reg =
            {
                .kind = OP_KIND_SPECIFIC_REG,
                .size_info_index = 1,
                .reg = SPECIFIC_REG_RAX,
            },
    },
    {
        .imm =
            {
                .kind = OP_KIND_IMM,
                .encoded_size_info_index = 2,
                .extended_size_info_index = 1,
                .extend_kind = IMM_EXT_SIGN_EXTEND,
            },
    },
    {
        .reg =
            {
                .kind = OP_KIND_REG,
                .size_info_index = 1,
                .encoding = REG_ENC_OPCODE,
            },
    },
    {
        .reg =
            {
                .kind = OP_KIND_REG,
                .size_info_index = 3,
                .encoding = REG_ENC_OPCODE,
            },
    },
    {
        .rm =
            {
                .kind = OP_KIND_RM,
                .size_info_index = 2,
            },
    },
    {
        .imm =
            {
                .kind = OP_KIND_IMM,
                .encoded_size_info_index = 2,
                .extended_size_info_index = 3,
                .extend_kind = IMM_EXT_SIGN_EXTEND,
            },
    },
    {
        .imm =
            {
                .kind = OP_KIND_IMM,
                .encoded_size_info_index = 0,
                .extended_size_info_index = 3,
                .extend_kind = IMM_EXT_SIGN_EXTEND,
            },
    },
    {
        .imm =
            {
                .kind = OP_KIND_IMM,
                .encoded_size_info_index = 0,
                .extended_size_info_index = 1,
                .extend_kind = IMM_EXT_SIGN_EXTEND,
            },
    },
    {
        .cond =
            {
                .kind = OP_KIND_COND,
            },
    },
    {
        .rel =
            {
                .kind = OP_KIND_REL,
                .size_info_index = 0,
            },
    },
    {
        .rm =
            {
                .kind = OP_KIND_RM,
                .size_info_index = 3,
            },
    },
    {
        .specific_reg =
            {
                .kind = OP_KIND_SPECIFIC_REG,
                .size_info_index = 4,
                .reg = SPECIFIC_REG_RAX,
            },
    },
    {
        .specific_reg =
            {
                .kind = OP_KIND_SPECIFIC_REG,
                .size_info_index = 1,
                .reg = SPECIFIC_REG_RDX,
            },
    },
    {
        .mem_offset =
            {
                .kind = OP_KIND_MEM_OFFSET,
                .mem_operand_size_info_index = 0,
            },
    },
    {
        .mem_offset =
            {
                .kind = OP_KIND_MEM_OFFSET,
                .mem_operand_size_info_index = 1,
            },
    },
    {
        .implicit =
            {
                .kind = OP_KIND_IMPLICIT,
                .size_info_index = 0,
            },
    },
    {
        .implicit =
            {
                .kind = OP_KIND_IMPLICIT,
                .size_info_index = 1,
            },
    },
    {
        .reg =
            {
                .kind = OP_KIND_REG,
                .size_info_index = 0,
                .encoding = REG_ENC_OPCODE,
            },
    },
    {
        .imm =
            {
                .kind = OP_KIND_IMM,
                .encoded_size_info_index = 1,
                .extended_size_info_index = 1,
                .extend_kind = IMM_EXT_ZERO_EXTEND,
            },
    },
    {
        .imm =
            {
                .kind = OP_KIND_IMM,
                .encoded_size_info_index = 0,
                .extended_size_info_index = 1,
                .extend_kind = IMM_EXT_ZERO_EXTEND,
            },
    },
    {
        .specific_imm =
            {
                .kind = OP_KIND_SPECIFIC_IMM,
                .operand_size_info_index = 0,
                .value = SPECIFIC_IMM_ONE,
            },
    },
    {
        .specific_imm =
            {
                .kind = OP_KIND_SPECIFIC_IMM,
                .operand_size_info_index = 1,
                .value = SPECIFIC_IMM_ONE,
            },
    },
    {
        .specific_reg =
            {
                .kind = OP_KIND_SPECIFIC_REG,
                .size_info_index = 0,
                .reg = SPECIFIC_REG_RCX,
            },
    },
    {
        .zext_specific_reg =
            {
                .kind = OP_KIND_ZEXT_SPECIFIC_REG,
                .size_info_index = 0,
                .extended_size_info_index = 1,
                .reg = SPECIFIC_REG_RCX,
            },
    },
    {
        .rel =
            {
                .kind = OP_KIND_REL,
                .size_info_index = 2,
            },
    },
    {
        .rm =
            {
                .kind = OP_KIND_RM,
                .size_info_index = 5,
            },
    },
};
const uint8_t laid_out_ops_infos_table[] = {
    0, 1,  2,  3,  1,  0,  3,  2,  4,  5,  6,  7,  8,  9, 3,  10, 11, 3, 2,  7,  12, 3,
    2, 13, 14, 15, 0,  5,  2,  7,  2,  13, 16, 6,  8,  6, 17, 18, 6,  4, 19, 6,  20, 19,
    4, 20, 6,  21, 22, 23, 5,  8,  24, 2,  25, 0,  26, 2, 27, 0,  28, 2, 29, 30, 15, 0,
    2, 10, 14, 3,  2,  14, 30, 14, 0,  2,  3,  25, 2,  3, 29, 3,  0,  3, 31,
};
const modrm_reg_opcode_ext_table_t modrm_reg_opcode_ext_tables[] = {
    {
        .by_reg_value =
            {
                {
                    .mnemonic = MNEMONIC_ADD,
                    .first_op_index = 26,
                    .ops_amount = 2,
                },
                {
                    .mnemonic = MNEMONIC_OR,
                    .first_op_index = 26,
                    .ops_amount = 2,
                },
                {
                    .mnemonic = MNEMONIC_ADC,
                    .first_op_index = 26,
                    .ops_amount = 2,
                },
                {
                    .mnemonic = MNEMONIC_SBB,
                    .first_op_index = 26,
                    .ops_amount = 2,
                },
                {
                    .mnemonic = MNEMONIC_AND,
                    .first_op_index = 26,
                    .ops_amount = 2,
                },
                {
                    .mnemonic = MNEMONIC_SUB,
                    .first_op_index = 26,
                    .ops_amount = 2,
                },
                {
                    .mnemonic = MNEMONIC_XOR,
                    .first_op_index = 26,
                    .ops_amount = 2,
                },
                {
                    .mnemonic = MNEMONIC_CMP,
                    .first_op_index = 26,
                    .ops_amount = 2,
                },
            },
    },
    {
        .by_reg_value =
            {
                {
                    .mnemonic = MNEMONIC_ADD,
                    .first_op_index = 28,
                    .ops_amount = 2,
                },
                {
                    .mnemonic = MNEMONIC_OR,
                    .first_op_index = 28,
                    .ops_amount = 2,
                },
                {
                    .mnemonic = MNEMONIC_ADC,
                    .first_op_index = 28,
                    .ops_amount = 2,
                },
                {
                    .mnemonic = MNEMONIC_SBB,
                    .first_op_index = 28,
                    .ops_amount = 2,
                },
                {
                    .mnemonic = MNEMONIC_AND,
                    .first_op_index = 28,
                    .ops_amount = 2,
                },
                {
                    .mnemonic = MNEMONIC_SUB,
                    .first_op_index = 28,
                    .ops_amount = 2,
                },
                {
                    .mnemonic = MNEMONIC_XOR,
                    .first_op_index = 28,
                    .ops_amount = 2,
                },
                {
                    .mnemonic = MNEMONIC_CMP,
                    .first_op_index = 28,
                    .ops_amount = 2,
                },
            },
    },
    {
        .by_reg_value =
            {
                {
                    .mnemonic = MNEMONIC_ADD,
                    .first_op_index = 30,
                    .ops_amount = 2,
                },
                {
                    .mnemonic = MNEMONIC_OR,
                    .first_op_index = 30,
                    .ops_amount = 2,
                },
                {
                    .mnemonic = MNEMONIC_ADC,
                    .first_op_index = 30,
                    .ops_amount = 2,
                },
                {
                    .mnemonic = MNEMONIC_SBB,
                    .first_op_index = 30,
                    .ops_amount = 2,
                },
                {
                    .mnemonic = MNEMONIC_AND,
                    .first_op_index = 30,
                    .ops_amount = 2,
                },
                {
                    .mnemonic = MNEMONIC_SUB,
                    .first_op_index = 30,
                    .ops_amount = 2,
                },
                {
                    .mnemonic = MNEMONIC_XOR,
                    .first_op_index = 30,
                    .ops_amount = 2,
                },
                {
                    .mnemonic = MNEMONIC_CMP,
                    .first_op_index = 30,
                    .ops_amount = 2,
                },
            },
    },
    {
        .by_reg_value =
            {
                {
                    .mnemonic = MNEMONIC_POP,
                    .first_op_index = 32,
                    .ops_amount = 1,
                },
                {
                    .mnemonic = MNEMONIC_UNSUPPORTED,
                    .first_op_index = 12,
                    .ops_amount = 0,
                },
                {
                    .mnemonic = MNEMONIC_UNSUPPORTED,
                    .first_op_index = 12,
                    .ops_amount = 0,
                },
                {
                    .mnemonic = MNEMONIC_UNSUPPORTED,
                    .first_op_index = 12,
                    .ops_amount = 0,
                },
                {
                    .mnemonic = MNEMONIC_UNSUPPORTED,
                    .first_op_index = 12,
                    .ops_amount = 0,
                },
                {
                    .mnemonic = MNEMONIC_UNSUPPORTED,
                    .first_op_index = 12,
                    .ops_amount = 0,
                },
                {
                    .mnemonic = MNEMONIC_UNSUPPORTED,
                    .first_op_index = 12,
                    .ops_amount = 0,
                },
                {
                    .mnemonic = MNEMONIC_UNSUPPORTED,
                    .first_op_index = 12,
                    .ops_amount = 0,
                },
            },
    },
    {
        .by_reg_value =
            {
                {
                    .mnemonic = MNEMONIC_ROL,
                    .first_op_index = 26,
                    .ops_amount = 2,
                },
                {
                    .mnemonic = MNEMONIC_ROR,
                    .first_op_index = 26,
                    .ops_amount = 2,
                },
                {
                    .mnemonic = MNEMONIC_RCL,
                    .first_op_index = 26,
                    .ops_amount = 2,
                },
                {
                    .mnemonic = MNEMONIC_RCR,
                    .first_op_index = 26,
                    .ops_amount = 2,
                },
                {
                    .mnemonic = MNEMONIC_SHL,
                    .first_op_index = 26,
                    .ops_amount = 2,
                },
                {
                    .mnemonic = MNEMONIC_SHR,
                    .first_op_index = 26,
                    .ops_amount = 2,
                },
                {
                    .mnemonic = MNEMONIC_UNSUPPORTED,
                    .first_op_index = 26,
                    .ops_amount = 2,
                },
                {
                    .mnemonic = MNEMONIC_SAR,
                    .first_op_index = 26,
                    .ops_amount = 2,
                },
            },
    },
    {
        .by_reg_value =
            {
                {
                    .mnemonic = MNEMONIC_ROL,
                    .first_op_index = 53,
                    .ops_amount = 2,
                },
                {
                    .mnemonic = MNEMONIC_ROR,
                    .first_op_index = 53,
                    .ops_amount = 2,
                },
                {
                    .mnemonic = MNEMONIC_RCL,
                    .first_op_index = 53,
                    .ops_amount = 2,
                },
                {
                    .mnemonic = MNEMONIC_RCR,
                    .first_op_index = 53,
                    .ops_amount = 2,
                },
                {
                    .mnemonic = MNEMONIC_SHL,
                    .first_op_index = 53,
                    .ops_amount = 2,
                },
                {
                    .mnemonic = MNEMONIC_SHR,
                    .first_op_index = 53,
                    .ops_amount = 2,
                },
                {
                    .mnemonic = MNEMONIC_UNSUPPORTED,
                    .first_op_index = 53,
                    .ops_amount = 2,
                },
                {
                    .mnemonic = MNEMONIC_SAR,
                    .first_op_index = 53,
                    .ops_amount = 2,
                },
            },
    },
    {
        .by_reg_value =
            {
                {
                    .mnemonic = MNEMONIC_MOV,
                    .first_op_index = 26,
                    .ops_amount = 2,
                },
                {
                    .mnemonic = MNEMONIC_UNSUPPORTED,
                    .first_op_index = 12,
                    .ops_amount = 0,
                },
                {
                    .mnemonic = MNEMONIC_UNSUPPORTED,
                    .first_op_index = 12,
                    .ops_amount = 0,
                },
                {
                    .mnemonic = MNEMONIC_UNSUPPORTED,
                    .first_op_index = 12,
                    .ops_amount = 0,
                },
                {
                    .mnemonic = MNEMONIC_UNSUPPORTED,
                    .first_op_index = 12,
                    .ops_amount = 0,
                },
                {
                    .mnemonic = MNEMONIC_UNSUPPORTED,
                    .first_op_index = 12,
                    .ops_amount = 0,
                },
                {
                    .mnemonic = MNEMONIC_UNSUPPORTED,
                    .first_op_index = 12,
                    .ops_amount = 0,
                },
                {
                    .mnemonic = MNEMONIC_UNSUPPORTED,
                    .first_op_index = 12,
                    .ops_amount = 0,
                },
            },
    },
    {
        .by_reg_value =
            {
                {
                    .mnemonic = MNEMONIC_MOV,
                    .first_op_index = 28,
                    .ops_amount = 2,
                },
                {
                    .mnemonic = MNEMONIC_UNSUPPORTED,
                    .first_op_index = 12,
                    .ops_amount = 0,
                },
                {
                    .mnemonic = MNEMONIC_UNSUPPORTED,
                    .first_op_index = 12,
                    .ops_amount = 0,
                },
                {
                    .mnemonic = MNEMONIC_UNSUPPORTED,
                    .first_op_index = 12,
                    .ops_amount = 0,
                },
                {
                    .mnemonic = MNEMONIC_UNSUPPORTED,
                    .first_op_index = 12,
                    .ops_amount = 0,
                },
                {
                    .mnemonic = MNEMONIC_UNSUPPORTED,
                    .first_op_index = 12,
                    .ops_amount = 0,
                },
                {
                    .mnemonic = MNEMONIC_UNSUPPORTED,
                    .first_op_index = 12,
                    .ops_amount = 0,
                },
                {
                    .mnemonic = MNEMONIC_UNSUPPORTED,
                    .first_op_index = 12,
                    .ops_amount = 0,
                },
            },
    },
    {
        .by_reg_value =
            {
                {
                    .mnemonic = MNEMONIC_ROL,
                    .first_op_index = 55,
                    .ops_amount = 2,
                },
                {
                    .mnemonic = MNEMONIC_ROR,
                    .first_op_index = 55,
                    .ops_amount = 2,
                },
                {
                    .mnemonic = MNEMONIC_RCL,
                    .first_op_index = 55,
                    .ops_amount = 2,
                },
                {
                    .mnemonic = MNEMONIC_RCR,
                    .first_op_index = 55,
                    .ops_amount = 2,
                },
                {
                    .mnemonic = MNEMONIC_SHL,
                    .first_op_index = 55,
                    .ops_amount = 2,
                },
                {
                    .mnemonic = MNEMONIC_SHR,
                    .first_op_index = 55,
                    .ops_amount = 2,
                },
                {
                    .mnemonic = MNEMONIC_UNSUPPORTED,
                    .first_op_index = 55,
                    .ops_amount = 2,
                },
                {
                    .mnemonic = MNEMONIC_SAR,
                    .first_op_index = 55,
                    .ops_amount = 2,
                },
            },
    },
    {
        .by_reg_value =
            {
                {
                    .mnemonic = MNEMONIC_ROL,
                    .first_op_index = 57,
                    .ops_amount = 2,
                },
                {
                    .mnemonic = MNEMONIC_ROR,
                    .first_op_index = 57,
                    .ops_amount = 2,
                },
                {
                    .mnemonic = MNEMONIC_RCL,
                    .first_op_index = 57,
                    .ops_amount = 2,
                },
                {
                    .mnemonic = MNEMONIC_RCR,
                    .first_op_index = 57,
                    .ops_amount = 2,
                },
                {
                    .mnemonic = MNEMONIC_SHL,
                    .first_op_index = 57,
                    .ops_amount = 2,
                },
                {
                    .mnemonic = MNEMONIC_SHR,
                    .first_op_index = 57,
                    .ops_amount = 2,
                },
                {
                    .mnemonic = MNEMONIC_UNSUPPORTED,
                    .first_op_index = 57,
                    .ops_amount = 2,
                },
                {
                    .mnemonic = MNEMONIC_SAR,
                    .first_op_index = 57,
                    .ops_amount = 2,
                },
            },
    },
    {
        .by_reg_value =
            {
                {
                    .mnemonic = MNEMONIC_ROL,
                    .first_op_index = 59,
                    .ops_amount = 2,
                },
                {
                    .mnemonic = MNEMONIC_ROR,
                    .first_op_index = 59,
                    .ops_amount = 2,
                },
                {
                    .mnemonic = MNEMONIC_RCL,
                    .first_op_index = 59,
                    .ops_amount = 2,
                },
                {
                    .mnemonic = MNEMONIC_RCR,
                    .first_op_index = 59,
                    .ops_amount = 2,
                },
                {
                    .mnemonic = MNEMONIC_SHL,
                    .first_op_index = 59,
                    .ops_amount = 2,
                },
                {
                    .mnemonic = MNEMONIC_SHR,
                    .first_op_index = 59,
                    .ops_amount = 2,
                },
                {
                    .mnemonic = MNEMONIC_UNSUPPORTED,
                    .first_op_index = 59,
                    .ops_amount = 2,
                },
                {
                    .mnemonic = MNEMONIC_SAR,
                    .first_op_index = 59,
                    .ops_amount = 2,
                },
            },
    },
    {
        .by_reg_value =
            {
                {
                    .mnemonic = MNEMONIC_ROL,
                    .first_op_index = 61,
                    .ops_amount = 2,
                },
                {
                    .mnemonic = MNEMONIC_ROR,
                    .first_op_index = 61,
                    .ops_amount = 2,
                },
                {
                    .mnemonic = MNEMONIC_RCL,
                    .first_op_index = 61,
                    .ops_amount = 2,
                },
                {
                    .mnemonic = MNEMONIC_RCR,
                    .first_op_index = 61,
                    .ops_amount = 2,
                },
                {
                    .mnemonic = MNEMONIC_SHL,
                    .first_op_index = 61,
                    .ops_amount = 2,
                },
                {
                    .mnemonic = MNEMONIC_SHR,
                    .first_op_index = 61,
                    .ops_amount = 2,
                },
                {
                    .mnemonic = MNEMONIC_UNSUPPORTED,
                    .first_op_index = 61,
                    .ops_amount = 2,
                },
                {
                    .mnemonic = MNEMONIC_SAR,
                    .first_op_index = 61,
                    .ops_amount = 2,
                },
            },
    },
    {
        .by_reg_value =
            {
                {
                    .mnemonic = MNEMONIC_TEST,
                    .first_op_index = 26,
                    .ops_amount = 2,
                },
                {
                    .mnemonic = MNEMONIC_UNSUPPORTED,
                    .first_op_index = 12,
                    .ops_amount = 0,
                },
                {
                    .mnemonic = MNEMONIC_NOT,
                    .first_op_index = 65,
                    .ops_amount = 1,
                },
                {
                    .mnemonic = MNEMONIC_NEG,
                    .first_op_index = 65,
                    .ops_amount = 1,
                },
                {
                    .mnemonic = MNEMONIC_MUL,
                    .first_op_index = 65,
                    .ops_amount = 1,
                },
                {
                    .mnemonic = MNEMONIC_IMUL,
                    .first_op_index = 65,
                    .ops_amount = 1,
                },
                {
                    .mnemonic = MNEMONIC_DIV,
                    .first_op_index = 65,
                    .ops_amount = 1,
                },
                {
                    .mnemonic = MNEMONIC_IDIV,
                    .first_op_index = 65,
                    .ops_amount = 1,
                },
            },
    },
    {
        .by_reg_value =
            {
                {
                    .mnemonic = MNEMONIC_TEST,
                    .first_op_index = 28,
                    .ops_amount = 2,
                },
                {
                    .mnemonic = MNEMONIC_UNSUPPORTED,
                    .first_op_index = 12,
                    .ops_amount = 0,
                },
                {
                    .mnemonic = MNEMONIC_NOT,
                    .first_op_index = 66,
                    .ops_amount = 1,
                },
                {
                    .mnemonic = MNEMONIC_NEG,
                    .first_op_index = 66,
                    .ops_amount = 1,
                },
                {
                    .mnemonic = MNEMONIC_MUL,
                    .first_op_index = 66,
                    .ops_amount = 1,
                },
                {
                    .mnemonic = MNEMONIC_IMUL,
                    .first_op_index = 66,
                    .ops_amount = 1,
                },
                {
                    .mnemonic = MNEMONIC_DIV,
                    .first_op_index = 66,
                    .ops_amount = 1,
                },
                {
                    .mnemonic = MNEMONIC_IDIV,
                    .first_op_index = 66,
                    .ops_amount = 1,
                },
            },
    },
    {
        .by_reg_value =
            {
                {
                    .mnemonic = MNEMONIC_INC,
                    .first_op_index = 65,
                    .ops_amount = 1,
                },
                {
                    .mnemonic = MNEMONIC_DEC,
                    .first_op_index = 65,
                    .ops_amount = 1,
                },
                {
                    .mnemonic = MNEMONIC_UNSUPPORTED,
                    .first_op_index = 12,
                    .ops_amount = 0,
                },
                {
                    .mnemonic = MNEMONIC_UNSUPPORTED,
                    .first_op_index = 12,
                    .ops_amount = 0,
                },
                {
                    .mnemonic = MNEMONIC_UNSUPPORTED,
                    .first_op_index = 12,
                    .ops_amount = 0,
                },
                {
                    .mnemonic = MNEMONIC_UNSUPPORTED,
                    .first_op_index = 12,
                    .ops_amount = 0,
                },
                {
                    .mnemonic = MNEMONIC_UNSUPPORTED,
                    .first_op_index = 12,
                    .ops_amount = 0,
                },
                {
                    .mnemonic = MNEMONIC_UNSUPPORTED,
                    .first_op_index = 12,
                    .ops_amount = 0,
                },
            },
    },
    {
        .by_reg_value =
            {
                {
                    .mnemonic = MNEMONIC_INC,
                    .first_op_index = 66,
                    .ops_amount = 1,
                },
                {
                    .mnemonic = MNEMONIC_DEC,
                    .first_op_index = 66,
                    .ops_amount = 1,
                },
                {
                    .mnemonic = MNEMONIC_CALL,
                    .first_op_index = 32,
                    .ops_amount = 1,
                },
                {
                    .mnemonic = MNEMONIC_UNSUPPORTED,
                    .first_op_index = 12,
                    .ops_amount = 0,
                },
                {
                    .mnemonic = MNEMONIC_JMP,
                    .first_op_index = 32,
                    .ops_amount = 1,
                },
                {
                    .mnemonic = MNEMONIC_UNSUPPORTED,
                    .first_op_index = 12,
                    .ops_amount = 0,
                },
                {
                    .mnemonic = MNEMONIC_PUSH,
                    .first_op_index = 32,
                    .ops_amount = 1,
                },
                {
                    .mnemonic = MNEMONIC_UNSUPPORTED,
                    .first_op_index = 12,
                    .ops_amount = 0,
                },
            },
    },
    {
        .by_reg_value =
            {
                {
                    .mnemonic = MNEMONIC_UNSUPPORTED,
                    .first_op_index = 12,
                    .ops_amount = 0,
                },
                {
                    .mnemonic = MNEMONIC_UNSUPPORTED,
                    .first_op_index = 12,
                    .ops_amount = 0,
                },
                {
                    .mnemonic = MNEMONIC_UNSUPPORTED,
                    .first_op_index = 12,
                    .ops_amount = 0,
                },
                {
                    .mnemonic = MNEMONIC_UNSUPPORTED,
                    .first_op_index = 12,
                    .ops_amount = 0,
                },
                {
                    .mnemonic = MNEMONIC_UNSUPPORTED,
                    .first_op_index = 12,
                    .ops_amount = 0,
                },
                {
                    .mnemonic = MNEMONIC_UNSUPPORTED,
                    .first_op_index = 12,
                    .ops_amount = 0,
                },
                {
                    .mnemonic = MNEMONIC_UNSUPPORTED,
                    .first_op_index = 12,
                    .ops_amount = 0,
                },
                {
                    .mnemonic = MNEMONIC_ENDBR,
                    .first_op_index = 12,
                    .ops_amount = 0,
                },
            },
    },
};
const insn_info_t
    first_opcode_byte_table[] =
        {
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_ADD,
                        .first_op_index = 0,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_ADD,
                        .first_op_index = 2,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_ADD,
                        .first_op_index = 4,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_ADD,
                        .first_op_index = 6,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_ADD,
                        .first_op_index = 8,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_ADD,
                        .first_op_index = 10,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_OR,
                        .first_op_index = 0,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_OR,
                        .first_op_index = 2,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_OR,
                        .first_op_index = 4,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_OR,
                        .first_op_index = 6,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_OR,
                        .first_op_index = 8,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_OR,
                        .first_op_index = 10,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_ADC,
                        .first_op_index = 0,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_ADC,
                        .first_op_index = 2,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_ADC,
                        .first_op_index = 4,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_ADC,
                        .first_op_index = 6,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_ADC,
                        .first_op_index = 8,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_ADC,
                        .first_op_index = 10,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_SBB,
                        .first_op_index = 0,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_SBB,
                        .first_op_index = 2,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_SBB,
                        .first_op_index = 4,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_SBB,
                        .first_op_index = 6,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_SBB,
                        .first_op_index = 8,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_SBB,
                        .first_op_index = 10,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_AND,
                        .first_op_index = 0,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_AND,
                        .first_op_index = 2,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_AND,
                        .first_op_index = 4,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_AND,
                        .first_op_index = 6,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_AND,
                        .first_op_index = 8,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_AND,
                        .first_op_index = 10,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_SUB,
                        .first_op_index = 0,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_SUB,
                        .first_op_index = 2,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_SUB,
                        .first_op_index = 4,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_SUB,
                        .first_op_index = 6,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_SUB,
                        .first_op_index = 8,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_SUB,
                        .first_op_index = 10,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_XOR,
                        .first_op_index = 0,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_XOR,
                        .first_op_index = 2,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_XOR,
                        .first_op_index = 4,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_XOR,
                        .first_op_index = 6,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_XOR,
                        .first_op_index = 8,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_XOR,
                        .first_op_index = 10,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_CMP,
                        .first_op_index = 0,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_CMP,
                        .first_op_index = 2,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_CMP,
                        .first_op_index = 4,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_CMP,
                        .first_op_index = 6,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_CMP,
                        .first_op_index = 8,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_CMP,
                        .first_op_index = 10,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_INC,
                        .first_op_index = 12,
                        .ops_amount = 1,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_INC,
                        .first_op_index = 12,
                        .ops_amount = 1,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_INC,
                        .first_op_index = 12,
                        .ops_amount = 1,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_INC,
                        .first_op_index = 12,
                        .ops_amount = 1,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_INC,
                        .first_op_index = 12,
                        .ops_amount = 1,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_INC,
                        .first_op_index = 12,
                        .ops_amount = 1,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_INC,
                        .first_op_index = 12,
                        .ops_amount = 1,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_INC,
                        .first_op_index = 12,
                        .ops_amount = 1,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_DEC,
                        .first_op_index = 12,
                        .ops_amount = 1,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_DEC,
                        .first_op_index = 12,
                        .ops_amount = 1,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_DEC,
                        .first_op_index = 12,
                        .ops_amount = 1,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_DEC,
                        .first_op_index = 12,
                        .ops_amount = 1,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_DEC,
                        .first_op_index = 12,
                        .ops_amount = 1,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_DEC,
                        .first_op_index = 12,
                        .ops_amount = 1,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_DEC,
                        .first_op_index = 12,
                        .ops_amount = 1,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_DEC,
                        .first_op_index = 12,
                        .ops_amount = 1,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_PUSH,
                        .first_op_index = 13,
                        .ops_amount = 1,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_PUSH,
                        .first_op_index = 13,
                        .ops_amount = 1,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_PUSH,
                        .first_op_index = 13,
                        .ops_amount = 1,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_PUSH,
                        .first_op_index = 13,
                        .ops_amount = 1,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_PUSH,
                        .first_op_index = 13,
                        .ops_amount = 1,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_PUSH,
                        .first_op_index = 13,
                        .ops_amount = 1,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_PUSH,
                        .first_op_index = 13,
                        .ops_amount = 1,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_PUSH,
                        .first_op_index = 13,
                        .ops_amount = 1,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_POP,
                        .first_op_index = 13,
                        .ops_amount = 1,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_POP,
                        .first_op_index = 13,
                        .ops_amount = 1,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_POP,
                        .first_op_index = 13,
                        .ops_amount = 1,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_POP,
                        .first_op_index = 13,
                        .ops_amount = 1,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_POP,
                        .first_op_index = 13,
                        .ops_amount = 1,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_POP,
                        .first_op_index = 13,
                        .ops_amount = 1,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_POP,
                        .first_op_index = 13,
                        .ops_amount = 1,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_POP,
                        .first_op_index = 13,
                        .ops_amount = 1,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_MOVSXD,
                        .first_op_index = 14,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_PUSH,
                        .first_op_index = 16,
                        .ops_amount = 1,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_IMUL,
                        .first_op_index = 17,
                        .ops_amount = 3,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_PUSH,
                        .first_op_index = 20,
                        .ops_amount = 1,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_IMUL,
                        .first_op_index = 21,
                        .ops_amount = 3,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_JCC,
                        .first_op_index = 24,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_JCC,
                        .first_op_index = 24,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_JCC,
                        .first_op_index = 24,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_JCC,
                        .first_op_index = 24,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_JCC,
                        .first_op_index = 24,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_JCC,
                        .first_op_index = 24,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_JCC,
                        .first_op_index = 24,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_JCC,
                        .first_op_index = 24,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_JCC,
                        .first_op_index = 24,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_JCC,
                        .first_op_index = 24,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_JCC,
                        .first_op_index = 24,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_JCC,
                        .first_op_index = 24,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_JCC,
                        .first_op_index = 24,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_JCC,
                        .first_op_index = 24,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_JCC,
                        .first_op_index = 24,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_JCC,
                        .first_op_index = 24,
                        .ops_amount = 2,
                    },
            },
            {
                .modrm_reg_opcode_ext =
                    {
                        .mnemonic = MNEMONIC_MODRM_REG_OPCODE_EXT,
                        .modrm_reg_table_index = 0,
                    },
            },
            {
                .modrm_reg_opcode_ext =
                    {
                        .mnemonic = MNEMONIC_MODRM_REG_OPCODE_EXT,
                        .modrm_reg_table_index = 1,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .modrm_reg_opcode_ext =
                    {
                        .mnemonic = MNEMONIC_MODRM_REG_OPCODE_EXT,
                        .modrm_reg_table_index = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_TEST,
                        .first_op_index = 0,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_TEST,
                        .first_op_index = 2,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_XCHG,
                        .first_op_index = 0,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_XCHG,
                        .first_op_index = 2,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_MOV,
                        .first_op_index = 0,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_MOV,
                        .first_op_index = 2,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_MOV,
                        .first_op_index = 4,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_MOV,
                        .first_op_index = 6,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_LEA,
                        .first_op_index = 6,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .modrm_reg_opcode_ext =
                    {
                        .mnemonic = MNEMONIC_MODRM_REG_OPCODE_EXT,
                        .modrm_reg_table_index = 3,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_NOP,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_XCHG,
                        .first_op_index = 33,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_XCHG,
                        .first_op_index = 33,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_XCHG,
                        .first_op_index = 33,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_XCHG,
                        .first_op_index = 33,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_XCHG,
                        .first_op_index = 33,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_XCHG,
                        .first_op_index = 33,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_XCHG,
                        .first_op_index = 33,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_MOVSX,
                        .first_op_index = 35,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_CWD,
                        .first_op_index = 37,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_MOV,
                        .first_op_index = 39,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_MOV,
                        .first_op_index = 41,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_MOV,
                        .first_op_index = 43,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_MOV,
                        .first_op_index = 45,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_MOVS,
                        .first_op_index = 47,
                        .ops_amount = 1,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_MOVS,
                        .first_op_index = 48,
                        .ops_amount = 1,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_CMPS,
                        .first_op_index = 47,
                        .ops_amount = 1,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_CMPS,
                        .first_op_index = 48,
                        .ops_amount = 1,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_TEST,
                        .first_op_index = 8,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_TEST,
                        .first_op_index = 10,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_STOS,
                        .first_op_index = 47,
                        .ops_amount = 1,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_STOS,
                        .first_op_index = 48,
                        .ops_amount = 1,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_LODS,
                        .first_op_index = 47,
                        .ops_amount = 1,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_LODS,
                        .first_op_index = 48,
                        .ops_amount = 1,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_SCAS,
                        .first_op_index = 47,
                        .ops_amount = 1,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_SCAS,
                        .first_op_index = 48,
                        .ops_amount = 1,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_MOV,
                        .first_op_index = 49,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_MOV,
                        .first_op_index = 49,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_MOV,
                        .first_op_index = 49,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_MOV,
                        .first_op_index = 49,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_MOV,
                        .first_op_index = 49,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_MOV,
                        .first_op_index = 49,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_MOV,
                        .first_op_index = 49,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_MOV,
                        .first_op_index = 49,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_MOV,
                        .first_op_index = 51,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_MOV,
                        .first_op_index = 51,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_MOV,
                        .first_op_index = 51,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_MOV,
                        .first_op_index = 51,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_MOV,
                        .first_op_index = 51,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_MOV,
                        .first_op_index = 51,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_MOV,
                        .first_op_index = 51,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_MOV,
                        .first_op_index = 51,
                        .ops_amount = 2,
                    },
            },
            {
                .modrm_reg_opcode_ext =
                    {
                        .mnemonic = MNEMONIC_MODRM_REG_OPCODE_EXT,
                        .modrm_reg_table_index = 4,
                    },
            },
            {
                .modrm_reg_opcode_ext =
                    {
                        .mnemonic = MNEMONIC_MODRM_REG_OPCODE_EXT,
                        .modrm_reg_table_index = 5,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_RET,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .modrm_reg_opcode_ext =
                    {
                        .mnemonic = MNEMONIC_MODRM_REG_OPCODE_EXT,
                        .modrm_reg_table_index = 6,
                    },
            },
            {
                .modrm_reg_opcode_ext =
                    {
                        .mnemonic = MNEMONIC_MODRM_REG_OPCODE_EXT,
                        .modrm_reg_table_index = 7,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .modrm_reg_opcode_ext =
                    {
                        .mnemonic = MNEMONIC_MODRM_REG_OPCODE_EXT,
                        .modrm_reg_table_index = 8,
                    },
            },
            {
                .modrm_reg_opcode_ext =
                    {
                        .mnemonic = MNEMONIC_MODRM_REG_OPCODE_EXT,
                        .modrm_reg_table_index = 9,
                    },
            },
            {
                .modrm_reg_opcode_ext =
                    {
                        .mnemonic = MNEMONIC_MODRM_REG_OPCODE_EXT,
                        .modrm_reg_table_index = 10,
                    },
            },
            {
                .modrm_reg_opcode_ext =
                    {
                        .mnemonic = MNEMONIC_MODRM_REG_OPCODE_EXT,
                        .modrm_reg_table_index = 11,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_CALL,
                        .first_op_index = 63,
                        .ops_amount = 1,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_JMP,
                        .first_op_index = 63,
                        .ops_amount = 1,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_JMP,
                        .first_op_index = 64,
                        .ops_amount = 1,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_HLT,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_CMC,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .modrm_reg_opcode_ext =
                    {
                        .mnemonic = MNEMONIC_MODRM_REG_OPCODE_EXT,
                        .modrm_reg_table_index = 12,
                    },
            },
            {
                .modrm_reg_opcode_ext =
                    {
                        .mnemonic = MNEMONIC_MODRM_REG_OPCODE_EXT,
                        .modrm_reg_table_index = 13,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_CLC,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_STC,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_CLI,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_STI,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_CLD,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_STD,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .modrm_reg_opcode_ext =
                    {
                        .mnemonic = MNEMONIC_MODRM_REG_OPCODE_EXT,
                        .modrm_reg_table_index = 14,
                    },
            },
            {
                .modrm_reg_opcode_ext =
                    {
                        .mnemonic = MNEMONIC_MODRM_REG_OPCODE_EXT,
                        .modrm_reg_table_index = 15,
                    },
            },
};
const insn_info_t
    second_opcode_byte_table[] =
        {
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .modrm_reg_opcode_ext =
                    {
                        .mnemonic = MNEMONIC_MODRM_REG_OPCODE_EXT,
                        .modrm_reg_table_index = 16,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_NOP,
                        .first_op_index = 67,
                        .ops_amount = 1,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_CMOVCC,
                        .first_op_index = 68,
                        .ops_amount = 3,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_CMOVCC,
                        .first_op_index = 68,
                        .ops_amount = 3,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_CMOVCC,
                        .first_op_index = 68,
                        .ops_amount = 3,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_CMOVCC,
                        .first_op_index = 68,
                        .ops_amount = 3,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_CMOVCC,
                        .first_op_index = 68,
                        .ops_amount = 3,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_CMOVCC,
                        .first_op_index = 68,
                        .ops_amount = 3,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_CMOVCC,
                        .first_op_index = 68,
                        .ops_amount = 3,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_CMOVCC,
                        .first_op_index = 68,
                        .ops_amount = 3,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_CMOVCC,
                        .first_op_index = 68,
                        .ops_amount = 3,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_CMOVCC,
                        .first_op_index = 68,
                        .ops_amount = 3,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_CMOVCC,
                        .first_op_index = 68,
                        .ops_amount = 3,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_CMOVCC,
                        .first_op_index = 68,
                        .ops_amount = 3,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_CMOVCC,
                        .first_op_index = 68,
                        .ops_amount = 3,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_CMOVCC,
                        .first_op_index = 68,
                        .ops_amount = 3,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_CMOVCC,
                        .first_op_index = 68,
                        .ops_amount = 3,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_CMOVCC,
                        .first_op_index = 68,
                        .ops_amount = 3,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_JCC,
                        .first_op_index = 71,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_JCC,
                        .first_op_index = 71,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_JCC,
                        .first_op_index = 71,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_JCC,
                        .first_op_index = 71,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_JCC,
                        .first_op_index = 71,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_JCC,
                        .first_op_index = 71,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_JCC,
                        .first_op_index = 71,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_JCC,
                        .first_op_index = 71,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_JCC,
                        .first_op_index = 71,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_JCC,
                        .first_op_index = 71,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_JCC,
                        .first_op_index = 71,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_JCC,
                        .first_op_index = 71,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_JCC,
                        .first_op_index = 71,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_JCC,
                        .first_op_index = 71,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_JCC,
                        .first_op_index = 71,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_JCC,
                        .first_op_index = 71,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_SETCC,
                        .first_op_index = 73,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_SETCC,
                        .first_op_index = 73,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_SETCC,
                        .first_op_index = 73,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_SETCC,
                        .first_op_index = 73,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_SETCC,
                        .first_op_index = 73,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_SETCC,
                        .first_op_index = 73,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_SETCC,
                        .first_op_index = 73,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_SETCC,
                        .first_op_index = 73,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_SETCC,
                        .first_op_index = 73,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_SETCC,
                        .first_op_index = 73,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_SETCC,
                        .first_op_index = 73,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_SETCC,
                        .first_op_index = 73,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_SETCC,
                        .first_op_index = 73,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_SETCC,
                        .first_op_index = 73,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_SETCC,
                        .first_op_index = 73,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_SETCC,
                        .first_op_index = 73,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_BT,
                        .first_op_index = 2,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_SHLD,
                        .first_op_index = 75,
                        .ops_amount = 3,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_SHLD,
                        .first_op_index = 78,
                        .ops_amount = 3,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_IMUL,
                        .first_op_index = 6,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_MOVZX,
                        .first_op_index = 81,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_MOVZX,
                        .first_op_index = 83,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_MOVSX,
                        .first_op_index = 81,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_MOVSX,
                        .first_op_index = 83,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 12,
                        .ops_amount = 0,
                    },
            },
};
