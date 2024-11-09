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
        .mode_32 = OP_SIZE_32,
        .mode_64 = OP_SIZE_32,
        .mode_64_with_rex_w = OP_SIZE_32,
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
        .imm =
            {
                .kind = OP_KIND_IMM,
                .encoded_size_info_index = 4,
                .extended_size_info_index = 2,
                .extend_kind = IMM_EXT_SIGN_EXTEND,
            },
    },
    {
        .rm =
            {
                .kind = OP_KIND_RM,
                .size_info_index = 4,
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
        .imm =
            {
                .kind = OP_KIND_IMM,
                .encoded_size_info_index = 4,
                .extended_size_info_index = 1,
                .extend_kind = IMM_EXT_SIGN_EXTEND,
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
        .specific_reg =
            {
                .kind = OP_KIND_SPECIFIC_REG,
                .size_info_index = 1,
                .reg = SPECIFIC_REG_RDX,
            },
    },
    {
        .cond =
            {
                .kind = OP_KIND_COND,
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
        .specific_reg =
            {
                .kind = OP_KIND_SPECIFIC_REG,
                .size_info_index = 0,
                .reg = SPECIFIC_REG_RCX,
            },
    },
    {
        .imm =
            {
                .kind = OP_KIND_IMM,
                .encoded_size_info_index = 0,
                .extended_size_info_index = 2,
                .extend_kind = IMM_EXT_SIGN_EXTEND,
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
                .encoded_size_info_index = 0,
                .extended_size_info_index = 1,
                .extend_kind = IMM_EXT_ZERO_EXTEND,
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
        .reg =
            {
                .kind = OP_KIND_REG,
                .size_info_index = 1,
                .encoding = REG_ENC_OPCODE,
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
        .mem_offset =
            {
                .kind = OP_KIND_MEM_OFFSET,
                .mem_operand_size_info_index = 1,
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
        .specific_imm =
            {
                .kind = OP_KIND_SPECIFIC_IMM,
                .operand_size_info_index = 0,
                .value = SPECIFIC_IMM_ONE,
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
        .reg =
            {
                .kind = OP_KIND_REG,
                .size_info_index = 2,
                .encoding = REG_ENC_OPCODE,
            },
    },
    {
        .specific_reg =
            {
                .kind = OP_KIND_SPECIFIC_REG,
                .size_info_index = 3,
                .reg = SPECIFIC_REG_RAX,
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
        .implicit =
            {
                .kind = OP_KIND_IMPLICIT,
                .size_info_index = 0,
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
        .implicit =
            {
                .kind = OP_KIND_IMPLICIT,
                .size_info_index = 1,
            },
    },
};
const uint8_t laid_out_ops_infos_table[] = {
    0,  1,  2,  3,  1,  0,  3,  2,  8,  9,  10, 7,  2,  3,  13, 2,  3,  17, 12, 0,
    2,  7,  0,  23, 0,  9,  19, 27, 2,  29, 30, 28, 8,  24, 10, 19, 2,  17, 0,  14,
    2,  13, 18, 2,  20, 22, 12, 18, 10, 26, 10, 21, 11, 10, 24, 8,  16, 9,  12, 6,
    21, 10, 0,  6,  2,  3,  2,  20, 15, 3,  2,  7,  4,  25, 12, 3,  2,  19, 5,
};
const modrm_reg_opcode_ext_table_t modrm_reg_opcode_ext_tables[] = {
    {
        .by_reg_value =
            {
                {
                    .mnemonic = MNEMONIC_ADD,
                    .first_op_index = 24,
                    .ops_amount = 2,
                },
                {
                    .mnemonic = MNEMONIC_OR,
                    .first_op_index = 24,
                    .ops_amount = 2,
                },
                {
                    .mnemonic = MNEMONIC_ADC,
                    .first_op_index = 24,
                    .ops_amount = 2,
                },
                {
                    .mnemonic = MNEMONIC_SBB,
                    .first_op_index = 24,
                    .ops_amount = 2,
                },
                {
                    .mnemonic = MNEMONIC_AND,
                    .first_op_index = 24,
                    .ops_amount = 2,
                },
                {
                    .mnemonic = MNEMONIC_SUB,
                    .first_op_index = 24,
                    .ops_amount = 2,
                },
                {
                    .mnemonic = MNEMONIC_XOR,
                    .first_op_index = 24,
                    .ops_amount = 2,
                },
                {
                    .mnemonic = MNEMONIC_CMD,
                    .first_op_index = 24,
                    .ops_amount = 2,
                },
            },
    },
    {
        .by_reg_value =
            {
                {
                    .mnemonic = MNEMONIC_ADD,
                    .first_op_index = 20,
                    .ops_amount = 2,
                },
                {
                    .mnemonic = MNEMONIC_OR,
                    .first_op_index = 20,
                    .ops_amount = 2,
                },
                {
                    .mnemonic = MNEMONIC_ADC,
                    .first_op_index = 20,
                    .ops_amount = 2,
                },
                {
                    .mnemonic = MNEMONIC_SBB,
                    .first_op_index = 20,
                    .ops_amount = 2,
                },
                {
                    .mnemonic = MNEMONIC_AND,
                    .first_op_index = 20,
                    .ops_amount = 2,
                },
                {
                    .mnemonic = MNEMONIC_SUB,
                    .first_op_index = 20,
                    .ops_amount = 2,
                },
                {
                    .mnemonic = MNEMONIC_XOR,
                    .first_op_index = 20,
                    .ops_amount = 2,
                },
                {
                    .mnemonic = MNEMONIC_CMD,
                    .first_op_index = 20,
                    .ops_amount = 2,
                },
            },
    },
    {
        .by_reg_value =
            {
                {
                    .mnemonic = MNEMONIC_ADD,
                    .first_op_index = 43,
                    .ops_amount = 2,
                },
                {
                    .mnemonic = MNEMONIC_OR,
                    .first_op_index = 43,
                    .ops_amount = 2,
                },
                {
                    .mnemonic = MNEMONIC_ADC,
                    .first_op_index = 43,
                    .ops_amount = 2,
                },
                {
                    .mnemonic = MNEMONIC_SBB,
                    .first_op_index = 43,
                    .ops_amount = 2,
                },
                {
                    .mnemonic = MNEMONIC_AND,
                    .first_op_index = 43,
                    .ops_amount = 2,
                },
                {
                    .mnemonic = MNEMONIC_SUB,
                    .first_op_index = 43,
                    .ops_amount = 2,
                },
                {
                    .mnemonic = MNEMONIC_XOR,
                    .first_op_index = 43,
                    .ops_amount = 2,
                },
                {
                    .mnemonic = MNEMONIC_CMD,
                    .first_op_index = 43,
                    .ops_amount = 2,
                },
            },
    },
    {
        .by_reg_value =
            {
                {
                    .mnemonic = MNEMONIC_POP,
                    .first_op_index = 45,
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
                    .first_op_index = 24,
                    .ops_amount = 2,
                },
                {
                    .mnemonic = MNEMONIC_ROR,
                    .first_op_index = 24,
                    .ops_amount = 2,
                },
                {
                    .mnemonic = MNEMONIC_RCL,
                    .first_op_index = 24,
                    .ops_amount = 2,
                },
                {
                    .mnemonic = MNEMONIC_RCR,
                    .first_op_index = 24,
                    .ops_amount = 2,
                },
                {
                    .mnemonic = MNEMONIC_SHL,
                    .first_op_index = 24,
                    .ops_amount = 2,
                },
                {
                    .mnemonic = MNEMONIC_SHR,
                    .first_op_index = 24,
                    .ops_amount = 2,
                },
                {
                    .mnemonic = MNEMONIC_UNSUPPORTED,
                    .first_op_index = 24,
                    .ops_amount = 2,
                },
                {
                    .mnemonic = MNEMONIC_SAR,
                    .first_op_index = 24,
                    .ops_amount = 2,
                },
            },
    },
    {
        .by_reg_value =
            {
                {
                    .mnemonic = MNEMONIC_ROL,
                    .first_op_index = 36,
                    .ops_amount = 2,
                },
                {
                    .mnemonic = MNEMONIC_ROR,
                    .first_op_index = 36,
                    .ops_amount = 2,
                },
                {
                    .mnemonic = MNEMONIC_RCL,
                    .first_op_index = 36,
                    .ops_amount = 2,
                },
                {
                    .mnemonic = MNEMONIC_RCR,
                    .first_op_index = 36,
                    .ops_amount = 2,
                },
                {
                    .mnemonic = MNEMONIC_SHL,
                    .first_op_index = 36,
                    .ops_amount = 2,
                },
                {
                    .mnemonic = MNEMONIC_SHR,
                    .first_op_index = 36,
                    .ops_amount = 2,
                },
                {
                    .mnemonic = MNEMONIC_UNSUPPORTED,
                    .first_op_index = 36,
                    .ops_amount = 2,
                },
                {
                    .mnemonic = MNEMONIC_SAR,
                    .first_op_index = 36,
                    .ops_amount = 2,
                },
            },
    },
    {
        .by_reg_value =
            {
                {
                    .mnemonic = MNEMONIC_MOV,
                    .first_op_index = 24,
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
                    .first_op_index = 20,
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
                    .first_op_index = 22,
                    .ops_amount = 2,
                },
                {
                    .mnemonic = MNEMONIC_ROR,
                    .first_op_index = 22,
                    .ops_amount = 2,
                },
                {
                    .mnemonic = MNEMONIC_RCL,
                    .first_op_index = 22,
                    .ops_amount = 2,
                },
                {
                    .mnemonic = MNEMONIC_RCR,
                    .first_op_index = 22,
                    .ops_amount = 2,
                },
                {
                    .mnemonic = MNEMONIC_SHL,
                    .first_op_index = 22,
                    .ops_amount = 2,
                },
                {
                    .mnemonic = MNEMONIC_SHR,
                    .first_op_index = 22,
                    .ops_amount = 2,
                },
                {
                    .mnemonic = MNEMONIC_UNSUPPORTED,
                    .first_op_index = 22,
                    .ops_amount = 2,
                },
                {
                    .mnemonic = MNEMONIC_SAR,
                    .first_op_index = 22,
                    .ops_amount = 2,
                },
            },
    },
    {
        .by_reg_value =
            {
                {
                    .mnemonic = MNEMONIC_ROL,
                    .first_op_index = 28,
                    .ops_amount = 2,
                },
                {
                    .mnemonic = MNEMONIC_ROR,
                    .first_op_index = 28,
                    .ops_amount = 2,
                },
                {
                    .mnemonic = MNEMONIC_RCL,
                    .first_op_index = 28,
                    .ops_amount = 2,
                },
                {
                    .mnemonic = MNEMONIC_RCR,
                    .first_op_index = 28,
                    .ops_amount = 2,
                },
                {
                    .mnemonic = MNEMONIC_SHL,
                    .first_op_index = 28,
                    .ops_amount = 2,
                },
                {
                    .mnemonic = MNEMONIC_SHR,
                    .first_op_index = 28,
                    .ops_amount = 2,
                },
                {
                    .mnemonic = MNEMONIC_UNSUPPORTED,
                    .first_op_index = 28,
                    .ops_amount = 2,
                },
                {
                    .mnemonic = MNEMONIC_SAR,
                    .first_op_index = 28,
                    .ops_amount = 2,
                },
            },
    },
    {
        .by_reg_value =
            {
                {
                    .mnemonic = MNEMONIC_ROL,
                    .first_op_index = 38,
                    .ops_amount = 2,
                },
                {
                    .mnemonic = MNEMONIC_ROR,
                    .first_op_index = 38,
                    .ops_amount = 2,
                },
                {
                    .mnemonic = MNEMONIC_RCL,
                    .first_op_index = 38,
                    .ops_amount = 2,
                },
                {
                    .mnemonic = MNEMONIC_RCR,
                    .first_op_index = 38,
                    .ops_amount = 2,
                },
                {
                    .mnemonic = MNEMONIC_SHL,
                    .first_op_index = 38,
                    .ops_amount = 2,
                },
                {
                    .mnemonic = MNEMONIC_SHR,
                    .first_op_index = 38,
                    .ops_amount = 2,
                },
                {
                    .mnemonic = MNEMONIC_UNSUPPORTED,
                    .first_op_index = 38,
                    .ops_amount = 2,
                },
                {
                    .mnemonic = MNEMONIC_SAR,
                    .first_op_index = 38,
                    .ops_amount = 2,
                },
            },
    },
    {
        .by_reg_value =
            {
                {
                    .mnemonic = MNEMONIC_ROL,
                    .first_op_index = 40,
                    .ops_amount = 2,
                },
                {
                    .mnemonic = MNEMONIC_ROR,
                    .first_op_index = 40,
                    .ops_amount = 2,
                },
                {
                    .mnemonic = MNEMONIC_RCL,
                    .first_op_index = 40,
                    .ops_amount = 2,
                },
                {
                    .mnemonic = MNEMONIC_RCR,
                    .first_op_index = 40,
                    .ops_amount = 2,
                },
                {
                    .mnemonic = MNEMONIC_SHL,
                    .first_op_index = 40,
                    .ops_amount = 2,
                },
                {
                    .mnemonic = MNEMONIC_SHR,
                    .first_op_index = 40,
                    .ops_amount = 2,
                },
                {
                    .mnemonic = MNEMONIC_UNSUPPORTED,
                    .first_op_index = 40,
                    .ops_amount = 2,
                },
                {
                    .mnemonic = MNEMONIC_SAR,
                    .first_op_index = 40,
                    .ops_amount = 2,
                },
            },
    },
    {
        .by_reg_value =
            {
                {
                    .mnemonic = MNEMONIC_TEST,
                    .first_op_index = 24,
                    .ops_amount = 2,
                },
                {
                    .mnemonic = MNEMONIC_UNSUPPORTED,
                    .first_op_index = 12,
                    .ops_amount = 0,
                },
                {
                    .mnemonic = MNEMONIC_NOT,
                    .first_op_index = 62,
                    .ops_amount = 1,
                },
                {
                    .mnemonic = MNEMONIC_NEG,
                    .first_op_index = 62,
                    .ops_amount = 1,
                },
                {
                    .mnemonic = MNEMONIC_MUL,
                    .first_op_index = 62,
                    .ops_amount = 1,
                },
                {
                    .mnemonic = MNEMONIC_IMUL,
                    .first_op_index = 62,
                    .ops_amount = 1,
                },
                {
                    .mnemonic = MNEMONIC_DIV,
                    .first_op_index = 62,
                    .ops_amount = 1,
                },
                {
                    .mnemonic = MNEMONIC_IDIV,
                    .first_op_index = 62,
                    .ops_amount = 1,
                },
            },
    },
    {
        .by_reg_value =
            {
                {
                    .mnemonic = MNEMONIC_TEST,
                    .first_op_index = 20,
                    .ops_amount = 2,
                },
                {
                    .mnemonic = MNEMONIC_UNSUPPORTED,
                    .first_op_index = 12,
                    .ops_amount = 0,
                },
                {
                    .mnemonic = MNEMONIC_NOT,
                    .first_op_index = 64,
                    .ops_amount = 1,
                },
                {
                    .mnemonic = MNEMONIC_NEG,
                    .first_op_index = 64,
                    .ops_amount = 1,
                },
                {
                    .mnemonic = MNEMONIC_MUL,
                    .first_op_index = 64,
                    .ops_amount = 1,
                },
                {
                    .mnemonic = MNEMONIC_IMUL,
                    .first_op_index = 64,
                    .ops_amount = 1,
                },
                {
                    .mnemonic = MNEMONIC_DIV,
                    .first_op_index = 64,
                    .ops_amount = 1,
                },
                {
                    .mnemonic = MNEMONIC_IDIV,
                    .first_op_index = 64,
                    .ops_amount = 1,
                },
            },
    },
    {
        .by_reg_value =
            {
                {
                    .mnemonic = MNEMONIC_INC,
                    .first_op_index = 62,
                    .ops_amount = 1,
                },
                {
                    .mnemonic = MNEMONIC_DEC,
                    .first_op_index = 62,
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
                    .first_op_index = 64,
                    .ops_amount = 1,
                },
                {
                    .mnemonic = MNEMONIC_DEC,
                    .first_op_index = 64,
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
                        .first_op_index = 77,
                        .ops_amount = 1,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_INC,
                        .first_op_index = 77,
                        .ops_amount = 1,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_INC,
                        .first_op_index = 77,
                        .ops_amount = 1,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_INC,
                        .first_op_index = 77,
                        .ops_amount = 1,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_INC,
                        .first_op_index = 77,
                        .ops_amount = 1,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_INC,
                        .first_op_index = 77,
                        .ops_amount = 1,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_INC,
                        .first_op_index = 77,
                        .ops_amount = 1,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_INC,
                        .first_op_index = 77,
                        .ops_amount = 1,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_DEC,
                        .first_op_index = 77,
                        .ops_amount = 1,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_DEC,
                        .first_op_index = 77,
                        .ops_amount = 1,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_DEC,
                        .first_op_index = 77,
                        .ops_amount = 1,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_DEC,
                        .first_op_index = 77,
                        .ops_amount = 1,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_DEC,
                        .first_op_index = 77,
                        .ops_amount = 1,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_DEC,
                        .first_op_index = 77,
                        .ops_amount = 1,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_DEC,
                        .first_op_index = 77,
                        .ops_amount = 1,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_DEC,
                        .first_op_index = 77,
                        .ops_amount = 1,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_PUSH,
                        .first_op_index = 73,
                        .ops_amount = 1,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_PUSH,
                        .first_op_index = 73,
                        .ops_amount = 1,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_PUSH,
                        .first_op_index = 73,
                        .ops_amount = 1,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_PUSH,
                        .first_op_index = 73,
                        .ops_amount = 1,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_PUSH,
                        .first_op_index = 73,
                        .ops_amount = 1,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_PUSH,
                        .first_op_index = 73,
                        .ops_amount = 1,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_PUSH,
                        .first_op_index = 73,
                        .ops_amount = 1,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_PUSH,
                        .first_op_index = 73,
                        .ops_amount = 1,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_POP,
                        .first_op_index = 73,
                        .ops_amount = 1,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_POP,
                        .first_op_index = 73,
                        .ops_amount = 1,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_POP,
                        .first_op_index = 73,
                        .ops_amount = 1,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_POP,
                        .first_op_index = 73,
                        .ops_amount = 1,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_POP,
                        .first_op_index = 73,
                        .ops_amount = 1,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_POP,
                        .first_op_index = 73,
                        .ops_amount = 1,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_POP,
                        .first_op_index = 73,
                        .ops_amount = 1,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_POP,
                        .first_op_index = 73,
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
                        .mnemonic = MNEMONIC_PUSH,
                        .first_op_index = 72,
                        .ops_amount = 1,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_IMUL,
                        .first_op_index = 69,
                        .ops_amount = 3,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_PUSH,
                        .first_op_index = 68,
                        .ops_amount = 1,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_IMUL,
                        .first_op_index = 65,
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
                        .first_op_index = 58,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_JCC,
                        .first_op_index = 58,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_JCC,
                        .first_op_index = 58,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_JCC,
                        .first_op_index = 58,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_JCC,
                        .first_op_index = 58,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_JCC,
                        .first_op_index = 58,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_JCC,
                        .first_op_index = 58,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_JCC,
                        .first_op_index = 58,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_JCC,
                        .first_op_index = 58,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_JCC,
                        .first_op_index = 58,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_JCC,
                        .first_op_index = 58,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_JCC,
                        .first_op_index = 58,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_JCC,
                        .first_op_index = 58,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_JCC,
                        .first_op_index = 58,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_JCC,
                        .first_op_index = 58,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_JCC,
                        .first_op_index = 58,
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
                        .first_op_index = 34,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_XCHG,
                        .first_op_index = 34,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_XCHG,
                        .first_op_index = 34,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_XCHG,
                        .first_op_index = 34,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_XCHG,
                        .first_op_index = 34,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_XCHG,
                        .first_op_index = 34,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_XCHG,
                        .first_op_index = 34,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_MOVSZ,
                        .first_op_index = 48,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_CWD,
                        .first_op_index = 52,
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
                        .first_op_index = 32,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_MOV,
                        .first_op_index = 50,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_MOV,
                        .first_op_index = 54,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_MOV,
                        .first_op_index = 60,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_MOVS,
                        .first_op_index = 31,
                        .ops_amount = 1,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_MOVS,
                        .first_op_index = 30,
                        .ops_amount = 1,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_CMPS,
                        .first_op_index = 31,
                        .ops_amount = 1,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_CMPS,
                        .first_op_index = 30,
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
                        .first_op_index = 31,
                        .ops_amount = 1,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_STOS,
                        .first_op_index = 30,
                        .ops_amount = 1,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_LODS,
                        .first_op_index = 31,
                        .ops_amount = 1,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_LODS,
                        .first_op_index = 30,
                        .ops_amount = 1,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_SCAS,
                        .first_op_index = 31,
                        .ops_amount = 1,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_SCAS,
                        .first_op_index = 30,
                        .ops_amount = 1,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_MOV,
                        .first_op_index = 56,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_MOV,
                        .first_op_index = 56,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_MOV,
                        .first_op_index = 56,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_MOV,
                        .first_op_index = 56,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_MOV,
                        .first_op_index = 56,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_MOV,
                        .first_op_index = 56,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_MOV,
                        .first_op_index = 56,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_MOV,
                        .first_op_index = 56,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_MOV,
                        .first_op_index = 26,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_MOV,
                        .first_op_index = 26,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_MOV,
                        .first_op_index = 26,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_MOV,
                        .first_op_index = 26,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_MOV,
                        .first_op_index = 26,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_MOV,
                        .first_op_index = 26,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_MOV,
                        .first_op_index = 26,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_MOV,
                        .first_op_index = 26,
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
                        .first_op_index = 42,
                        .ops_amount = 1,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_JMP,
                        .first_op_index = 42,
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
                        .first_op_index = 78,
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
                        .first_op_index = 74,
                        .ops_amount = 3,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_CMOVCC,
                        .first_op_index = 74,
                        .ops_amount = 3,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_CMOVCC,
                        .first_op_index = 74,
                        .ops_amount = 3,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_CMOVCC,
                        .first_op_index = 74,
                        .ops_amount = 3,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_CMOVCC,
                        .first_op_index = 74,
                        .ops_amount = 3,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_CMOVCC,
                        .first_op_index = 74,
                        .ops_amount = 3,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_CMOVCC,
                        .first_op_index = 74,
                        .ops_amount = 3,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_CMOVCC,
                        .first_op_index = 74,
                        .ops_amount = 3,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_CMOVCC,
                        .first_op_index = 74,
                        .ops_amount = 3,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_CMOVCC,
                        .first_op_index = 74,
                        .ops_amount = 3,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_CMOVCC,
                        .first_op_index = 74,
                        .ops_amount = 3,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_CMOVCC,
                        .first_op_index = 74,
                        .ops_amount = 3,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_CMOVCC,
                        .first_op_index = 74,
                        .ops_amount = 3,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_CMOVCC,
                        .first_op_index = 74,
                        .ops_amount = 3,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_CMOVCC,
                        .first_op_index = 74,
                        .ops_amount = 3,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_CMOVCC,
                        .first_op_index = 74,
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
                        .first_op_index = 46,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_JCC,
                        .first_op_index = 46,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_JCC,
                        .first_op_index = 46,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_JCC,
                        .first_op_index = 46,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_JCC,
                        .first_op_index = 46,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_JCC,
                        .first_op_index = 46,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_JCC,
                        .first_op_index = 46,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_JCC,
                        .first_op_index = 46,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_JCC,
                        .first_op_index = 46,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_JCC,
                        .first_op_index = 46,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_JCC,
                        .first_op_index = 46,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_JCC,
                        .first_op_index = 46,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_JCC,
                        .first_op_index = 46,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_JCC,
                        .first_op_index = 46,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_JCC,
                        .first_op_index = 46,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_JCC,
                        .first_op_index = 46,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_SETCC,
                        .first_op_index = 18,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_SETCC,
                        .first_op_index = 18,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_SETCC,
                        .first_op_index = 18,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_SETCC,
                        .first_op_index = 18,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_SETCC,
                        .first_op_index = 18,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_SETCC,
                        .first_op_index = 18,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_SETCC,
                        .first_op_index = 18,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_SETCC,
                        .first_op_index = 18,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_SETCC,
                        .first_op_index = 18,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_SETCC,
                        .first_op_index = 18,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_SETCC,
                        .first_op_index = 18,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_SETCC,
                        .first_op_index = 18,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_SETCC,
                        .first_op_index = 18,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_SETCC,
                        .first_op_index = 18,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_SETCC,
                        .first_op_index = 18,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_SETCC,
                        .first_op_index = 18,
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
                        .first_op_index = 15,
                        .ops_amount = 3,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_SHLD,
                        .first_op_index = 12,
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
