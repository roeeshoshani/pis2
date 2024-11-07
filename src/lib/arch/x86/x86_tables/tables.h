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
        .mode_64 = OP_SIZE_64,
        .mode_64_with_rex_w = OP_SIZE_64,
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
        .with_operand_size_override = OP_SIZE_8,
        .mode_32 = OP_SIZE_16,
        .mode_64 = OP_SIZE_16,
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
                .size_info_index = 2,
            },
    },
    {
        .reg =
            {
                .kind = OP_KIND_REG,
                .size_info_index = 2,
                .encoding = REG_ENC_MODRM,
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
                .encoded_size_info_index = 0,
                .extended_size_info_index = 0,
                .extend_kind = IMM_EXT_ZERO_EXTEND,
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
                .size_info_index = 2,
                .reg = SPECIFIC_REG_RAX,
            },
    },
    {
        .imm =
            {
                .kind = OP_KIND_IMM,
                .encoded_size_info_index = 3,
                .extended_size_info_index = 3,
                .extend_kind = IMM_EXT_SIGN_EXTEND,
            },
    },
    {
        .imm =
            {
                .kind = OP_KIND_IMM,
                .encoded_size_info_index = 3,
                .extended_size_info_index = 3,
                .extend_kind = IMM_EXT_SIGN_EXTEND,
            },
    },
    {
        .zext_specific_reg =
            {
                .kind = OP_KIND_ZEXT_SPECIFIC_REG,
                .size_info_index = 0,
                .extended_size_info_index = 2,
                .reg = SPECIFIC_REG_RCX,
            },
    },
    {
        .implicit =
            {
                .kind = OP_KIND_IMPLICIT,
                .size_info_index = 2,
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
        .mem_offset =
            {
                .kind = OP_KIND_MEM_OFFSET,
                .mem_operand_size_info_index = 2,
            },
    },
    {
        .cond =
            {
                .kind = OP_KIND_COND,
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
        .specific_imm =
            {
                .kind = OP_KIND_SPECIFIC_IMM,
                .operand_size_info_index = 0,
                .value = SPECIFIC_IMM_ONE,
            },
    },
    {
        .rel =
            {
                .kind = OP_KIND_REL,
                .size_info_index = 1,
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
        .imm =
            {
                .kind = OP_KIND_IMM,
                .encoded_size_info_index = 2,
                .extended_size_info_index = 2,
                .extend_kind = IMM_EXT_ZERO_EXTEND,
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
        .specific_imm =
            {
                .kind = OP_KIND_SPECIFIC_IMM,
                .operand_size_info_index = 2,
                .value = SPECIFIC_IMM_ONE,
            },
    },
    {
        .specific_reg =
            {
                .kind = OP_KIND_SPECIFIC_REG,
                .size_info_index = 2,
                .reg = SPECIFIC_REG_RDX,
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
        .rm =
            {
                .kind = OP_KIND_RM,
                .size_info_index = 1,
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
};
const uint8_t laid_out_ops_infos_table[] = {
    0,  1,  2,  3,  1,  0,  3, 2,  8,  9, 10, 11, 2,  13, 14, 15, 16, 10, 18, 8,  0,  9,
    10, 16, 8,  18, 26, 10, 0, 29, 27, 9, 19, 23, 2,  11, 0,  2,  2,  4,  17, 5,  10, 24,
    2,  25, 10, 19, 7,  2,  6, 19, 21, 0, 20, 28, 12, 3,  2,  4,  22, 3,  2,  11, 5,
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
                        .first_op_index = 51,
                        .ops_amount = 1,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_INC,
                        .first_op_index = 51,
                        .ops_amount = 1,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_INC,
                        .first_op_index = 51,
                        .ops_amount = 1,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_INC,
                        .first_op_index = 51,
                        .ops_amount = 1,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_INC,
                        .first_op_index = 51,
                        .ops_amount = 1,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_INC,
                        .first_op_index = 51,
                        .ops_amount = 1,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_INC,
                        .first_op_index = 51,
                        .ops_amount = 1,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_INC,
                        .first_op_index = 51,
                        .ops_amount = 1,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_DEC,
                        .first_op_index = 51,
                        .ops_amount = 1,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_DEC,
                        .first_op_index = 51,
                        .ops_amount = 1,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_DEC,
                        .first_op_index = 51,
                        .ops_amount = 1,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_DEC,
                        .first_op_index = 51,
                        .ops_amount = 1,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_DEC,
                        .first_op_index = 51,
                        .ops_amount = 1,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_DEC,
                        .first_op_index = 51,
                        .ops_amount = 1,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_DEC,
                        .first_op_index = 51,
                        .ops_amount = 1,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_DEC,
                        .first_op_index = 51,
                        .ops_amount = 1,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_PUSH,
                        .first_op_index = 48,
                        .ops_amount = 1,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_PUSH,
                        .first_op_index = 48,
                        .ops_amount = 1,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_PUSH,
                        .first_op_index = 48,
                        .ops_amount = 1,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_PUSH,
                        .first_op_index = 48,
                        .ops_amount = 1,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_PUSH,
                        .first_op_index = 48,
                        .ops_amount = 1,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_PUSH,
                        .first_op_index = 48,
                        .ops_amount = 1,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_PUSH,
                        .first_op_index = 48,
                        .ops_amount = 1,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_PUSH,
                        .first_op_index = 48,
                        .ops_amount = 1,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_POP,
                        .first_op_index = 48,
                        .ops_amount = 1,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_POP,
                        .first_op_index = 48,
                        .ops_amount = 1,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_POP,
                        .first_op_index = 48,
                        .ops_amount = 1,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_POP,
                        .first_op_index = 48,
                        .ops_amount = 1,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_POP,
                        .first_op_index = 48,
                        .ops_amount = 1,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_POP,
                        .first_op_index = 48,
                        .ops_amount = 1,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_POP,
                        .first_op_index = 48,
                        .ops_amount = 1,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_POP,
                        .first_op_index = 48,
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
                        .first_op_index = 56,
                        .ops_amount = 1,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_IMUL,
                        .first_op_index = 61,
                        .ops_amount = 3,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_PUSH,
                        .first_op_index = 60,
                        .ops_amount = 1,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_IMUL,
                        .first_op_index = 57,
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
                        .first_op_index = 40,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_JCC,
                        .first_op_index = 40,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_JCC,
                        .first_op_index = 40,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_JCC,
                        .first_op_index = 40,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_JCC,
                        .first_op_index = 40,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_JCC,
                        .first_op_index = 40,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_JCC,
                        .first_op_index = 40,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_JCC,
                        .first_op_index = 40,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_JCC,
                        .first_op_index = 40,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_JCC,
                        .first_op_index = 40,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_JCC,
                        .first_op_index = 40,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_JCC,
                        .first_op_index = 40,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_JCC,
                        .first_op_index = 40,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_JCC,
                        .first_op_index = 40,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_JCC,
                        .first_op_index = 40,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_JCC,
                        .first_op_index = 40,
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
                        .first_op_index = 46,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_XCHG,
                        .first_op_index = 46,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_XCHG,
                        .first_op_index = 46,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_XCHG,
                        .first_op_index = 46,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_XCHG,
                        .first_op_index = 46,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_XCHG,
                        .first_op_index = 46,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_XCHG,
                        .first_op_index = 46,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_XCHG,
                        .first_op_index = 46,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_MOVSZ,
                        .first_op_index = 42,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_CWD,
                        .first_op_index = 26,
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
                        .first_op_index = 24,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_MOV,
                        .first_op_index = 22,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_MOV,
                        .first_op_index = 18,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_MOV,
                        .first_op_index = 16,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_MOVS,
                        .first_op_index = 15,
                        .ops_amount = 1,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_MOVS,
                        .first_op_index = 14,
                        .ops_amount = 1,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_CMPS,
                        .first_op_index = 15,
                        .ops_amount = 1,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_CMPS,
                        .first_op_index = 14,
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
                        .first_op_index = 15,
                        .ops_amount = 1,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_STOS,
                        .first_op_index = 14,
                        .ops_amount = 1,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_LODS,
                        .first_op_index = 15,
                        .ops_amount = 1,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_LODS,
                        .first_op_index = 14,
                        .ops_amount = 1,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_SCAS,
                        .first_op_index = 15,
                        .ops_amount = 1,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_SCAS,
                        .first_op_index = 14,
                        .ops_amount = 1,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_MOV,
                        .first_op_index = 30,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_MOV,
                        .first_op_index = 30,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_MOV,
                        .first_op_index = 30,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_MOV,
                        .first_op_index = 30,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_MOV,
                        .first_op_index = 30,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_MOV,
                        .first_op_index = 30,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_MOV,
                        .first_op_index = 30,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_MOV,
                        .first_op_index = 30,
                        .ops_amount = 2,
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
                        .first_op_index = 32,
                        .ops_amount = 2,
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
                        .first_op_index = 32,
                        .ops_amount = 2,
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
                        .first_op_index = 32,
                        .ops_amount = 2,
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
                        .first_op_index = 32,
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
                        .first_op_index = 52,
                        .ops_amount = 1,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_JMP,
                        .first_op_index = 52,
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
