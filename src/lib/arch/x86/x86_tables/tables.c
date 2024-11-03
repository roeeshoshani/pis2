const op_size_info_t op_size_infos_table[] = {
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
        .with_operand_size_override = OP_SIZE_8,
        .mode_32 = OP_SIZE_8,
        .mode_64 = OP_SIZE_8,
        .mode_64_with_rex_w = OP_SIZE_8,
    },
};
const op_info_t op_infos_table[] = {
    {
        .cond =
            {
                .kind = OP_KIND_COND,
            },
    },
    {
        .reg =
            {
                .kind = OP_KIND_REG,
                .size_info_index = 3,
                .encoding = REG_ENC_MODRM,
            },
    },
    {
        .imm =
            {
                .kind = OP_KIND_IMM,
                .encoded_size_info_index = 4,
                .extended_size_info_index = 4,
                .extend_kind = IMM_EXT_ZERO_EXTEND,
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
                .encoded_size_info_index = 3,
                .extended_size_info_index = 3,
                .extend_kind = IMM_EXT_ZERO_EXTEND,
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
        .implicit =
            {
                .kind = OP_KIND_IMPLICIT,
                .size_info_index = 4,
            },
    },
    {
        .imm =
            {
                .kind = OP_KIND_IMM,
                .encoded_size_info_index = 4,
                .extended_size_info_index = 4,
                .extend_kind = IMM_EXT_SIGN_EXTEND,
            },
    },
    {
        .rel =
            {
                .kind = OP_KIND_REL,
                .size_info_index = 4,
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
        .rm =
            {
                .kind = OP_KIND_RM,
                .size_info_index = 4,
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
        .reg =
            {
                .kind = OP_KIND_REG,
                .size_info_index = 3,
                .encoding = REG_ENC_OPCODE,
            },
    },
    {
        .zext_specific_reg =
            {
                .kind = OP_KIND_ZEXT_SPECIFIC_REG,
                .size_info_index = 4,
                .extended_size_info_index = 3,
                .reg = SPECIFIC_REG_RCX,
            },
    },
    {
        .imm =
            {
                .kind = OP_KIND_IMM,
                .encoded_size_info_index = 4,
                .extended_size_info_index = 4,
                .extend_kind = IMM_EXT_SIGN_EXTEND,
            },
    },
    {
        .imm =
            {
                .kind = OP_KIND_IMM,
                .encoded_size_info_index = 1,
                .extended_size_info_index = 1,
                .extend_kind = IMM_EXT_SIGN_EXTEND,
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
        .specific_reg =
            {
                .kind = OP_KIND_SPECIFIC_REG,
                .size_info_index = 4,
                .reg = SPECIFIC_REG_RAX,
            },
    },
    {
        .mem_offset =
            {
                .kind = OP_KIND_MEM_OFFSET,
                .mem_operand_size_info_index = 3,
            },
    },
    {
        .reg =
            {
                .kind = OP_KIND_REG,
                .size_info_index = 4,
                .encoding = REG_ENC_MODRM,
            },
    },
    {
        .specific_imm =
            {
                .kind = OP_KIND_SPECIFIC_IMM,
                .operand_size_info_index = 3,
                .value = SPECIFIC_IMM_ONE,
            },
    },
    {
        .imm =
            {
                .kind = OP_KIND_IMM,
                .encoded_size_info_index = 4,
                .extended_size_info_index = 4,
                .extend_kind = IMM_EXT_SIGN_EXTEND,
            },
    },
    {
        .mem_offset =
            {
                .kind = OP_KIND_MEM_OFFSET,
                .mem_operand_size_info_index = 4,
            },
    },
    {
        .imm =
            {
                .kind = OP_KIND_IMM,
                .encoded_size_info_index = 1,
                .extended_size_info_index = 1,
                .extend_kind = IMM_EXT_SIGN_EXTEND,
            },
    },
    {
        .specific_reg =
            {
                .kind = OP_KIND_SPECIFIC_REG,
                .size_info_index = 3,
                .reg = SPECIFIC_REG_RDX,
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
        .implicit =
            {
                .kind = OP_KIND_IMPLICIT,
                .size_info_index = 3,
            },
    },
    {
        .specific_imm =
            {
                .kind = OP_KIND_SPECIFIC_IMM,
                .operand_size_info_index = 4,
                .value = SPECIFIC_IMM_ONE,
            },
    },
    {
        .specific_reg =
            {
                .kind = OP_KIND_SPECIFIC_REG,
                .size_info_index = 4,
                .reg = SPECIFIC_REG_RCX,
            },
    },
    {
        .reg =
            {
                .kind = OP_KIND_REG,
                .size_info_index = 4,
                .encoding = REG_ENC_OPCODE,
            },
    },
};
const uint8_t laid_out_ops_infos_table[] = {
    19, 10, 18, 5,  10, 21, 10, 10, 27, 8,  17, 22, 11, 20, 5,  12, 11, 1,  11, 13, 16, 12,
    4,  25, 1,  11, 9,  26, 0,  8,  1,  11, 15, 17, 21, 6,  23, 11, 2,  29, 21, 10, 28, 12,
    5,  15, 7,  5,  18, 11, 11, 14, 1,  11, 14, 10, 19, 24, 5,  22, 17, 5,  3,  11, 15,
};
const insn_info_t
    first_opcode_byte_table[] =
        {
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_ADD,
                        .first_op_index = 55,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_ADD,
                        .first_op_index = 16,
                        .ops_amount = 2,
                    },
            },
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
                        .first_op_index = 24,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_ADD,
                        .first_op_index = 33,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_ADD,
                        .first_op_index = 44,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 7,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 7,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_OR,
                        .first_op_index = 55,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_OR,
                        .first_op_index = 16,
                        .ops_amount = 2,
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
                        .first_op_index = 24,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_OR,
                        .first_op_index = 33,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_OR,
                        .first_op_index = 44,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 7,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 7,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_ADC,
                        .first_op_index = 55,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_ADC,
                        .first_op_index = 16,
                        .ops_amount = 2,
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
                        .first_op_index = 24,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_ADC,
                        .first_op_index = 33,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_ADC,
                        .first_op_index = 44,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 7,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 7,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_SBB,
                        .first_op_index = 55,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_SBB,
                        .first_op_index = 16,
                        .ops_amount = 2,
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
                        .first_op_index = 24,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_SBB,
                        .first_op_index = 33,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_SBB,
                        .first_op_index = 44,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 7,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 7,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_AND,
                        .first_op_index = 55,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_AND,
                        .first_op_index = 16,
                        .ops_amount = 2,
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
                        .first_op_index = 24,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_AND,
                        .first_op_index = 33,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_AND,
                        .first_op_index = 44,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 7,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 7,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_SUB,
                        .first_op_index = 55,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_SUB,
                        .first_op_index = 16,
                        .ops_amount = 2,
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
                        .first_op_index = 24,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_SUB,
                        .first_op_index = 33,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_SUB,
                        .first_op_index = 44,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 7,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 7,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_XOR,
                        .first_op_index = 55,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_XOR,
                        .first_op_index = 16,
                        .ops_amount = 2,
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
                        .first_op_index = 24,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_XOR,
                        .first_op_index = 33,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_XOR,
                        .first_op_index = 44,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 7,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 7,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_CMP,
                        .first_op_index = 55,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_CMP,
                        .first_op_index = 16,
                        .ops_amount = 2,
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
                        .first_op_index = 24,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_CMP,
                        .first_op_index = 33,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_CMP,
                        .first_op_index = 44,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 7,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 7,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_INC,
                        .first_op_index = 43,
                        .ops_amount = 1,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_INC,
                        .first_op_index = 43,
                        .ops_amount = 1,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_INC,
                        .first_op_index = 43,
                        .ops_amount = 1,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_INC,
                        .first_op_index = 43,
                        .ops_amount = 1,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_INC,
                        .first_op_index = 43,
                        .ops_amount = 1,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_INC,
                        .first_op_index = 43,
                        .ops_amount = 1,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_INC,
                        .first_op_index = 43,
                        .ops_amount = 1,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_INC,
                        .first_op_index = 43,
                        .ops_amount = 1,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_DEC,
                        .first_op_index = 43,
                        .ops_amount = 1,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_DEC,
                        .first_op_index = 43,
                        .ops_amount = 1,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_DEC,
                        .first_op_index = 43,
                        .ops_amount = 1,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_DEC,
                        .first_op_index = 43,
                        .ops_amount = 1,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_DEC,
                        .first_op_index = 43,
                        .ops_amount = 1,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_DEC,
                        .first_op_index = 43,
                        .ops_amount = 1,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_DEC,
                        .first_op_index = 43,
                        .ops_amount = 1,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_DEC,
                        .first_op_index = 43,
                        .ops_amount = 1,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_PUSH,
                        .first_op_index = 26,
                        .ops_amount = 1,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_PUSH,
                        .first_op_index = 26,
                        .ops_amount = 1,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_PUSH,
                        .first_op_index = 26,
                        .ops_amount = 1,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_PUSH,
                        .first_op_index = 26,
                        .ops_amount = 1,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_PUSH,
                        .first_op_index = 26,
                        .ops_amount = 1,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_PUSH,
                        .first_op_index = 26,
                        .ops_amount = 1,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_PUSH,
                        .first_op_index = 26,
                        .ops_amount = 1,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_PUSH,
                        .first_op_index = 26,
                        .ops_amount = 1,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_POP,
                        .first_op_index = 26,
                        .ops_amount = 1,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_POP,
                        .first_op_index = 26,
                        .ops_amount = 1,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_POP,
                        .first_op_index = 26,
                        .ops_amount = 1,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_POP,
                        .first_op_index = 26,
                        .ops_amount = 1,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_POP,
                        .first_op_index = 26,
                        .ops_amount = 1,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_POP,
                        .first_op_index = 26,
                        .ops_amount = 1,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_POP,
                        .first_op_index = 26,
                        .ops_amount = 1,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_POP,
                        .first_op_index = 26,
                        .ops_amount = 1,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 7,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 7,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 7,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 7,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 7,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 7,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 7,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 7,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_PUSH,
                        .first_op_index = 36,
                        .ops_amount = 1,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_IMUL,
                        .first_op_index = 30,
                        .ops_amount = 3,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_PUSH,
                        .first_op_index = 46,
                        .ops_amount = 1,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_IMUL,
                        .first_op_index = 52,
                        .ops_amount = 3,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 7,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 7,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 7,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 7,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_JCC,
                        .first_op_index = 28,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_JCC,
                        .first_op_index = 28,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_JCC,
                        .first_op_index = 28,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_JCC,
                        .first_op_index = 28,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_JCC,
                        .first_op_index = 28,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_JCC,
                        .first_op_index = 28,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_JCC,
                        .first_op_index = 28,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_JCC,
                        .first_op_index = 28,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_JCC,
                        .first_op_index = 28,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_JCC,
                        .first_op_index = 28,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_JCC,
                        .first_op_index = 28,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_JCC,
                        .first_op_index = 28,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_JCC,
                        .first_op_index = 28,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_JCC,
                        .first_op_index = 28,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_JCC,
                        .first_op_index = 28,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_JCC,
                        .first_op_index = 28,
                        .ops_amount = 2,
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
                        .modrm_reg_table_index = 14,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 7,
                        .ops_amount = 0,
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
                        .mnemonic = MNEMONIC_TEST,
                        .first_op_index = 55,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_TEST,
                        .first_op_index = 16,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_XCHG,
                        .first_op_index = 55,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_XCHG,
                        .first_op_index = 16,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_MOV,
                        .first_op_index = 55,
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
                        .mnemonic = MNEMONIC_MOV,
                        .first_op_index = 0,
                        .ops_amount = 2,
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
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 7,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_LEA,
                        .first_op_index = 24,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 7,
                        .ops_amount = 0,
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
                        .mnemonic = MNEMONIC_NOP,
                        .first_op_index = 7,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_XCHG,
                        .first_op_index = 14,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_XCHG,
                        .first_op_index = 14,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_XCHG,
                        .first_op_index = 14,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_XCHG,
                        .first_op_index = 14,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_XCHG,
                        .first_op_index = 14,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_XCHG,
                        .first_op_index = 14,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_XCHG,
                        .first_op_index = 14,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_XCHG,
                        .first_op_index = 14,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_MOVSZ,
                        .first_op_index = 61,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_CWD,
                        .first_op_index = 57,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 7,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 7,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 7,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 7,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 7,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 7,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_MOV,
                        .first_op_index = 10,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_MOV,
                        .first_op_index = 47,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_MOV,
                        .first_op_index = 59,
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
                        .mnemonic = MNEMONIC_MOVS,
                        .first_op_index = 35,
                        .ops_amount = 1,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_MOVS,
                        .first_op_index = 27,
                        .ops_amount = 1,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_CMPS,
                        .first_op_index = 35,
                        .ops_amount = 1,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_CMPS,
                        .first_op_index = 27,
                        .ops_amount = 1,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_TEST,
                        .first_op_index = 33,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_TEST,
                        .first_op_index = 44,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_STOS,
                        .first_op_index = 35,
                        .ops_amount = 1,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_STOS,
                        .first_op_index = 27,
                        .ops_amount = 1,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_LODS,
                        .first_op_index = 35,
                        .ops_amount = 1,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_LODS,
                        .first_op_index = 27,
                        .ops_amount = 1,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_SCAS,
                        .first_op_index = 35,
                        .ops_amount = 1,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_SCAS,
                        .first_op_index = 27,
                        .ops_amount = 1,
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
                        .first_op_index = 39,
                        .ops_amount = 2,
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
                        .first_op_index = 39,
                        .ops_amount = 2,
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
                        .first_op_index = 39,
                        .ops_amount = 2,
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
                        .first_op_index = 39,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_MOV,
                        .first_op_index = 21,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_MOV,
                        .first_op_index = 21,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_MOV,
                        .first_op_index = 21,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_MOV,
                        .first_op_index = 21,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_MOV,
                        .first_op_index = 21,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_MOV,
                        .first_op_index = 21,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_MOV,
                        .first_op_index = 21,
                        .ops_amount = 2,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_MOV,
                        .first_op_index = 21,
                        .ops_amount = 2,
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
                .modrm_reg_opcode_ext =
                    {
                        .mnemonic = MNEMONIC_MODRM_REG_OPCODE_EXT,
                        .modrm_reg_table_index = 4,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 7,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_RET,
                        .first_op_index = 7,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 7,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 7,
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
                        .first_op_index = 7,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 7,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 7,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 7,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 7,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 7,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 7,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 7,
                        .ops_amount = 0,
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
                        .modrm_reg_table_index = 9,
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
                .modrm_reg_opcode_ext =
                    {
                        .mnemonic = MNEMONIC_MODRM_REG_OPCODE_EXT,
                        .modrm_reg_table_index = 8,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 7,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 7,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 7,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 7,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 7,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 7,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 7,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 7,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 7,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 7,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 7,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 7,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 7,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 7,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 7,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 7,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 7,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 7,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 7,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 7,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_CALL,
                        .first_op_index = 23,
                        .ops_amount = 1,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_JMP,
                        .first_op_index = 23,
                        .ops_amount = 1,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 7,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_JMP,
                        .first_op_index = 9,
                        .ops_amount = 1,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 7,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 7,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 7,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 7,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 7,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 7,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 7,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_UNSUPPORTED,
                        .first_op_index = 7,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_HLT,
                        .first_op_index = 7,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_CMC,
                        .first_op_index = 7,
                        .ops_amount = 0,
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
                .modrm_reg_opcode_ext =
                    {
                        .mnemonic = MNEMONIC_MODRM_REG_OPCODE_EXT,
                        .modrm_reg_table_index = 15,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_CLC,
                        .first_op_index = 7,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_STC,
                        .first_op_index = 7,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_CLI,
                        .first_op_index = 7,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_STI,
                        .first_op_index = 7,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_CLD,
                        .first_op_index = 7,
                        .ops_amount = 0,
                    },
            },
            {
                .regular =
                    {
                        .mnemonic = MNEMONIC_STD,
                        .first_op_index = 7,
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
                        .modrm_reg_table_index = 6,
                    },
            },
};
