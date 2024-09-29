#include "ctx.h"
#include "arch/x86/tmps.h"
#include "errors.h"
#include "except.h"
#include "lift_ctx.h"
#include "modrm.h"
#include "pis.h"
#include "prefixes.h"
#include "regs.h"

static pis_operand_size_t cpumode_get_operand_size(pis_x86_cpumode_t cpumode) {
    switch (cpumode) {
    case PIS_X86_CPUMODE_64_BIT:
        return PIS_OPERAND_SIZE_8;
    case PIS_X86_CPUMODE_32_BIT:
        return PIS_OPERAND_SIZE_4;
    case PIS_X86_CPUMODE_16_BIT:
        return PIS_OPERAND_SIZE_2;
    default:
        // unreachable
        return PIS_OPERAND_SIZE_1;
    }
}

static pis_operand_size_t get_effective_stack_addr_size(pis_x86_cpumode_t cpumode) {
    return cpumode_get_operand_size(cpumode);
}

static pis_operand_t get_sp_operand(pis_x86_cpumode_t cpumode) {
    return PIS_OPERAND_REG(0b100 * 8, get_effective_stack_addr_size(cpumode));
}

static pis_operand_size_t get_effective_operand_size(
    pis_x86_cpumode_t cpumode, const prefixes_t* prefixes, bool default_to_64_bit
) {
    bool has_size_override =
        prefixes_contain_legacy_prefix(prefixes, LEGACY_PREFIX_OPERAND_SIZE_OVERRIDE);

    switch (cpumode) {
    case PIS_X86_CPUMODE_16_BIT:
        return has_size_override ? PIS_OPERAND_SIZE_4 : PIS_OPERAND_SIZE_2;
    case PIS_X86_CPUMODE_32_BIT:
        return has_size_override ? PIS_OPERAND_SIZE_2 : PIS_OPERAND_SIZE_4;
    case PIS_X86_CPUMODE_64_BIT:
        if (prefixes->rex.w) {
            return PIS_OPERAND_SIZE_8;
        } else {
            if (default_to_64_bit) {
                return has_size_override ? PIS_OPERAND_SIZE_2 : PIS_OPERAND_SIZE_8;
            } else {
                return has_size_override ? PIS_OPERAND_SIZE_2 : PIS_OPERAND_SIZE_4;
            }
        }
    default:
        // unreachable
        return PIS_OPERAND_SIZE_1;
    }
}

static pis_operand_size_t
    get_effective_addr_size(pis_x86_cpumode_t cpumode, const prefixes_t* prefixes) {
    bool has_size_override =
        prefixes_contain_legacy_prefix(prefixes, LEGACY_PREFIX_ADDRESS_SIZE_OVERRIDE);

    switch (cpumode) {
    case PIS_X86_CPUMODE_16_BIT:
        return has_size_override ? PIS_OPERAND_SIZE_4 : PIS_OPERAND_SIZE_2;
    case PIS_X86_CPUMODE_32_BIT:
        return has_size_override ? PIS_OPERAND_SIZE_2 : PIS_OPERAND_SIZE_4;
    case PIS_X86_CPUMODE_64_BIT:
        return has_size_override ? PIS_OPERAND_SIZE_4 : PIS_OPERAND_SIZE_8;
    default:
        // unreachable
        return PIS_OPERAND_SIZE_1;
    }
}

static err_t
    calc_parity_flag(const post_prefixes_ctx_t* ctx, const pis_operand_t* calculation_result) {
    err_t err = SUCCESS;

    LIFT_CTX_EMIT(
        ctx->lift_ctx,
        PIS_INSN3(
            PIS_OPCODE_GET_LOW_BITS,
            g_parity_flag_low_byte_tmp,
            *calculation_result,
            PIS_OPERAND_CONST(8, PIS_OPERAND_SIZE_1)
        )
    );
    LIFT_CTX_EMIT(
        ctx->lift_ctx,
        PIS_INSN2(PIS_OPCODE_PARITY, FLAGS_PF, g_parity_flag_low_byte_tmp)
    );

cleanup:
    return err;
}

static err_t
    calc_zero_flag(const post_prefixes_ctx_t* ctx, const pis_operand_t* calculation_result) {
    err_t err = SUCCESS;

    LIFT_CTX_EMIT(
        ctx->lift_ctx,
        PIS_INSN3(
            PIS_OPCODE_EQUALS,
            FLAGS_ZF,
            *calculation_result,
            PIS_OPERAND_CONST(0, calculation_result->size)
        )
    );

cleanup:
    return err;
}

static err_t
    calc_sign_flag(const post_prefixes_ctx_t* ctx, const pis_operand_t* calculation_result) {
    err_t err = SUCCESS;

    u64 shift_amount = pis_operand_size_to_bits(calculation_result->size) - 1;

    LIFT_CTX_EMIT(
        ctx->lift_ctx,
        PIS_INSN3(
            PIS_OPCODE_SHIFT_RIGHT,
            FLAGS_SF,
            *calculation_result,
            PIS_OPERAND_CONST(shift_amount, PIS_OPERAND_SIZE_1)
        )
    );

cleanup:
    return err;
}

static err_t calc_parity_zero_sign_flags(
    const post_prefixes_ctx_t* ctx, const pis_operand_t* calculation_result
) {
    err_t err = SUCCESS;

    CHECK_RETHROW(calc_parity_flag(ctx, calculation_result));
    CHECK_RETHROW(calc_zero_flag(ctx, calculation_result));
    CHECK_RETHROW(calc_sign_flag(ctx, calculation_result));

cleanup:
    return err;
}

static err_t do_add_modrm(
    const post_prefixes_ctx_t* ctx, const modrm_operand_t* dst, const modrm_operand_t* src
) {
    err_t err = SUCCESS;

    pis_operand_size_t operand_size = ctx->operand_sizes.insn_default_not_64_bit;
    pis_operand_t dst_tmp = PIS_OPERAND(g_src_op_1_tmp_addr, operand_size);
    pis_operand_t src_tmp = PIS_OPERAND(g_src_op_2_tmp_addr, operand_size);
    pis_operand_t res_tmp = PIS_OPERAND(g_calc_res_tmp_addr, operand_size);

    CHECK_RETHROW(modrm_operand_read(ctx, &dst_tmp, dst));
    CHECK_RETHROW(modrm_operand_read(ctx, &src_tmp, src));

    // carry flag
    LIFT_CTX_EMIT(ctx->lift_ctx, PIS_INSN3(PIS_OPCODE_UNSIGNED_CARRY, FLAGS_CF, dst_tmp, src_tmp));

    // overflow flag
    LIFT_CTX_EMIT(ctx->lift_ctx, PIS_INSN3(PIS_OPCODE_SIGNED_CARRY, FLAGS_OF, dst_tmp, src_tmp));

    // perform the actual addition
    LIFT_CTX_EMIT(ctx->lift_ctx, PIS_INSN3(PIS_OPCODE_ADD, res_tmp, dst_tmp, src_tmp));

    CHECK_RETHROW(calc_parity_zero_sign_flags(ctx, &res_tmp));

    CHECK_RETHROW(modrm_operand_write(ctx, dst, &res_tmp));

cleanup:
    return err;
}

static err_t do_sub(
    const post_prefixes_ctx_t* ctx,
    const pis_operand_t* a,
    const pis_operand_t* b,
    pis_operand_t* result
) {
    err_t err = SUCCESS;

    pis_operand_size_t operand_size = ctx->operand_sizes.insn_default_not_64_bit;
    pis_operand_t res_tmp = PIS_OPERAND(g_calc_res_tmp_addr, operand_size);

    // carry flag
    LIFT_CTX_EMIT(ctx->lift_ctx, PIS_INSN3(PIS_OPCODE_UNSIGNED_LESS_THAN, FLAGS_CF, *a, *b));

    // overflow flag
    LIFT_CTX_EMIT(ctx->lift_ctx, PIS_INSN3(PIS_OPCODE_SIGNED_BORROW, FLAGS_OF, *a, *b));

    // perform the actual subtraction
    LIFT_CTX_EMIT(ctx->lift_ctx, PIS_INSN3(PIS_OPCODE_SUB, res_tmp, *a, *b));

    CHECK_RETHROW(calc_parity_zero_sign_flags(ctx, &res_tmp));

    *result = res_tmp;

cleanup:
    return err;
}

static err_t do_sub_modrm(
    const post_prefixes_ctx_t* ctx, const modrm_operand_t* dst, const modrm_operand_t* src
) {
    err_t err = SUCCESS;

    pis_operand_size_t operand_size = ctx->operand_sizes.insn_default_not_64_bit;
    pis_operand_t dst_tmp = PIS_OPERAND(g_src_op_1_tmp_addr, operand_size);
    pis_operand_t src_tmp = PIS_OPERAND(g_src_op_2_tmp_addr, operand_size);

    CHECK_RETHROW(modrm_operand_read(ctx, &dst_tmp, dst));
    CHECK_RETHROW(modrm_operand_read(ctx, &src_tmp, src));

    pis_operand_t res_tmp = {};
    CHECK_RETHROW(do_sub(ctx, &dst_tmp, &src_tmp, &res_tmp));

    CHECK_RETHROW(modrm_operand_write(ctx, dst, &res_tmp));

cleanup:
    return err;
}

static err_t rel_jmp_fetch_disp(const post_prefixes_ctx_t* ctx, u64* disp) {
    err_t err = SUCCESS;
    pis_operand_size_t operand_size = ctx->operand_sizes.insn_default_not_64_bit;
    switch (operand_size) {
    case PIS_OPERAND_SIZE_8: {
        i32 disp32 = LIFT_CTX_CUR4_ADVANCE(ctx->lift_ctx);
        *disp = (i64) disp32;
        break;
    }
    case PIS_OPERAND_SIZE_4: {
        i32 disp32 = LIFT_CTX_CUR4_ADVANCE(ctx->lift_ctx);
        *disp = (i64) disp32;
        break;
    }
    case PIS_OPERAND_SIZE_2: {
        i16 disp16 = LIFT_CTX_CUR2_ADVANCE(ctx->lift_ctx);
        *disp = (i64) disp16;
        break;
    }
    case PIS_OPERAND_SIZE_1:
        UNREACHABLE();
    }
cleanup:
    return err;
}

static err_t rel_jmp_fetch_disp_and_calc_target(const post_prefixes_ctx_t* ctx, u64* target) {
    err_t err = SUCCESS;

    u64 disp = 0;
    CHECK_RETHROW(rel_jmp_fetch_disp(ctx, &disp));

    u64 cur_insn_end_addr = ctx->lift_ctx->cur_insn_addr + lift_ctx_index(ctx->lift_ctx);
    *target = cur_insn_end_addr + disp;

cleanup:
    return err;
}

static err_t lift_second_opcode_byte(const post_prefixes_ctx_t* ctx, u8 second_opcode_byte) {
    err_t err = SUCCESS;

    UNUSED(ctx);

    if (second_opcode_byte == 0x87) {
        // ja rel
        pis_operand_t a_tmp = PIS_OPERAND(g_src_op_1_tmp_addr, PIS_OPERAND_SIZE_1);
        pis_operand_t b_tmp = PIS_OPERAND(g_src_op_2_tmp_addr, PIS_OPERAND_SIZE_1);
        pis_operand_t res_tmp = PIS_OPERAND(g_calc_res_tmp_addr, PIS_OPERAND_SIZE_1);

        LIFT_CTX_EMIT(ctx->lift_ctx, PIS_INSN2(PIS_OPCODE_NOT, a_tmp, FLAGS_CF));
        LIFT_CTX_EMIT(ctx->lift_ctx, PIS_INSN2(PIS_OPCODE_NOT, b_tmp, FLAGS_ZF));
        LIFT_CTX_EMIT(ctx->lift_ctx, PIS_INSN3(PIS_OPCODE_AND, res_tmp, a_tmp, b_tmp));

        u64 target = 0;
        CHECK_RETHROW(rel_jmp_fetch_disp_and_calc_target(ctx, &target));

        LIFT_CTX_EMIT(
            ctx->lift_ctx,
            PIS_INSN2(PIS_OPCODE_JMP_COND, res_tmp, PIS_OPERAND_RAM(target, PIS_OPERAND_SIZE_1))
        );
    } else if (second_opcode_byte == 0x1f) {
        // xxx r/m
        modrm_t modrm = modrm_decode_byte(LIFT_CTX_CUR1_ADVANCE(ctx->lift_ctx));

        if (modrm.reg == 0) {
            // nop r/m

            // don't emit anything, this is a nop
        } else {
            CHECK_FAIL_CODE(PIS_ERR_UNSUPPORTED_INSN);
        }
    } else {
        CHECK_FAIL_TRACE_CODE(
            PIS_ERR_UNSUPPORTED_INSN,
            "unsupported second opcode byte: 0x%x",
            second_opcode_byte
        );
    }

cleanup:
    return err;
}

u8 opcode_reg_extract(const post_prefixes_ctx_t* ctx, u8 opcode_byte) {
    return apply_rex_bit_to_reg_encoding(opcode_byte & 0b111, ctx->prefixes->rex.b);
}

u8 opcode_reg_opcode_only(u8 opcode_byte) {
    return opcode_byte & (~0b111);
}

static err_t lift_first_opcode_byte(const post_prefixes_ctx_t* ctx, u8 first_opcode_byte) {
    err_t err = SUCCESS;
    modrm_operands_t modrm_operands = {};

    if (opcode_reg_opcode_only(first_opcode_byte) == 0x50) {
        // push <reg>
        u8 reg_encoding = opcode_reg_extract(ctx, first_opcode_byte);

        pis_operand_size_t operand_size = ctx->operand_sizes.insn_default_64_bit;
        pis_operand_t sp = ctx->lift_ctx->sp;
        u64 operand_size_bytes = pis_operand_size_to_bytes(operand_size);

        LIFT_CTX_EMIT(
            ctx->lift_ctx,
            PIS_INSN_ADD2(sp, PIS_OPERAND_CONST_NEG(operand_size_bytes, sp.size))
        );
        LIFT_CTX_EMIT(
            ctx->lift_ctx,
            PIS_INSN2(
                PIS_OPCODE_STORE,
                sp,
                reg_get_operand(reg_encoding, operand_size, ctx->prefixes)
            )
        );
    } else if (opcode_reg_opcode_only(first_opcode_byte) == 0x58) {
        // pop <reg>
        u8 reg_encoding = opcode_reg_extract(ctx, first_opcode_byte);

        pis_operand_size_t operand_size = ctx->operand_sizes.insn_default_64_bit;
        pis_operand_t sp = ctx->lift_ctx->sp;
        u64 operand_size_bytes = pis_operand_size_to_bytes(operand_size);

        pis_operand_t tmp = PIS_OPERAND(g_calc_res_tmp_addr, operand_size);

        LIFT_CTX_EMIT(ctx->lift_ctx, PIS_INSN2(PIS_OPCODE_LOAD, tmp, sp));

        LIFT_CTX_EMIT(
            ctx->lift_ctx,
            PIS_INSN_ADD2(sp, PIS_OPERAND_CONST(operand_size_bytes, sp.size))
        );

        LIFT_CTX_EMIT(
            ctx->lift_ctx,
            PIS_INSN2(
                PIS_OPCODE_MOVE,
                reg_get_operand(reg_encoding, operand_size, ctx->prefixes),
                tmp
            )
        );
    } else if (first_opcode_byte == 0x89) {
        // move r/m, r
        CHECK_RETHROW(modrm_fetch_and_process(ctx, &modrm_operands));
        CHECK_RETHROW(
            modrm_rm_write(ctx, &modrm_operands.rm_operand.rm, &modrm_operands.reg_operand.reg)
        );
    } else if (first_opcode_byte == 0x8b) {
        // move r, r/m
        CHECK_RETHROW(modrm_fetch_and_process(ctx, &modrm_operands));
        CHECK_RETHROW(
            modrm_rm_read(ctx, &modrm_operands.reg_operand.reg, &modrm_operands.rm_operand.rm)
        );
    } else if (first_opcode_byte == 0x63) {
        // movsxd r, r/m
        CHECK_RETHROW(modrm_fetch_and_process(ctx, &modrm_operands));
        pis_operand_size_t operand_size = ctx->operand_sizes.insn_default_not_64_bit;
        if (operand_size == PIS_OPERAND_SIZE_8) {
            pis_operand_t tmp32 = PIS_OPERAND(g_src_op_1_tmp_addr, PIS_OPERAND_SIZE_4);
            CHECK_RETHROW(modrm_rm_read(ctx, &tmp32, &modrm_operands.rm_operand.rm));
            LIFT_CTX_EMIT(
                ctx->lift_ctx,
                PIS_INSN2(PIS_OPCODE_SIGN_EXTEND, modrm_operands.reg_operand.reg, tmp32)
            );

        } else {
            // regular mov
            CHECK_RETHROW(
                modrm_rm_read(ctx, &modrm_operands.reg_operand.reg, &modrm_operands.rm_operand.rm)
            );
        }
    } else if (first_opcode_byte == 0x01) {
        // add r/m, r
        CHECK_RETHROW(modrm_fetch_and_process(ctx, &modrm_operands));
        CHECK_RETHROW(do_add_modrm(ctx, &modrm_operands.rm_operand, &modrm_operands.reg_operand));
    } else if (first_opcode_byte == 0x03) {
        // add r, r/m
        CHECK_RETHROW(modrm_fetch_and_process(ctx, &modrm_operands));
        CHECK_RETHROW(do_add_modrm(ctx, &modrm_operands.reg_operand, &modrm_operands.rm_operand));
    } else if (first_opcode_byte == 0x29) {
        // sub r/m, r
        CHECK_RETHROW(modrm_fetch_and_process(ctx, &modrm_operands));
        CHECK_RETHROW(do_sub_modrm(ctx, &modrm_operands.rm_operand, &modrm_operands.reg_operand));
    } else if (first_opcode_byte == 0x2b) {
        // sub r, r/m
        CHECK_RETHROW(modrm_fetch_and_process(ctx, &modrm_operands));
        CHECK_RETHROW(do_sub_modrm(ctx, &modrm_operands.reg_operand, &modrm_operands.rm_operand));
    } else if (first_opcode_byte == 0x8d) {
        // lea r, m

        CHECK_RETHROW(modrm_fetch_and_process(ctx, &modrm_operands));

        // the rm operand must be a memory operand in case of `lea`.
        CHECK(modrm_operands.rm_operand.rm.is_memory);

        LIFT_CTX_EMIT(
            ctx->lift_ctx,
            PIS_INSN2(
                PIS_OPCODE_MOVE,
                modrm_operands.reg_operand.reg,
                modrm_operands.rm_operand.rm.addr_or_reg
            )
        );
    } else if (first_opcode_byte == 0xff) {
        // xxx r/m
        modrm_t modrm = modrm_decode_byte(LIFT_CTX_CUR1_ADVANCE(ctx->lift_ctx));

        if (modrm.reg == 4) {
            // jmp r/m

            // decide the operand size
            pis_operand_size_t operand_size = ctx->operand_sizes.insn_default_not_64_bit;
            if (ctx->lift_ctx->pis_x86_ctx->cpumode == PIS_X86_CPUMODE_64_BIT) {
                operand_size = PIS_OPERAND_SIZE_8;
            }

            modrm_rm_operand_t rm_operand = {};
            CHECK_RETHROW(modrm_decode_rm_operand(ctx, &modrm, operand_size, &rm_operand));

            pis_operand_t rm_tmp = PIS_OPERAND(g_src_op_1_tmp_addr, operand_size);
            CHECK_RETHROW(modrm_rm_read(ctx, &rm_tmp, &rm_operand));

            LIFT_CTX_EMIT(ctx->lift_ctx, PIS_INSN1(PIS_OPCODE_JMP, rm_tmp));
        } else {
            CHECK_FAIL_CODE(PIS_ERR_UNSUPPORTED_INSN);
        }

    } else if (first_opcode_byte == 0x83) {
        // xxx r/m, imm8
        CHECK_RETHROW(modrm_fetch_and_process(ctx, &modrm_operands));

        pis_operand_size_t operand_size = ctx->operand_sizes.insn_default_not_64_bit;
        pis_operand_t rm_tmp = PIS_OPERAND(g_src_op_2_tmp_addr, operand_size);
        CHECK_RETHROW(modrm_operand_read(ctx, &rm_tmp, &modrm_operands.rm_operand));

        i8 imm8 = LIFT_CTX_CUR1_ADVANCE(ctx->lift_ctx);
        u64 imm64 = pis_sign_extend_byte(imm8, operand_size);

        if (modrm_operands.modrm.reg == 5) {
            // sub r/m, imm8
            pis_operand_t res_tmp = {};
            CHECK_RETHROW(do_sub(ctx, &rm_tmp, &PIS_OPERAND_CONST(imm64, operand_size), &res_tmp));

            CHECK_RETHROW(modrm_rm_write(ctx, &modrm_operands.rm_operand.rm, &res_tmp));
        } else {
            CHECK_FAIL_CODE(PIS_ERR_UNSUPPORTED_INSN);
        }
    } else if (first_opcode_byte == 0xe9) {
        u64 target = 0;
        CHECK_RETHROW(rel_jmp_fetch_disp_and_calc_target(ctx, &target));

        LIFT_CTX_EMIT(
            ctx->lift_ctx,
            PIS_INSN1(PIS_OPCODE_JMP, PIS_OPERAND_RAM(target, PIS_OPERAND_SIZE_1))
        );
    } else if (first_opcode_byte == 0xc3) {
        // ret
        pis_operand_size_t operand_size = ctx->lift_ctx->stack_addr_size;
        pis_operand_t sp = ctx->lift_ctx->sp;
        u64 operand_size_bytes = pis_operand_size_to_bytes(operand_size);

        pis_operand_t tmp = PIS_OPERAND(g_calc_res_tmp_addr, operand_size);

        LIFT_CTX_EMIT(ctx->lift_ctx, PIS_INSN2(PIS_OPCODE_LOAD, tmp, sp));

        LIFT_CTX_EMIT(
            ctx->lift_ctx,
            PIS_INSN_ADD2(sp, PIS_OPERAND_CONST(operand_size_bytes, sp.size))
        );

        LIFT_CTX_EMIT(ctx->lift_ctx, PIS_INSN1(PIS_OPCODE_JMP, tmp));
    } else if (first_opcode_byte == 0x0f) {
        // opcode is longer than 1 byte
        u8 second_opcode_byte = LIFT_CTX_CUR1_ADVANCE(ctx->lift_ctx);

        CHECK_RETHROW(lift_second_opcode_byte(ctx, second_opcode_byte));
    } else {
        CHECK_FAIL_TRACE_CODE(
            PIS_ERR_UNSUPPORTED_INSN,
            "unsupported first opcode byte: 0x%x",
            first_opcode_byte
        );
    }

cleanup:
    return err;
}

static err_t post_prefixes_lift(const post_prefixes_ctx_t* ctx) {
    err_t err = SUCCESS;

    u8 first_opcode_byte = LIFT_CTX_CUR1_ADVANCE(ctx->lift_ctx);

    CHECK_RETHROW(lift_first_opcode_byte(ctx, first_opcode_byte));

cleanup:
    return err;
}

static err_t lift(lift_ctx_t* ctx) {
    err_t err = SUCCESS;
    prefixes_t prefixes = {};

    CHECK_RETHROW(parse_prefixes(ctx, &prefixes));

    post_prefixes_ctx_t post_prefixes_ctx = {
        .lift_ctx = ctx,
        .prefixes = &prefixes,
        .addr_size = get_effective_addr_size(ctx->pis_x86_ctx->cpumode, &prefixes),
        .operand_sizes =
            {
                .insn_default_64_bit =
                    get_effective_operand_size(ctx->pis_x86_ctx->cpumode, &prefixes, true),
                .insn_default_not_64_bit =
                    get_effective_operand_size(ctx->pis_x86_ctx->cpumode, &prefixes, false),
            },
    };
    CHECK_RETHROW(post_prefixes_lift(&post_prefixes_ctx));

cleanup:
    return err;
}

err_t pis_x86_lift(
    const pis_x86_ctx_t* ctx,
    const u8* machine_code,
    size_t machine_code_len,
    u64 machine_code_addr,
    pis_lift_result_t* result
) {
    err_t err = SUCCESS;

    CHECK_CODE(machine_code != NULL, PIS_ERR_NULL_ARG);
    CHECK_CODE(machine_code_len > 0, PIS_ERR_EARLY_EOF);

    lift_ctx_t lift_ctx = {
        .pis_x86_ctx = ctx,
        .start = machine_code,
        .cur = machine_code,
        .end = machine_code + machine_code_len,
        .cur_insn_addr = machine_code_addr,
        .result = result,
        .stack_addr_size = get_effective_stack_addr_size(ctx->cpumode),
        .sp = get_sp_operand(ctx->cpumode),
    };
    CHECK_RETHROW(lift(&lift_ctx));

    result->machine_insn_len = lift_ctx_index(&lift_ctx);

cleanup:
    return err;
}
