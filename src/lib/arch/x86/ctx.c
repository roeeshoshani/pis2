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
        PIS_INSN2(
            PIS_OPCODE_EQUALS,
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
    const post_prefixes_ctx_t* ctx,
    const modrm_operands_t* modrm_operands,
    pis_operand_t* addition_result
) {
    err_t err = SUCCESS;

    pis_operand_size_t operand_size = ctx->operand_sizes.insn_default_not_64_bit;
    pis_operand_t tmp = PIS_OPERAND(g_read_modify_write_tmp_addr, operand_size);

    CHECK_RETHROW(modrm_rm_read(ctx, &tmp, &modrm_operands->rm_operand));

    // carry flag
    LIFT_CTX_EMIT(
        ctx->lift_ctx,
        PIS_INSN3(PIS_OPCODE_UNSIGNED_CARRY, FLAGS_CF, tmp, modrm_operands->reg_operand)
    );

    // overflow flag
    LIFT_CTX_EMIT(
        ctx->lift_ctx,
        PIS_INSN3(PIS_OPCODE_SIGNED_CARRY, FLAGS_OF, tmp, modrm_operands->reg_operand)
    );

    // perform the actual addition
    LIFT_CTX_EMIT(ctx->lift_ctx, PIS_INSN_ADD2(tmp, modrm_operands->reg_operand));

    CHECK_RETHROW(calc_parity_zero_sign_flags(ctx, &tmp));

    *addition_result = tmp;

cleanup:
    return err;
}

static err_t post_prefixes_lift(const post_prefixes_ctx_t* ctx) {
    err_t err = SUCCESS;

    u8 first_opcode_byte = LIFT_CTX_CUR1_ADVANCE(ctx->lift_ctx);

    if ((first_opcode_byte & (~0b111)) == 0x50) {
        // push <reg>
        u8 reg_encoding =
            apply_rex_bit_to_reg_encoding(first_opcode_byte & 0b111, ctx->prefixes->rex.b);

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
    } else if (first_opcode_byte == 0x89) {
        // move r/m, r
        modrm_operands_t modrm_operands = {};
        CHECK_RETHROW(modrm_fetch_and_process(ctx, &modrm_operands));
        CHECK_RETHROW(modrm_rm_write(ctx, &modrm_operands.rm_operand, &modrm_operands.reg_operand));
    } else if (first_opcode_byte == 0x01) {
        // add r/m, r

        modrm_operands_t modrm_operands = {};
        CHECK_RETHROW(modrm_fetch_and_process(ctx, &modrm_operands));

        pis_operand_t addition_result = {};
        CHECK_RETHROW(do_add_modrm(ctx, &modrm_operands, &addition_result));

        // write the result
        CHECK_RETHROW(modrm_rm_write(ctx, &modrm_operands.rm_operand, &addition_result));
    } else if (first_opcode_byte == 0x03) {
        // add r, r/m
        modrm_operands_t modrm_operands = {};
        CHECK_RETHROW(modrm_fetch_and_process(ctx, &modrm_operands));

        pis_operand_t addition_result = {};
        CHECK_RETHROW(do_add_modrm(ctx, &modrm_operands, &addition_result));

        // write the result
        LIFT_CTX_EMIT(
            ctx->lift_ctx,
            PIS_INSN2(PIS_OPCODE_MOVE, modrm_operands.reg_operand, addition_result)
        );
    } else if (first_opcode_byte == 0x29) {
        // sub r/m, r
        modrm_operands_t modrm_operands = {};
        CHECK_RETHROW(modrm_fetch_and_process(ctx, &modrm_operands));

        pis_operand_size_t operand_size = ctx->operand_sizes.insn_default_not_64_bit;
        pis_operand_t tmp = PIS_OPERAND(g_read_modify_write_tmp_addr, operand_size);

        CHECK_RETHROW(modrm_rm_read(ctx, &tmp, &modrm_operands.rm_operand));

        // carry flag
        LIFT_CTX_EMIT(
            ctx->lift_ctx,
            PIS_INSN3(PIS_OPCODE_UNSIGNED_LESS_THAN, FLAGS_CF, tmp, modrm_operands.reg_operand)
        );

        // overflow flag
        LIFT_CTX_EMIT(
            ctx->lift_ctx,
            PIS_INSN3(PIS_OPCODE_SIGNED_LESS_THAN, FLAGS_OF, tmp, modrm_operands.reg_operand)
        );

        // perform the actual subtraction
        LIFT_CTX_EMIT(
            ctx->lift_ctx,
            PIS_INSN3(PIS_OPCODE_SUB, tmp, tmp, modrm_operands.reg_operand)
        );

        CHECK_RETHROW(calc_parity_zero_sign_flags(ctx, &tmp));

        // write the result
        CHECK_RETHROW(modrm_rm_write(ctx, &modrm_operands.rm_operand, &tmp));
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

cleanup:
    return err;
}
