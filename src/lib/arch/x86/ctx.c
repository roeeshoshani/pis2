#include "ctx.h"
#include "arch/x86/common.h"
#include "arch/x86/modrm.h"
#include "errors.h"
#include "except.h"
#include "lift_ctx.h"
#include "pis.h"
#include "prefixes.h"
#include "regs.h"

static err_t build_modrm_rm_addr_16_into(
    const post_prefixes_ctx_t* ctx, const modrm_t* modrm, const pis_operand_t* into
) {
    err_t err = SUCCESS;

    if (modrm->mod == 0b00 && modrm->rm == 0b110) {
        // 16 bit displacement only
        u16 disp = LIFT_CTX_CUR2_ADVANCE(ctx->lift_ctx);
        LIFT_CTX_EMIT(
            ctx->lift_ctx,
            PIS_INSN(PIS_OPCODE_MOVE, *into, PIS_OPERAND_CONST(disp, ctx->addr_size))
        );
    } else {
        // handle the base regs
        switch (modrm->rm) {
        case 0b000:
            LIFT_CTX_EMIT(ctx->lift_ctx, PIS_INSN(PIS_OPCODE_MOVE, *into, bx));
            LIFT_CTX_EMIT(ctx->lift_ctx, PIS_INSN(PIS_OPCODE_ADD, *into, si));
            break;
        case 0b001:
            LIFT_CTX_EMIT(ctx->lift_ctx, PIS_INSN(PIS_OPCODE_MOVE, *into, bx));
            LIFT_CTX_EMIT(ctx->lift_ctx, PIS_INSN(PIS_OPCODE_ADD, *into, di));
            break;
        case 0b010:
            LIFT_CTX_EMIT(ctx->lift_ctx, PIS_INSN(PIS_OPCODE_MOVE, *into, bp));
            LIFT_CTX_EMIT(ctx->lift_ctx, PIS_INSN(PIS_OPCODE_ADD, *into, si));
            break;
        case 0b011:
            LIFT_CTX_EMIT(ctx->lift_ctx, PIS_INSN(PIS_OPCODE_MOVE, *into, bp));
            LIFT_CTX_EMIT(ctx->lift_ctx, PIS_INSN(PIS_OPCODE_ADD, *into, di));
            break;
        case 0b100:
            LIFT_CTX_EMIT(ctx->lift_ctx, PIS_INSN(PIS_OPCODE_MOVE, *into, si));
            break;
        case 0b101:
            LIFT_CTX_EMIT(ctx->lift_ctx, PIS_INSN(PIS_OPCODE_MOVE, *into, di));
            break;
        case 0b110:
            LIFT_CTX_EMIT(ctx->lift_ctx, PIS_INSN(PIS_OPCODE_MOVE, *into, bp));
            break;
        case 0b111:
            LIFT_CTX_EMIT(ctx->lift_ctx, PIS_INSN(PIS_OPCODE_MOVE, *into, bx));
            break;
        }

        // now handle displacement
        switch (modrm->mod) {
        case 0b00:
            // no displacement
            break;
        case 0b01: {
            // 8 bit displacement
            i8 disp8 = LIFT_CTX_CUR1_ADVANCE(ctx->lift_ctx);
            // sign extend it to 16 bits
            u16 disp16 = (i16) disp8;
            LIFT_CTX_EMIT(
                ctx->lift_ctx,
                PIS_INSN(PIS_OPCODE_ADD, *into, PIS_OPERAND_CONST(disp16, ctx->addr_size))
            );
            break;
        }
        case 0b10: {
            // 16 bit displacement
            u16 disp = LIFT_CTX_CUR2_ADVANCE(ctx->lift_ctx);
            LIFT_CTX_EMIT(
                ctx->lift_ctx,
                PIS_INSN(PIS_OPCODE_ADD, *into, PIS_OPERAND_CONST(disp, ctx->addr_size))
            );
            break;
        }
        case 0b11:
            // unreachable
            CHECK_FAIL();
        }
    }
cleanup:
    return err;
}

static err_t build_modrm_rm_addr_32_into(
    const post_prefixes_ctx_t* ctx, const modrm_t* modrm, const pis_operand_t* into
) {
    err_t err = SUCCESS;

    if (modrm->rm == 0b100) {
        // SIB
        CHECK_FAIL_TRACE_CODE(PIS_ERR_UNSUPPORTED_INSN, "SIB bytes are not supported yet");
    } else if (modrm->rm == 0b100 && modrm->mod == 0b00) {
        // 32-bit displacement only
        u32 disp = LIFT_CTX_CUR4_ADVANCE(ctx->lift_ctx);
        LIFT_CTX_EMIT(
            ctx->lift_ctx,
            PIS_INSN(PIS_OPCODE_MOVE, *into, PIS_OPERAND_CONST(disp, ctx->addr_size))
        );
    } else {
        // base register encoded in rm
        reg_t base_reg = {.encoding = modrm->rm};
        pis_operand_t base_reg_operand = reg_get_operand(base_reg, ctx->addr_size, ctx->prefixes);
        LIFT_CTX_EMIT(ctx->lift_ctx, PIS_INSN(PIS_OPCODE_MOVE, *into, base_reg_operand));

        // handle displacement
        switch (modrm->mod) {
        case 0b00:
            // no displacement
            break;
        case 0b01: {
            // 8 bit displacement
            i8 disp8 = LIFT_CTX_CUR1_ADVANCE(ctx->lift_ctx);
            // sign extend it to 32 bits
            u32 disp32 = (i32) disp8;
            LIFT_CTX_EMIT(
                ctx->lift_ctx,
                PIS_INSN(PIS_OPCODE_ADD, *into, PIS_OPERAND_CONST(disp32, ctx->addr_size))
            );
            break;
        }
        case 0b10: {
            // 32 bit displacement
            u32 disp = LIFT_CTX_CUR4_ADVANCE(ctx->lift_ctx);
            LIFT_CTX_EMIT(
                ctx->lift_ctx,
                PIS_INSN(PIS_OPCODE_ADD, *into, PIS_OPERAND_CONST(disp, ctx->addr_size))
            );
            break;
        }
        case 0b11:
            // unreachable
            CHECK_FAIL();
        }
    }

cleanup:
    return err;
}

static err_t build_modrm_rm_addr_into(
    const post_prefixes_ctx_t* ctx, const modrm_t* modrm, const pis_operand_t* into
) {
    err_t err = SUCCESS;

    // make sure that the addressing mode of the r/m field is not a register, but a memory address.
    CHECK(modrm->mod != 0b11);

    switch (ctx->addr_size) {
    case PIS_OPERAND_SIZE_8:
        CHECK_FAIL();
        break;
    case PIS_OPERAND_SIZE_4:
        CHECK_RETHROW(build_modrm_rm_addr_32_into(ctx, modrm, into));
        break;
    case PIS_OPERAND_SIZE_2:
        CHECK_RETHROW(build_modrm_rm_addr_16_into(ctx, modrm, into));
        break;
    case PIS_OPERAND_SIZE_1:
        // unreachable
        CHECK_FAIL();
    }
cleanup:
    return err;
}

static err_t post_prefixes_lift(const post_prefixes_ctx_t* ctx) {
    err_t err = SUCCESS;

    u8 first_opcode_byte = LIFT_CTX_CUR1_ADVANCE(ctx->lift_ctx);

    if ((first_opcode_byte & (~0b111)) == 0x50) {
        // push <reg> instruction
        u8 reg_encoding = first_opcode_byte & 0b111;
        if (ctx->prefixes->rex.is_present) {
            // the REX.B bit is an extensions to the register
            reg_encoding |= ctx->prefixes->rex.b << 3;
        }
        reg_t reg = (reg_t) {.encoding = reg_encoding};

        pis_operand_size_t operand_size = ctx->operand_sizes.insn_default_64_bit;
        pis_operand_t sp = ctx->lift_ctx->sp;
        u64 operand_size_bytes = pis_operand_size_to_bytes(operand_size);

        LIFT_CTX_EMIT(
            ctx->lift_ctx,
            PIS_INSN(PIS_OPCODE_ADD, sp, PIS_OPERAND_CONST_NEG(operand_size_bytes, sp.size))
        );
        LIFT_CTX_EMIT(
            ctx->lift_ctx,
            PIS_INSN(PIS_OPCODE_STORE, sp, reg_get_operand(reg, operand_size, ctx->prefixes))
        );
    } else if (first_opcode_byte == 0x89) {
        // move r/m, r instruction
        modrm_t modrm = decode_modrm_byte(LIFT_CTX_CUR1_ADVANCE(ctx->lift_ctx));
        pis_operand_size_t operand_size = ctx->operand_sizes.insn_default_not_64_bit;
        if (modrm.mod == 0b11) {
            reg_t dst_reg = {.encoding = modrm.rm};
            pis_operand_t dst = reg_get_operand(dst_reg, operand_size, ctx->prefixes);

            reg_t src_reg = {.encoding = modrm.reg};
            pis_operand_t src = reg_get_operand(src_reg, operand_size, ctx->prefixes);

            LIFT_CTX_EMIT(ctx->lift_ctx, PIS_INSN(PIS_OPCODE_MOVE, dst, src));
        } else {
            pis_operand_t rm_addr_tmp = PIS_OPERAND_TMP(0, ctx->addr_size);
            CHECK_RETHROW(build_modrm_rm_addr_into(ctx, &modrm, &rm_addr_tmp));
            // CHECK_FAIL_TRACE_CODE(
            //     PIS_ERR_UNSUPPORTED_INSN,
            //     "memory access with modrm not supported"
            // );
        }
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

    CHECK_RETHROW(post_prefixes_lift(&(post_prefixes_ctx_t) {
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
    }));

cleanup:
    return err;
}

err_t pis_x86_lift(
    const pis_x86_ctx_t* ctx,
    const u8* machine_code,
    size_t machine_code_len,
    pis_lift_result_t* result
) {
    err_t err = SUCCESS;

    CHECK_CODE(machine_code != NULL, PIS_ERR_NULL_ARG);
    CHECK_CODE(machine_code_len > 0, PIS_ERR_EARLY_EOF);

    lift_ctx_t lift_ctx = {
        .pis_x86_ctx = ctx,
        .cur = machine_code,
        .end = machine_code + machine_code_len,
        .result = result,
        .stack_addr_size = get_effective_stack_addr_size(ctx->cpumode),
        .sp = get_sp_operand(ctx->cpumode),
    };
    CHECK_RETHROW(lift(&lift_ctx));

cleanup:
    return err;
}
