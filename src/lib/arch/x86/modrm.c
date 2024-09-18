#include "modrm.h"
#include "regs.h"

modrm_t modrm_decode_byte(u8 modrm_byte) {
    return (modrm_t) {
        .mod = modrm_byte >> 6,
        .reg = (modrm_byte >> 3) & 0b111,
        .rm = modrm_byte & 0b111,
    };
}


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
    } else if (modrm->rm == 0b101 && modrm->mod == 0b00) {
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

err_t modrm_fetch_and_process(const post_prefixes_ctx_t* ctx, modrm_operands_t* operands) {
    err_t err = SUCCESS;

    modrm_t modrm = modrm_decode_byte(LIFT_CTX_CUR1_ADVANCE(ctx->lift_ctx));
    pis_operand_size_t operand_size = ctx->operand_sizes.insn_default_not_64_bit;

    reg_t reg = {.encoding = modrm.reg};
    pis_operand_t reg_operand = reg_get_operand(reg, operand_size, ctx->prefixes);

    if (modrm.mod == 0b11) {
        reg_t rm_reg = {.encoding = modrm.rm};
        pis_operand_t rm_operand = reg_get_operand(rm_reg, operand_size, ctx->prefixes);

        operands->reg_operand = reg_operand;
        operands->rm_operand.addr_or_reg = rm_operand;
        operands->rm_operand.is_memory = false;
    } else {
        pis_operand_t rm_addr_tmp = PIS_OPERAND_TMP(0, ctx->addr_size);
        CHECK_RETHROW(build_modrm_rm_addr_into(ctx, &modrm, &rm_addr_tmp));

        operands->reg_operand = reg_operand;
        operands->rm_operand.addr_or_reg = rm_addr_tmp;
        operands->rm_operand.is_memory = true;
    }

cleanup:
    return err;
}
