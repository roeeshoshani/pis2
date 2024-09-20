#include "modrm.h"
#include "arch/x86/tmps.h"
#include "lift_ctx.h"
#include "pis.h"
#include "prefixes.h"
#include "regs.h"

modrm_t modrm_decode_byte(u8 modrm_byte) {
    return (modrm_t) {
        .mod = modrm_byte >> 6,
        .reg = (modrm_byte >> 3) & 0b111,
        .rm = modrm_byte & 0b111,
    };
}

sib_t sib_decode_byte(u8 sib_byte) {
    return (sib_t) {
        .scale = sib_byte >> 6,
        .index = (sib_byte >> 3) & 0b111,
        .base = sib_byte & 0b111,
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
            LIFT_CTX_EMIT(ctx->lift_ctx, PIS_INSN(PIS_OPCODE_MOVE, *into, BX));
            LIFT_CTX_EMIT(ctx->lift_ctx, PIS_INSN(PIS_OPCODE_ADD, *into, SI));
            break;
        case 0b001:
            LIFT_CTX_EMIT(ctx->lift_ctx, PIS_INSN(PIS_OPCODE_MOVE, *into, BX));
            LIFT_CTX_EMIT(ctx->lift_ctx, PIS_INSN(PIS_OPCODE_ADD, *into, DI));
            break;
        case 0b010:
            LIFT_CTX_EMIT(ctx->lift_ctx, PIS_INSN(PIS_OPCODE_MOVE, *into, BP));
            LIFT_CTX_EMIT(ctx->lift_ctx, PIS_INSN(PIS_OPCODE_ADD, *into, SI));
            break;
        case 0b011:
            LIFT_CTX_EMIT(ctx->lift_ctx, PIS_INSN(PIS_OPCODE_MOVE, *into, BP));
            LIFT_CTX_EMIT(ctx->lift_ctx, PIS_INSN(PIS_OPCODE_ADD, *into, DI));
            break;
        case 0b100:
            LIFT_CTX_EMIT(ctx->lift_ctx, PIS_INSN(PIS_OPCODE_MOVE, *into, SI));
            break;
        case 0b101:
            LIFT_CTX_EMIT(ctx->lift_ctx, PIS_INSN(PIS_OPCODE_MOVE, *into, DI));
            break;
        case 0b110:
            LIFT_CTX_EMIT(ctx->lift_ctx, PIS_INSN(PIS_OPCODE_MOVE, *into, BP));
            break;
        case 0b111:
            LIFT_CTX_EMIT(ctx->lift_ctx, PIS_INSN(PIS_OPCODE_MOVE, *into, BX));
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

    if (modrm->rm == 0b101 && modrm->mod == 0b00) {
        // 32-bit displacement only
        u32 disp = LIFT_CTX_CUR4_ADVANCE(ctx->lift_ctx);
        LIFT_CTX_EMIT(
            ctx->lift_ctx,
            PIS_INSN(PIS_OPCODE_MOVE, *into, PIS_OPERAND_CONST(disp, ctx->addr_size))
        );
    } else {
        if (modrm->rm == 0b100) {
            // SIB
            sib_t sib = sib_decode_byte(LIFT_CTX_CUR1_ADVANCE(ctx->lift_ctx));

            // handle the sib base
            if (sib.base == 0b101 && modrm->mod == 0b00) {
                // the base is a disp32
                u32 disp = LIFT_CTX_CUR4_ADVANCE(ctx->lift_ctx);
                LIFT_CTX_EMIT(
                    ctx->lift_ctx,
                    PIS_INSN(PIS_OPCODE_MOVE, *into, PIS_OPERAND_CONST(disp, ctx->addr_size))
                );
            } else {
                pis_operand_t base_reg_operand =
                    reg_get_operand(sib.base, ctx->addr_size, ctx->prefixes);
                LIFT_CTX_EMIT(ctx->lift_ctx, PIS_INSN(PIS_OPCODE_MOVE, *into, base_reg_operand));
            }

            // handle the scaled index
            if (sib.index == 0b100) {
                // no index
            } else {
                // build the scaled index into a tmp
                pis_operand_t sib_tmp = PIS_OPERAND(g_sib_index_tmp_addr, ctx->addr_size);
                pis_operand_t index_reg_operand =
                    reg_get_operand(sib.index, ctx->addr_size, ctx->prefixes);
                LIFT_CTX_EMIT(ctx->lift_ctx, PIS_INSN(PIS_OPCODE_MOVE, sib_tmp, index_reg_operand));
                LIFT_CTX_EMIT(
                    ctx->lift_ctx,
                    PIS_INSN(
                        PIS_OPCODE_MUL,
                        sib_tmp,
                        PIS_OPERAND_CONST(1 << sib.scale, ctx->addr_size)
                    )
                );

                // add the scaled index to the address
                LIFT_CTX_EMIT(ctx->lift_ctx, PIS_INSN(PIS_OPCODE_ADD, *into, sib_tmp));
            }
        } else {
            // base register encoded in rm
            pis_operand_t base_reg_operand =
                reg_get_operand(modrm->rm, ctx->addr_size, ctx->prefixes);
            LIFT_CTX_EMIT(ctx->lift_ctx, PIS_INSN(PIS_OPCODE_MOVE, *into, base_reg_operand));
        }

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

static err_t build_modrm_rm_addr_64_into(
    const post_prefixes_ctx_t* ctx, const modrm_t* modrm, const pis_operand_t* into
) {
    err_t err = SUCCESS;

    if (modrm->rm == 0b100) {
        // SIB
        CHECK_FAIL_TRACE_CODE(PIS_ERR_UNSUPPORTED_INSN, "SIB bytes are not supported yet");
    } else if (modrm->rm == 0b101 && modrm->mod == 0b00) {
        // rip relative with 32-bit displacement
        i32 disp32 = LIFT_CTX_CUR4_ADVANCE(ctx->lift_ctx);
        // sign extend it to 64 bits
        u64 disp64 = (i64) disp32;
        UNUSED(disp64);
        CHECK_FAIL_TRACE("rip-relative not supported yet");
    } else {
        // base register encoded in rm
        pis_operand_t base_reg_operand = reg_get_operand(
            apply_rex_bit_to_reg_encoding(modrm->rm, ctx->prefixes->rex.b),
            ctx->addr_size,
            ctx->prefixes
        );
        LIFT_CTX_EMIT(ctx->lift_ctx, PIS_INSN(PIS_OPCODE_MOVE, *into, base_reg_operand));

        // handle displacement
        switch (modrm->mod) {
        case 0b00:
            // no displacement
            break;
        case 0b01: {
            // 8 bit displacement
            i8 disp8 = LIFT_CTX_CUR1_ADVANCE(ctx->lift_ctx);
            // sign extend it to 64 bits
            u64 disp64 = (i64) disp8;
            LIFT_CTX_EMIT(
                ctx->lift_ctx,
                PIS_INSN(PIS_OPCODE_ADD, *into, PIS_OPERAND_CONST(disp64, ctx->addr_size))
            );
            break;
        }
        case 0b10: {
            // 32 bit displacement
            i32 disp32 = LIFT_CTX_CUR4_ADVANCE(ctx->lift_ctx);
            // sign extend it to 64 bits
            u64 disp64 = (i64) disp32;
            LIFT_CTX_EMIT(
                ctx->lift_ctx,
                PIS_INSN(PIS_OPCODE_ADD, *into, PIS_OPERAND_CONST(disp64, ctx->addr_size))
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
        CHECK_RETHROW(build_modrm_rm_addr_64_into(ctx, modrm, into));
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

    pis_operand_t reg_operand = reg_get_operand(
        apply_rex_bit_to_reg_encoding(modrm.reg, ctx->prefixes->rex.r),
        operand_size,
        ctx->prefixes
    );

    if (modrm.mod == 0b11) {
        // in this case, the r/m field is a register and not a memory operand
        pis_operand_t rm_operand = reg_get_operand(
            apply_rex_bit_to_reg_encoding(modrm.rm, ctx->prefixes->rex.b),
            operand_size,
            ctx->prefixes
        );

        operands->reg_operand = reg_operand;
        operands->rm_operand.addr_or_reg = rm_operand;
        operands->rm_operand.is_memory = false;
    } else {
        // in this case, the r/m field is a memory operand
        pis_operand_t rm_addr_tmp = PIS_OPERAND_TMP(0, ctx->addr_size);
        CHECK_RETHROW(build_modrm_rm_addr_into(ctx, &modrm, &rm_addr_tmp));

        operands->reg_operand = reg_operand;
        operands->rm_operand.addr_or_reg = rm_addr_tmp;
        operands->rm_operand.is_memory = true;
    }

cleanup:
    return err;
}
