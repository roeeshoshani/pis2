#include "modrm.h"
#include "../../except.h"
#include "../../pis.h"
#include "lift_ctx.h"
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

static err_t
    build_sib_addr_into(const insn_ctx_t* ctx, const modrm_t* modrm, const pis_operand_t* into) {
    err_t err = SUCCESS;
    sib_t sib = sib_decode_byte(LIFT_CTX_CUR1_ADVANCE(ctx->lift_ctx));

    // handle the sib base
    if (sib.base == 0b101 && modrm->mod == 0b00) {
        // the base is a disp32
        u32 disp = LIFT_CTX_CUR4_ADVANCE(ctx->lift_ctx);
        LIFT_CTX_EMIT(
            ctx->lift_ctx,
            PIS_INSN2(PIS_OPCODE_MOVE, *into, PIS_OPERAND_CONST(disp, ctx->addr_size))
        );
    } else {
        pis_operand_t base_reg_operand = reg_get_operand(
            apply_rex_bit_to_reg_encoding(sib.base, ctx->prefixes->rex.b),
            ctx->addr_size,
            ctx->prefixes
        );
        LIFT_CTX_EMIT(ctx->lift_ctx, PIS_INSN2(PIS_OPCODE_MOVE, *into, base_reg_operand));
    }

    // handle the scaled index
    u8 index = apply_rex_bit_to_reg_encoding(sib.index, ctx->prefixes->rex.x);
    if (index == 0b100) {
        // no index
    } else {
        // build the scaled index into a tmp
        pis_operand_t sib_tmp = LIFT_CTX_NEW_TMP(ctx->lift_ctx, ctx->addr_size);
        pis_operand_t index_reg_operand = reg_get_operand(index, ctx->addr_size, ctx->prefixes);
        LIFT_CTX_EMIT(ctx->lift_ctx, PIS_INSN2(PIS_OPCODE_MOVE, sib_tmp, index_reg_operand));
        LIFT_CTX_EMIT(
            ctx->lift_ctx,
            PIS_INSN3(
                PIS_OPCODE_UNSIGNED_MUL,
                sib_tmp,
                sib_tmp,
                PIS_OPERAND_CONST(1 << sib.scale, ctx->addr_size)
            )
        );

        // add the scaled index to the address
        LIFT_CTX_EMIT(ctx->lift_ctx, PIS_INSN3(PIS_OPCODE_ADD, *into, *into, sib_tmp));
    }
cleanup:
    return err;
}

static err_t build_modrm_rm_addr_16_into(
    const insn_ctx_t* ctx, const modrm_t* modrm, const pis_operand_t* into
) {
    err_t err = SUCCESS;

    if (modrm->mod == 0b00 && modrm->rm == 0b110) {
        // 16 bit displacement only
        u16 disp = LIFT_CTX_CUR2_ADVANCE(ctx->lift_ctx);
        LIFT_CTX_EMIT(
            ctx->lift_ctx,
            PIS_INSN2(PIS_OPCODE_MOVE, *into, PIS_OPERAND_CONST(disp, ctx->addr_size))
        );
    } else {
        // handle the base regs
        switch (modrm->rm) {
        case 0b000:
            LIFT_CTX_EMIT(ctx->lift_ctx, PIS_INSN2(PIS_OPCODE_MOVE, *into, BX));
            LIFT_CTX_EMIT(ctx->lift_ctx, PIS_INSN3(PIS_OPCODE_ADD, *into, *into, SI));
            break;
        case 0b001:
            LIFT_CTX_EMIT(ctx->lift_ctx, PIS_INSN2(PIS_OPCODE_MOVE, *into, BX));
            LIFT_CTX_EMIT(ctx->lift_ctx, PIS_INSN3(PIS_OPCODE_ADD, *into, *into, DI));
            break;
        case 0b010:
            LIFT_CTX_EMIT(ctx->lift_ctx, PIS_INSN2(PIS_OPCODE_MOVE, *into, BP));
            LIFT_CTX_EMIT(ctx->lift_ctx, PIS_INSN3(PIS_OPCODE_ADD, *into, *into, SI));
            break;
        case 0b011:
            LIFT_CTX_EMIT(ctx->lift_ctx, PIS_INSN2(PIS_OPCODE_MOVE, *into, BP));
            LIFT_CTX_EMIT(ctx->lift_ctx, PIS_INSN3(PIS_OPCODE_ADD, *into, *into, DI));
            break;
        case 0b100:
            LIFT_CTX_EMIT(ctx->lift_ctx, PIS_INSN2(PIS_OPCODE_MOVE, *into, SI));
            break;
        case 0b101:
            LIFT_CTX_EMIT(ctx->lift_ctx, PIS_INSN2(PIS_OPCODE_MOVE, *into, DI));
            break;
        case 0b110:
            LIFT_CTX_EMIT(ctx->lift_ctx, PIS_INSN2(PIS_OPCODE_MOVE, *into, BP));
            break;
        case 0b111:
            LIFT_CTX_EMIT(ctx->lift_ctx, PIS_INSN2(PIS_OPCODE_MOVE, *into, BX));
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
                PIS_INSN3(PIS_OPCODE_ADD, *into, *into, PIS_OPERAND_CONST(disp16, ctx->addr_size))
            );
            break;
        }
        case 0b10: {
            // 16 bit displacement
            u16 disp = LIFT_CTX_CUR2_ADVANCE(ctx->lift_ctx);
            LIFT_CTX_EMIT(
                ctx->lift_ctx,
                PIS_INSN3(PIS_OPCODE_ADD, *into, *into, PIS_OPERAND_CONST(disp, ctx->addr_size))
            );
            break;
        }
        case 0b11:
            UNREACHABLE();
        }
    }
cleanup:
    return err;
}

static err_t build_modrm_rm_addr_32_into(
    const insn_ctx_t* ctx, const modrm_t* modrm, const pis_operand_t* into
) {
    err_t err = SUCCESS;

    if (modrm->rm == 0b101 && modrm->mod == 0b00) {
        // 32-bit displacement only
        u32 disp = LIFT_CTX_CUR4_ADVANCE(ctx->lift_ctx);
        LIFT_CTX_EMIT(
            ctx->lift_ctx,
            PIS_INSN2(PIS_OPCODE_MOVE, *into, PIS_OPERAND_CONST(disp, ctx->addr_size))
        );
    } else {
        if (modrm->rm == 0b100) {
            CHECK_RETHROW(build_sib_addr_into(ctx, modrm, into));
        } else {
            // base register encoded in rm
            pis_operand_t base_reg_operand =
                reg_get_operand(modrm->rm, ctx->addr_size, ctx->prefixes);
            LIFT_CTX_EMIT(ctx->lift_ctx, PIS_INSN2(PIS_OPCODE_MOVE, *into, base_reg_operand));
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
                PIS_INSN3(PIS_OPCODE_ADD, *into, *into, PIS_OPERAND_CONST(disp32, ctx->addr_size))
            );
            break;
        }
        case 0b10: {
            // 32 bit displacement
            u32 disp = LIFT_CTX_CUR4_ADVANCE(ctx->lift_ctx);
            LIFT_CTX_EMIT(
                ctx->lift_ctx,
                PIS_INSN3(PIS_OPCODE_ADD, *into, *into, PIS_OPERAND_CONST(disp, ctx->addr_size))
            );
            break;
        }
        case 0b11:
            UNREACHABLE();
        }
    }

cleanup:
    return err;
}

static err_t build_modrm_rm_addr_64_into(
    const insn_ctx_t* ctx, const modrm_t* modrm, const pis_operand_t* into
) {
    err_t err = SUCCESS;

    if (modrm->rm == 0b101 && modrm->mod == 0b00) {
        // rip relative with 32-bit displacement
        i32 disp32 = LIFT_CTX_CUR4_ADVANCE(ctx->lift_ctx);
        // sign extend it to 64 bits
        u64 disp64 = (i64) disp32;

        u64 cur_insn_end_addr = ctx->lift_ctx->cur_insn_addr + lift_ctx_index(ctx->lift_ctx);
        u64 mem_addr = cur_insn_end_addr + disp64;

        LIFT_CTX_EMIT(
            ctx->lift_ctx,
            PIS_INSN2(PIS_OPCODE_MOVE, *into, PIS_OPERAND_CONST(mem_addr, ctx->addr_size))
        );
    } else {
        if (modrm->rm == 0b100) {
            CHECK_RETHROW(build_sib_addr_into(ctx, modrm, into));
        } else {
            // base register encoded in rm
            pis_operand_t base_reg_operand = reg_get_operand(
                apply_rex_bit_to_reg_encoding(modrm->rm, ctx->prefixes->rex.b),
                ctx->addr_size,
                ctx->prefixes
            );
            LIFT_CTX_EMIT(ctx->lift_ctx, PIS_INSN2(PIS_OPCODE_MOVE, *into, base_reg_operand));
        }

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
                PIS_INSN3(PIS_OPCODE_ADD, *into, *into, PIS_OPERAND_CONST(disp64, ctx->addr_size))
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
                PIS_INSN3(PIS_OPCODE_ADD, *into, *into, PIS_OPERAND_CONST(disp64, ctx->addr_size))
            );
            break;
        }
        case 0b11:
            UNREACHABLE();
        }
    }

cleanup:
    return err;
}

static err_t build_modrm_rm_addr_into(
    const insn_ctx_t* ctx, const modrm_t* modrm, const pis_operand_t* into
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
        UNREACHABLE();
    }
cleanup:
    return err;
}

err_t modrm_decode_rm_operand(
    const insn_ctx_t* ctx,
    const modrm_t* modrm,
    pis_operand_size_t operand_size,
    modrm_rm_operand_t* rm_operand
) {
    err_t err = SUCCESS;

    if (modrm->mod == 0b11) {
        // in this case, the r/m field is a register and not a memory operand
        pis_operand_t rm_reg_operand = reg_get_operand(
            apply_rex_bit_to_reg_encoding(modrm->rm, ctx->prefixes->rex.b),
            operand_size,
            ctx->prefixes
        );

        *rm_operand = (modrm_rm_operand_t) {
            .is_memory = false,
            .addr_or_reg = rm_reg_operand,
        };
    } else {
        // in this case, the r/m field is a memory operand
        pis_operand_t rm_addr_tmp = LIFT_CTX_NEW_TMP(ctx->lift_ctx, ctx->addr_size);
        CHECK_RETHROW(build_modrm_rm_addr_into(ctx, modrm, &rm_addr_tmp));

        *rm_operand = (modrm_rm_operand_t) {
            .is_memory = true,
            .addr_or_reg = rm_addr_tmp,
        };
    }

cleanup:
    return err;
}

err_t modrm_fetch_and_process_with_operand_sizes(
    const insn_ctx_t* ctx,
    modrm_operands_t* operands,
    pis_operand_size_t rm_size,
    pis_operand_size_t reg_size
) {
    err_t err = SUCCESS;

    modrm_t modrm = modrm_decode_byte(LIFT_CTX_CUR1_ADVANCE(ctx->lift_ctx));

    u8 reg_encoding = apply_rex_bit_to_reg_encoding(modrm.reg, ctx->prefixes->rex.r);
    pis_operand_t reg_operand = reg_get_operand(reg_encoding, reg_size, ctx->prefixes);

    modrm_rm_operand_t rm_operand = {};
    CHECK_RETHROW(modrm_decode_rm_operand(ctx, &modrm, rm_size, &rm_operand));

    *operands = (modrm_operands_t) {
        .reg_operand =
            {
                .type = MODRM_OPERAND_TYPE_REG,
                .reg = reg_operand,
            },
        .rm_operand =
            {
                .type = MODRM_OPERAND_TYPE_RM,
                .rm = rm_operand,
            },
        .modrm = modrm,
    };

cleanup:
    return err;
}

err_t modrm_fetch_and_process(const insn_ctx_t* ctx, modrm_operands_t* operands) {
    err_t err = SUCCESS;

    pis_operand_size_t operand_size = ctx->operand_sizes.insn_default_not_64_bit;
    CHECK_RETHROW(
        modrm_fetch_and_process_with_operand_sizes(ctx, operands, operand_size, operand_size)
    );

cleanup:
    return err;
}

err_t modrm_rm_write(
    const insn_ctx_t* ctx, const modrm_rm_operand_t* rm_operand, const pis_operand_t* to_write
) {
    err_t err = SUCCESS;

    if (rm_operand->is_memory) {
        LIFT_CTX_EMIT(
            ctx->lift_ctx,
            PIS_INSN2(PIS_OPCODE_STORE, rm_operand->addr_or_reg, *to_write)
        );
    } else {
        CHECK_RETHROW(write_gpr(ctx, &rm_operand->addr_or_reg, to_write));
    }

cleanup:
    return err;
}

err_t modrm_rm_read(
    const insn_ctx_t* ctx, const pis_operand_t* read_into, const modrm_rm_operand_t* rm_operand
) {
    err_t err = SUCCESS;

    LIFT_CTX_EMIT(
        ctx->lift_ctx,
        PIS_INSN2(
            rm_operand->is_memory ? PIS_OPCODE_LOAD : PIS_OPCODE_MOVE,
            *read_into,
            rm_operand->addr_or_reg
        )
    );

cleanup:
    return err;
}

err_t modrm_operand_read(
    const insn_ctx_t* ctx, const pis_operand_t* read_into, const modrm_operand_t* operand
) {
    err_t err = SUCCESS;

    switch (operand->type) {
    case MODRM_OPERAND_TYPE_REG:
        LIFT_CTX_EMIT(ctx->lift_ctx, PIS_INSN2(PIS_OPCODE_MOVE, *read_into, operand->reg));
        break;
    case MODRM_OPERAND_TYPE_RM:
        CHECK_RETHROW(modrm_rm_read(ctx, read_into, &operand->rm));
        break;
    default:
        UNREACHABLE();
    }

cleanup:
    return err;
}

err_t modrm_operand_write(
    const insn_ctx_t* ctx, const modrm_operand_t* operand, const pis_operand_t* to_write
) {
    err_t err = SUCCESS;

    switch (operand->type) {
    case MODRM_OPERAND_TYPE_REG:
        CHECK_RETHROW(write_gpr(ctx, &operand->reg, to_write));
        break;
    case MODRM_OPERAND_TYPE_RM:
        CHECK_RETHROW(modrm_rm_write(ctx, &operand->rm, to_write));
        break;
    default:
        UNREACHABLE();
    }

cleanup:
    return err;
}
