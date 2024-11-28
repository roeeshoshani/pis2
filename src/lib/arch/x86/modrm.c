#include "modrm.h"
#include "../../except.h"
#include "../../pis.h"
#include "../../tmp.h"
#include "ctx.h"
#include "prefixes.h"
#include "regs.h"
#include "segment_override.h"

modrm_t modrm_decode_byte(u8 modrm_byte) {
    return (modrm_t) {
        .mod = GET_BITS(modrm_byte, 6, 2),
        .reg = GET_BITS(modrm_byte, 3, 3),
        .rm = GET_BITS(modrm_byte, 0, 3),
    };
}

sib_t sib_decode_byte(u8 sib_byte) {
    return (sib_t) {
        .scale = GET_BITS(sib_byte, 6, 2),
        .index = GET_BITS(sib_byte, 3, 3),
        .base = GET_BITS(sib_byte, 0, 3),
    };
}

static err_t build_sib_addr_into(ctx_t* ctx, const modrm_t* modrm, const pis_op_t* into) {
    err_t err = SUCCESS;

    u8 sib_byte = 0;
    CHECK_RETHROW(cursor_next_1(&ctx->args->machine_code, &sib_byte));

    sib_t sib = sib_decode_byte(sib_byte);

    // handle the sib base
    if (sib.base == 0b101 && modrm->mod == 0b00) {
        // the base is a disp32
        u32 disp = 0;
        CHECK_RETHROW(cursor_next_4(&ctx->args->machine_code, &disp, PIS_ENDIANNESS_LITTLE));
        PIS_EMIT(
            &ctx->args->result,
            PIS_INSN2(PIS_OPCODE_MOVE, *into, PIS_OPERAND_IMM(disp, ctx->addr_size))
        );
    } else {
        pis_op_t base_reg_operand = reg_get_operand(
            apply_rex_bit_to_reg_encoding(sib.base, ctx->prefixes.rex.b),
            ctx->addr_size,
            &ctx->prefixes
        );
        PIS_EMIT(&ctx->args->result, PIS_INSN2(PIS_OPCODE_MOVE, *into, base_reg_operand));
    }

    // handle the scaled index
    u8 index = apply_rex_bit_to_reg_encoding(sib.index, ctx->prefixes.rex.x);
    if (index == 0b100) {
        // no index
    } else {
        // build the scaled index into a tmp
        pis_op_t sib_tmp = TMP_ALLOC(&ctx->tmp_allocator, ctx->addr_size);

        pis_op_t index_reg_operand = reg_get_operand(index, ctx->addr_size, &ctx->prefixes);
        PIS_EMIT(&ctx->args->result, PIS_INSN2(PIS_OPCODE_MOVE, sib_tmp, index_reg_operand));
        PIS_EMIT(
            &ctx->args->result,
            PIS_INSN3(
                PIS_OPCODE_UNSIGNED_MUL,
                sib_tmp,
                sib_tmp,
                PIS_OPERAND_IMM(1 << sib.scale, ctx->addr_size)
            )
        );

        // add the scaled index to the address
        PIS_EMIT(&ctx->args->result, PIS_INSN3(PIS_OPCODE_ADD, *into, *into, sib_tmp));
    }
cleanup:
    return err;
}

static err_t
    build_modrm_rm_addr_16_into(const ctx_t* ctx, const modrm_t* modrm, const pis_op_t* into) {
    err_t err = SUCCESS;

    if (modrm->mod == 0b00 && modrm->rm == 0b110) {
        // 16 bit displacement only
        u16 disp = 0;
        CHECK_RETHROW(cursor_next_2(&ctx->args->machine_code, &disp, PIS_ENDIANNESS_LITTLE));
        PIS_EMIT(
            &ctx->args->result,
            PIS_INSN2(PIS_OPCODE_MOVE, *into, PIS_OPERAND_IMM(disp, ctx->addr_size))
        );
    } else {
        // handle the base regs
        switch (modrm->rm) {
            case 0b000:
                PIS_EMIT(
                    &ctx->args->result,
                    PIS_INSN2(PIS_OPCODE_MOVE, *into, pis_reg_to_op(X86_BX))
                );
                PIS_EMIT(
                    &ctx->args->result,
                    PIS_INSN3(PIS_OPCODE_ADD, *into, *into, pis_reg_to_op(X86_SI))
                );
                break;
            case 0b001:
                PIS_EMIT(
                    &ctx->args->result,
                    PIS_INSN2(PIS_OPCODE_MOVE, *into, pis_reg_to_op(X86_BX))
                );
                PIS_EMIT(
                    &ctx->args->result,
                    PIS_INSN3(PIS_OPCODE_ADD, *into, *into, pis_reg_to_op(X86_DI))
                );
                break;
            case 0b010:
                PIS_EMIT(
                    &ctx->args->result,
                    PIS_INSN2(PIS_OPCODE_MOVE, *into, pis_reg_to_op(X86_BP))
                );
                PIS_EMIT(
                    &ctx->args->result,
                    PIS_INSN3(PIS_OPCODE_ADD, *into, *into, pis_reg_to_op(X86_SI))
                );
                break;
            case 0b011:
                PIS_EMIT(
                    &ctx->args->result,
                    PIS_INSN2(PIS_OPCODE_MOVE, *into, pis_reg_to_op(X86_BP))
                );
                PIS_EMIT(
                    &ctx->args->result,
                    PIS_INSN3(PIS_OPCODE_ADD, *into, *into, pis_reg_to_op(X86_DI))
                );
                break;
            case 0b100:
                PIS_EMIT(
                    &ctx->args->result,
                    PIS_INSN2(PIS_OPCODE_MOVE, *into, pis_reg_to_op(X86_SI))
                );
                break;
            case 0b101:
                PIS_EMIT(
                    &ctx->args->result,
                    PIS_INSN2(PIS_OPCODE_MOVE, *into, pis_reg_to_op(X86_DI))
                );
                break;
            case 0b110:
                PIS_EMIT(
                    &ctx->args->result,
                    PIS_INSN2(PIS_OPCODE_MOVE, *into, pis_reg_to_op(X86_BP))
                );
                break;
            case 0b111:
                PIS_EMIT(
                    &ctx->args->result,
                    PIS_INSN2(PIS_OPCODE_MOVE, *into, pis_reg_to_op(X86_BX))
                );
                break;
        }

        // now handle displacement
        switch (modrm->mod) {
            case 0b00:
                // no displacement
                break;
            case 0b01: {
                // 8 bit displacement, sign extended to 16-bits
                u64 disp = 0;
                CHECK_RETHROW(cursor_next_imm_ext(
                    &ctx->args->machine_code,
                    PIS_SIZE_1,
                    PIS_SIZE_2,
                    IMM_EXT_KIND_SIGN_EXTEND,
                    PIS_ENDIANNESS_LITTLE,
                    &disp
                ));
                PIS_EMIT(
                    &ctx->args->result,
                    PIS_INSN3(PIS_OPCODE_ADD, *into, *into, PIS_OPERAND_IMM(disp, ctx->addr_size))
                );
                break;
            }
            case 0b10: {
                // 16 bit displacement
                u16 disp = 0;
                CHECK_RETHROW(cursor_next_2(&ctx->args->machine_code, &disp, PIS_ENDIANNESS_LITTLE)
                );
                PIS_EMIT(
                    &ctx->args->result,
                    PIS_INSN3(PIS_OPCODE_ADD, *into, *into, PIS_OPERAND_IMM(disp, ctx->addr_size))
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

static err_t build_modrm_rm_addr_32_into(ctx_t* ctx, const modrm_t* modrm, const pis_op_t* into) {
    err_t err = SUCCESS;

    if (modrm->rm == 0b101 && modrm->mod == 0b00) {
        // 32-bit displacement only
        u32 disp = 0;
        CHECK_RETHROW(cursor_next_4(&ctx->args->machine_code, &disp, PIS_ENDIANNESS_LITTLE));
        PIS_EMIT(
            &ctx->args->result,
            PIS_INSN2(PIS_OPCODE_MOVE, *into, PIS_OPERAND_IMM(disp, ctx->addr_size))
        );
    } else {
        if (modrm->rm == 0b100) {
            CHECK_RETHROW(build_sib_addr_into(ctx, modrm, into));
        } else {
            // base register encoded in rm
            pis_op_t base_reg_operand = reg_get_operand(modrm->rm, ctx->addr_size, &ctx->prefixes);
            PIS_EMIT(&ctx->args->result, PIS_INSN2(PIS_OPCODE_MOVE, *into, base_reg_operand));
        }

        // handle displacement
        switch (modrm->mod) {
            case 0b00:
                // no displacement
                break;
            case 0b01: {
                // 8 bit displacement
                u64 disp = 0;
                CHECK_RETHROW(cursor_next_imm_ext(
                    &ctx->args->machine_code,
                    PIS_SIZE_1,
                    PIS_SIZE_4,
                    IMM_EXT_KIND_SIGN_EXTEND,
                    PIS_ENDIANNESS_LITTLE,
                    &disp
                ));
                PIS_EMIT(
                    &ctx->args->result,
                    PIS_INSN3(PIS_OPCODE_ADD, *into, *into, PIS_OPERAND_IMM(disp, PIS_SIZE_4))
                );
                break;
            }
            case 0b10: {
                // 32 bit displacement
                u32 disp = 0;
                CHECK_RETHROW(cursor_next_4(&ctx->args->machine_code, &disp, PIS_ENDIANNESS_LITTLE)
                );
                PIS_EMIT(
                    &ctx->args->result,
                    PIS_INSN3(PIS_OPCODE_ADD, *into, *into, PIS_OPERAND_IMM(disp, ctx->addr_size))
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

static err_t build_modrm_rm_addr_64_into(ctx_t* ctx, const modrm_t* modrm, const pis_op_t* into) {
    err_t err = SUCCESS;

    if (modrm->rm == 0b101 && modrm->mod == 0b00) {
        // rip relative with 32-bit displacement
        u64 disp = 0;
        CHECK_RETHROW(cursor_next_imm_ext(
            &ctx->args->machine_code,
            PIS_SIZE_4,
            PIS_SIZE_8,
            IMM_EXT_KIND_SIGN_EXTEND,
            PIS_ENDIANNESS_LITTLE,
            &disp
        ));

        u64 cur_insn_end_addr =
            ctx->args->machine_code_addr + cursor_index(&ctx->args->machine_code);
        u64 mem_addr = cur_insn_end_addr + disp;

        PIS_EMIT(
            &ctx->args->result,
            PIS_INSN2(PIS_OPCODE_MOVE, *into, PIS_OPERAND_IMM(mem_addr, ctx->addr_size))
        );
    } else {
        if (modrm->rm == 0b100) {
            CHECK_RETHROW(build_sib_addr_into(ctx, modrm, into));
        } else {
            // base register encoded in rm
            pis_op_t base_reg_operand = reg_get_operand(
                apply_rex_bit_to_reg_encoding(modrm->rm, ctx->prefixes.rex.b),
                ctx->addr_size,
                &ctx->prefixes
            );
            PIS_EMIT(&ctx->args->result, PIS_INSN2(PIS_OPCODE_MOVE, *into, base_reg_operand));
        }

        // handle displacement
        switch (modrm->mod) {
            case 0b00:
                // no displacement
                break;
            case 0b01: {
                // 8 bit displacement
                u64 disp = 0;
                CHECK_RETHROW(cursor_next_imm_ext(
                    &ctx->args->machine_code,
                    PIS_SIZE_1,
                    PIS_SIZE_8,
                    IMM_EXT_KIND_SIGN_EXTEND,
                    PIS_ENDIANNESS_LITTLE,
                    &disp
                ));
                PIS_EMIT(
                    &ctx->args->result,
                    PIS_INSN3(PIS_OPCODE_ADD, *into, *into, PIS_OPERAND_IMM(disp, ctx->addr_size))
                );
                break;
            }
            case 0b10: {
                // 32 bit displacement
                u64 disp = 0;
                CHECK_RETHROW(cursor_next_imm_ext(
                    &ctx->args->machine_code,
                    PIS_SIZE_4,
                    PIS_SIZE_8,
                    IMM_EXT_KIND_SIGN_EXTEND,
                    PIS_ENDIANNESS_LITTLE,
                    &disp
                ));
                PIS_EMIT(
                    &ctx->args->result,
                    PIS_INSN3(PIS_OPCODE_ADD, *into, *into, PIS_OPERAND_IMM(disp, ctx->addr_size))
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

static err_t build_modrm_rm_addr_into(ctx_t* ctx, const modrm_t* modrm, const pis_op_t* into) {
    err_t err = SUCCESS;

    // make sure that the addressing mode of the r/m field is not a register, but a memory address.
    CHECK(modrm->mod != 0b11);

    switch (ctx->addr_size) {
        case PIS_SIZE_8:
            CHECK_RETHROW(build_modrm_rm_addr_64_into(ctx, modrm, into));
            break;
        case PIS_SIZE_4:
            CHECK_RETHROW(build_modrm_rm_addr_32_into(ctx, modrm, into));
            break;
        case PIS_SIZE_2:
            CHECK_RETHROW(build_modrm_rm_addr_16_into(ctx, modrm, into));
            break;
        case PIS_SIZE_1:
            UNREACHABLE();
    }

    // account for segment override prefixes
    pis_op_t segment_base = {};
    if (insn_has_segment_override(ctx, &segment_base)) {
        PIS_EMIT(&ctx->args->result, PIS_INSN3(PIS_OPCODE_ADD, *into, *into, segment_base));
    }

cleanup:
    return err;
}

err_t modrm_decode_rm_operand(
    ctx_t* ctx, const modrm_t* modrm, pis_size_t operand_size, modrm_rm_operand_t* rm_operand
) {
    err_t err = SUCCESS;

    if (modrm->mod == 0b11) {
        // in this case, the r/m field is a register and not a memory operand
        pis_op_t rm_reg_operand = reg_get_operand(
            apply_rex_bit_to_reg_encoding(modrm->rm, ctx->prefixes.rex.b),
            operand_size,
            &ctx->prefixes
        );

        *rm_operand = (modrm_rm_operand_t) {
            .is_memory = false,
            .addr_or_reg = rm_reg_operand,
        };
    } else {
        // in this case, the r/m field is a memory operand
        pis_op_t rm_addr_tmp = TMP_ALLOC(&ctx->tmp_allocator, ctx->addr_size);
        CHECK_RETHROW(build_modrm_rm_addr_into(ctx, modrm, &rm_addr_tmp));

        *rm_operand = (modrm_rm_operand_t) {
            .is_memory = true,
            .addr_or_reg = rm_addr_tmp,
        };
    }

cleanup:
    return err;
}
