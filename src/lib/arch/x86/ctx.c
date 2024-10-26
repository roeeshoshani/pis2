#include "ctx.h"
#include "arch/x86/regs.h"
#include "distorm/include/distorm.h"
#include "distorm/include/mnemonics.h"
#include "except.h"
#include "pis.h"
#include "utils.h"

typedef struct {
    _DInst insn;
    pis_operand_size_t operand_size;
    pis_operand_size_t addr_size;
    u64 cur_tmp_offset;
    pis_lift_result_t* lift_result;
} ctx_t;

static inline pis_operand_size_t distorm_addr_or_operand_size_to_pis(u8 distorm_size) {
    return (pis_operand_size_t) (distorm_size + 2);
}

static inline pis_operand_size_t insn_operand_size(const _DInst* insn) {
    return distorm_addr_or_operand_size_to_pis(FLAG_GET_OPSIZE(insn->flags));
}

static inline pis_operand_size_t insn_addr_size(const _DInst* insn) {
    return distorm_addr_or_operand_size_to_pis(FLAG_GET_ADDRSIZE(insn->flags));
}

static inline err_t distorm_operand_get_size(const _Operand* operand, pis_operand_size_t* result) {
    err_t err = SUCCESS;
    CHECK_RETHROW(pis_operand_size_from_bits(operand->size, result));
cleanup:
    return err;
}

static inline err_t new_tmp(ctx_t* ctx, pis_operand_size_t size, pis_operand_t* new_tmp) {
    err_t err = SUCCESS;
    pis_operand_t result = PIS_OPERAND_TMP(ctx->cur_tmp_offset, size);

    u64 size_in_bytes = pis_operand_size_to_bytes(size);

    // make sure that we will not overflow
    CHECK_CODE(ctx->cur_tmp_offset <= UINT64_MAX - size_in_bytes, PIS_ERR_TOO_MANY_TMPS);

    ctx->cur_tmp_offset += size_in_bytes;

    *new_tmp = result;
cleanup:
    return err;
}

static err_t mem_operand_get_addr(ctx_t* ctx, const _Operand* operand, pis_operand_t* result_addr) {
    err_t err = SUCCESS;

    pis_operand_t disp = PIS_OPERAND_CONST(
        ctx->insn.disp & pis_operand_size_max_unsigned_value(ctx->addr_size),
        ctx->addr_size
    );

    switch (operand->type) {
    case O_DISP: {
        *result_addr = disp;
        break;
    }
    case O_SMEM: {
        pis_operand_t reg;
        CHECK_RETHROW(distorm_reg_to_operand(operand->index, &reg));

        pis_operand_t addr_tmp;
        CHECK_RETHROW(new_tmp(ctx, ctx->addr_size, &addr_tmp));

        PIS_LIFT_RESULT_EMIT(ctx->lift_result, PIS_INSN3(PIS_OPCODE_ADD, addr_tmp, reg, disp));

        *result_addr = addr_tmp;
        break;
    }
    case O_MEM: {
        pis_operand_t index_reg;
        CHECK_RETHROW(distorm_reg_to_operand(operand->index, &index_reg));

        pis_operand_t base_reg;
        CHECK_RETHROW(distorm_reg_to_operand(ctx->insn.base, &base_reg));

        pis_operand_t disp = PIS_OPERAND_CONST(
            ctx->insn.disp & pis_operand_size_max_unsigned_value(ctx->addr_size),
            ctx->addr_size
        );

        pis_operand_t scale = PIS_OPERAND_CONST(ctx->insn.scale, ctx->addr_size);

        pis_operand_t addr_tmp;
        CHECK_RETHROW(new_tmp(ctx, ctx->addr_size, &addr_tmp));

        // calculate the scaled index
        PIS_LIFT_RESULT_EMIT(
            ctx->lift_result,
            PIS_INSN3(PIS_OPCODE_UNSIGNED_MUL, addr_tmp, index_reg, scale)
        );

        // add base reg and disp
        PIS_LIFT_RESULT_EMIT(
            ctx->lift_result,
            PIS_INSN3(PIS_OPCODE_ADD, addr_tmp, addr_tmp, base_reg)
        );
        PIS_LIFT_RESULT_EMIT(ctx->lift_result, PIS_INSN3(PIS_OPCODE_ADD, addr_tmp, addr_tmp, disp));

        *result_addr = addr_tmp;
        break;
    }
    default:
        // not a memory operand
        UNREACHABLE();
    }

cleanup:
    return err;
}

static err_t read_operand(ctx_t* ctx, const _Operand* operand, pis_operand_t* result) {
    err_t err = SUCCESS;

    switch (operand->type) {
    case O_NONE:
        UNREACHABLE();
    case O_REG:
        CHECK_RETHROW(distorm_reg_to_operand(operand->index, result));
        CHECK(pis_operand_size_to_bits(result->size) == operand->size);
        break;
    case O_IMM: {
        *result = PIS_OPERAND_CONST(
            ctx->insn.imm.qword & pis_operand_size_max_unsigned_value(ctx->operand_size),
            ctx->operand_size
        );
        break;
    }
    case O_IMM1:
        TODO();
    case O_IMM2:
        TODO();
    case O_DISP:
        FALLTHROUGH;
    case O_SMEM:
        FALLTHROUGH;
    case O_MEM: {
        pis_operand_size_t operand_size;
        CHECK_RETHROW(distorm_operand_get_size(operand, &operand_size));

        pis_operand_t addr;
        CHECK_RETHROW(mem_operand_get_addr(ctx, operand, &addr));

        pis_operand_t load_tmp;
        CHECK_RETHROW(new_tmp(ctx, operand_size, &load_tmp));

        PIS_LIFT_RESULT_EMIT(ctx->lift_result, PIS_INSN2(PIS_OPCODE_LOAD, load_tmp, addr));

        *result = load_tmp;

        break;
    }
    case O_PC:
        TODO();
    case O_PTR:
        TODO();
    }

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

    _CodeInfo codeinfo = {
        .code = machine_code,
        .codeLen = machine_code_len,
        .codeOffset = 0,
        .dt = (_DecodeType) ctx->cpumode,
        .features = DF_NONE,
    };

    ctx_t inner_ctx = {
        .cur_tmp_offset = 0,
        .lift_result = result,
    };

    unsigned int insn_count = 0;
    _DecodeResult decode_result = distorm_decompose(&codeinfo, &inner_ctx.insn, 1, &insn_count);

    CHECK(decode_result == DECRES_SUCCESS || decode_result == DECRES_MEMORYERR);
    CHECK(insn_count == 1);
    CHECK(inner_ctx.insn.flags != FLAG_NOT_DECODABLE);

    inner_ctx.addr_size = insn_addr_size(&inner_ctx.insn);
    inner_ctx.operand_size = insn_operand_size(&inner_ctx.insn);

    result->machine_insn_len = inner_ctx.insn.size;

    UNUSED(machine_code_addr);

cleanup:
    return err;
}
