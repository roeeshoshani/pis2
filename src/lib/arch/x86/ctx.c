#include "ctx.h"
#include "arch/x86/regs.h"
#include "distorm/include/distorm.h"
#include "distorm/include/mnemonics.h"
#include "except.h"
#include "pis.h"

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

static inline err_t __attribute__((unused))
distorm_operand_get_size(const _Operand* operand, pis_operand_size_t* result) {
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

static err_t __attribute__((unused))
read_operand(ctx_t* ctx, const _Operand* operand, pis_operand_t* result) {
    err_t err = SUCCESS;

    switch (operand->type) {
    case O_NONE:
        UNREACHABLE();
        break;
    case O_REG:
        CHECK_RETHROW(reg_get_operand(operand->index, result));
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
    case O_DISP: {
        pis_operand_t addr = PIS_OPERAND_CONST(
            ctx->insn.disp & pis_operand_size_max_unsigned_value(ctx->addr_size),
            ctx->addr_size
        );

        pis_operand_t load_tmp;
        CHECK_RETHROW(new_tmp(ctx, ctx->addr_size, &load_tmp));

        PIS_LIFT_RESULT_EMIT(ctx->lift_result, PIS_INSN2(PIS_OPCODE_LOAD, load_tmp, addr));

        *result = load_tmp;
        break;
    }
    case O_SMEM:
        break;
    case O_MEM:
        break;
    case O_PC:
        break;
    case O_PTR:
        TODO();
        break;
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
