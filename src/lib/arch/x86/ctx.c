#include "ctx.h"
#include "errors.h"
#include "except.h"
#include "lift_ctx.h"
#include "modrm.h"
#include "pis.h"
#include "prefixes.h"
#include "regs.h"

/// the maximum value of a condition encoding.
#define X86_COND_ENCODING_MAX_VALUE (0xf)

typedef enum {
    X86_COND_CLASS_OVERFLOW,
    X86_COND_CLASS_BELOW,
    X86_COND_CLASS_EQUALS,
    X86_COND_CLASS_BELOW_EQUAL,
    X86_COND_CLASS_SIGN,
    X86_COND_CLASS_PARITY,
    X86_COND_CLASS_LOWER,
    X86_COND_CLASS_LOWER_EQUAL,
} x86_cond_kind_t;

typedef struct {
    x86_cond_kind_t kind;
    bool is_negative;
} x86_cond_t;

static err_t cond_decode(u8 cond_encoding, x86_cond_t* cond) {
    err_t err = SUCCESS;

    CHECK(cond_encoding <= X86_COND_ENCODING_MAX_VALUE);

    cond->is_negative = cond_encoding & 1;
    cond->kind = cond_encoding >> 1;

cleanup:
    return err;
}

static err_t cond_negate(
    const post_prefixes_ctx_t* ctx, const pis_operand_t* cond, const pis_operand_t* result
) {
    err_t err = SUCCESS;

    CHECK(cond->size == PIS_OPERAND_SIZE_1);
    CHECK(result->size == PIS_OPERAND_SIZE_1);

    // condition negation is done by `XOR`ing with 1.
    // we can't use `NOT` because it flips all bits, not only the lowest bit.
    LIFT_CTX_EMIT(
        ctx->lift_ctx,
        PIS_INSN3(PIS_OPCODE_XOR, *result, *cond, PIS_OPERAND_CONST(1, PIS_OPERAND_SIZE_1))
    );

cleanup:
    return err;
}

static err_t
    calc_cond(const post_prefixes_ctx_t* ctx, const x86_cond_t cond, pis_operand_t* result) {
    err_t err = SUCCESS;

    pis_operand_t tmp = LIFT_CTX_NEW_TMP(ctx->lift_ctx, PIS_OPERAND_SIZE_1);

    switch (cond.kind) {
    case X86_COND_CLASS_OVERFLOW:
        LIFT_CTX_EMIT(ctx->lift_ctx, PIS_INSN2(PIS_OPCODE_MOVE, tmp, FLAGS_OF));
        break;
    case X86_COND_CLASS_BELOW:
        LIFT_CTX_EMIT(ctx->lift_ctx, PIS_INSN2(PIS_OPCODE_MOVE, tmp, FLAGS_CF));
        break;
    case X86_COND_CLASS_EQUALS:
        LIFT_CTX_EMIT(ctx->lift_ctx, PIS_INSN2(PIS_OPCODE_MOVE, tmp, FLAGS_ZF));
        break;
    case X86_COND_CLASS_BELOW_EQUAL:
        LIFT_CTX_EMIT(ctx->lift_ctx, PIS_INSN3(PIS_OPCODE_OR, tmp, FLAGS_ZF, FLAGS_CF));
        break;
    case X86_COND_CLASS_SIGN:
        LIFT_CTX_EMIT(ctx->lift_ctx, PIS_INSN2(PIS_OPCODE_MOVE, tmp, FLAGS_SF));
        break;
    case X86_COND_CLASS_PARITY:
        LIFT_CTX_EMIT(ctx->lift_ctx, PIS_INSN2(PIS_OPCODE_MOVE, tmp, FLAGS_PF));
        break;
    case X86_COND_CLASS_LOWER:
        LIFT_CTX_EMIT(ctx->lift_ctx, PIS_INSN3(PIS_OPCODE_XOR, tmp, FLAGS_SF, FLAGS_OF));
        break;
    case X86_COND_CLASS_LOWER_EQUAL: {
        pis_operand_t inner_tmp = LIFT_CTX_NEW_TMP(ctx->lift_ctx, PIS_OPERAND_SIZE_1);
        LIFT_CTX_EMIT(ctx->lift_ctx, PIS_INSN3(PIS_OPCODE_XOR, inner_tmp, FLAGS_SF, FLAGS_OF));
        LIFT_CTX_EMIT(ctx->lift_ctx, PIS_INSN3(PIS_OPCODE_OR, tmp, inner_tmp, FLAGS_ZF));
        break;
    }
    default:
        UNREACHABLE();
    }

    if (cond.is_negative) {
        pis_operand_t negated = LIFT_CTX_NEW_TMP(ctx->lift_ctx, PIS_OPERAND_SIZE_1);
        CHECK_RETHROW(cond_negate(ctx, &tmp, &negated));
        *result = negated;
    } else {
        *result = tmp;
    }

cleanup:
    return err;
}

static err_t
    cond_decode_and_calc(const post_prefixes_ctx_t* ctx, u8 cond_encoding, pis_operand_t* result) {
    err_t err = SUCCESS;

    x86_cond_t cond = {};
    CHECK_RETHROW(cond_decode(cond_encoding, &cond));

    CHECK_RETHROW(calc_cond(ctx, cond, result));

cleanup:
    return err;
}

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

static pis_operand_t get_ax_operand_of_size(pis_operand_size_t size) {
    return PIS_OPERAND_REG(0, size);
}

static pis_operand_t get_dx_operand_of_size(pis_operand_size_t size) {
    return PIS_OPERAND_REG(0b010 * 8, size);
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


static err_t calc_parity_flag_into(
    const post_prefixes_ctx_t* ctx, const pis_operand_t* value, const pis_operand_t* result
) {
    err_t err = SUCCESS;

    pis_operand_t low_byte_tmp = LIFT_CTX_NEW_TMP(ctx->lift_ctx, PIS_OPERAND_SIZE_1);
    LIFT_CTX_EMIT(ctx->lift_ctx, PIS_INSN2(PIS_OPCODE_GET_LOW_BITS, low_byte_tmp, *value));
    LIFT_CTX_EMIT(ctx->lift_ctx, PIS_INSN2(PIS_OPCODE_PARITY, *result, low_byte_tmp));

cleanup:
    return err;
}

static err_t
    calc_parity_flag(const post_prefixes_ctx_t* ctx, const pis_operand_t* calculation_result) {
    err_t err = SUCCESS;

    CHECK_RETHROW(calc_parity_flag_into(ctx, calculation_result, &FLAGS_PF));

cleanup:
    return err;
}

static err_t calc_zero_flag_into(
    const post_prefixes_ctx_t* ctx, const pis_operand_t* value, const pis_operand_t* result
) {
    err_t err = SUCCESS;

    LIFT_CTX_EMIT(
        ctx->lift_ctx,
        PIS_INSN3(PIS_OPCODE_EQUALS, *result, *value, PIS_OPERAND_CONST(0, value->size))
    );

cleanup:
    return err;
}

static err_t
    calc_zero_flag(const post_prefixes_ctx_t* ctx, const pis_operand_t* calculation_result) {
    err_t err = SUCCESS;

    CHECK_RETHROW(calc_zero_flag_into(ctx, calculation_result, &FLAGS_ZF));

cleanup:
    return err;
}

static err_t extract_most_significant_bit(
    const post_prefixes_ctx_t* ctx, const pis_operand_t* value, const pis_operand_t* result
) {
    err_t err = SUCCESS;

    // make sure that the output operand is a 1 byte conditional expression
    CHECK(result->size == PIS_OPERAND_SIZE_1);

    u64 shift_amount = pis_operand_size_to_bits(value->size) - 1;

    pis_operand_t tmp = LIFT_CTX_NEW_TMP(ctx->lift_ctx, value->size);
    LIFT_CTX_EMIT(
        ctx->lift_ctx,
        PIS_INSN3(PIS_OPCODE_SHIFT_RIGHT, tmp, *value, PIS_OPERAND_CONST(shift_amount, value->size))
    );

    LIFT_CTX_EMIT(ctx->lift_ctx, PIS_INSN2(PIS_OPCODE_GET_LOW_BITS, *result, tmp));

cleanup:
    return err;
}

static err_t extract_least_significant_bit(
    const post_prefixes_ctx_t* ctx, const pis_operand_t* value, const pis_operand_t* result
) {
    err_t err = SUCCESS;

    // make sure that the output operand is a 1 byte conditional expression
    CHECK(result->size == PIS_OPERAND_SIZE_1);

    pis_operand_t tmp = LIFT_CTX_NEW_TMP(ctx->lift_ctx, value->size);
    LIFT_CTX_EMIT(
        ctx->lift_ctx,
        PIS_INSN3(PIS_OPCODE_AND, tmp, *value, PIS_OPERAND_CONST(1, value->size))
    );

    LIFT_CTX_EMIT(ctx->lift_ctx, PIS_INSN2(PIS_OPCODE_GET_LOW_BITS, *result, tmp));

cleanup:
    return err;
}

static err_t
    calc_sign_flag(const post_prefixes_ctx_t* ctx, const pis_operand_t* calculation_result) {
    err_t err = SUCCESS;

    CHECK_RETHROW(extract_most_significant_bit(ctx, calculation_result, &FLAGS_SF));

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

static err_t do_add(
    const post_prefixes_ctx_t* ctx,
    const pis_operand_t* a,
    const pis_operand_t* b,
    pis_operand_t* result
) {
    err_t err = SUCCESS;

    CHECK(a->size == b->size);
    pis_operand_size_t operand_size = a->size;

    pis_operand_t res_tmp = LIFT_CTX_NEW_TMP(ctx->lift_ctx, operand_size);

    // carry flag
    LIFT_CTX_EMIT(ctx->lift_ctx, PIS_INSN3(PIS_OPCODE_UNSIGNED_CARRY, FLAGS_CF, *a, *b));

    // overflow flag
    LIFT_CTX_EMIT(ctx->lift_ctx, PIS_INSN3(PIS_OPCODE_SIGNED_CARRY, FLAGS_OF, *a, *b));

    // perform the actual addition
    LIFT_CTX_EMIT(ctx->lift_ctx, PIS_INSN3(PIS_OPCODE_ADD, res_tmp, *a, *b));

    CHECK_RETHROW(calc_parity_zero_sign_flags(ctx, &res_tmp));

    *result = res_tmp;

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

    CHECK(a->size == b->size);
    pis_operand_size_t operand_size = a->size;

    pis_operand_t res_tmp = LIFT_CTX_NEW_TMP(ctx->lift_ctx, operand_size);

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

static err_t
    do_dec(const post_prefixes_ctx_t* ctx, const pis_operand_t* operand, pis_operand_t* result) {
    err_t err = SUCCESS;

    pis_operand_size_t operand_size = operand->size;

    pis_operand_t one = PIS_OPERAND_CONST(1, operand_size);

    // overflow flag
    LIFT_CTX_EMIT(ctx->lift_ctx, PIS_INSN3(PIS_OPCODE_SIGNED_BORROW, FLAGS_OF, *operand, one));

    // perform the actual subtraction
    pis_operand_t res_tmp = LIFT_CTX_NEW_TMP(ctx->lift_ctx, operand_size);
    LIFT_CTX_EMIT(ctx->lift_ctx, PIS_INSN3(PIS_OPCODE_SUB, res_tmp, *operand, one));

    CHECK_RETHROW(calc_parity_zero_sign_flags(ctx, &res_tmp));

    *result = res_tmp;

cleanup:
    return err;
}

static err_t do_and(
    const post_prefixes_ctx_t* ctx,
    const pis_operand_t* a,
    const pis_operand_t* b,
    pis_operand_t* result
) {
    err_t err = SUCCESS;

    CHECK(a->size == b->size);
    pis_operand_size_t operand_size = a->size;

    pis_operand_t res_tmp = LIFT_CTX_NEW_TMP(ctx->lift_ctx, operand_size);

    // set CF and OF to zero
    LIFT_CTX_EMIT(
        ctx->lift_ctx,
        PIS_INSN2(PIS_OPCODE_MOVE, FLAGS_CF, PIS_OPERAND_CONST(0, PIS_OPERAND_SIZE_1))
    );
    LIFT_CTX_EMIT(
        ctx->lift_ctx,
        PIS_INSN2(PIS_OPCODE_MOVE, FLAGS_OF, PIS_OPERAND_CONST(0, PIS_OPERAND_SIZE_1))
    );

    // perform the actual bitwide and operation
    LIFT_CTX_EMIT(ctx->lift_ctx, PIS_INSN3(PIS_OPCODE_AND, res_tmp, *a, *b));

    CHECK_RETHROW(calc_parity_zero_sign_flags(ctx, &res_tmp));

    *result = res_tmp;

cleanup:
    return err;
}

static err_t do_imul(
    const post_prefixes_ctx_t* ctx,
    const pis_operand_t* a,
    const pis_operand_t* b,
    pis_operand_t* result
) {
    err_t err = SUCCESS;

    CHECK(a->size == b->size);
    pis_operand_size_t operand_size = a->size;

    pis_operand_t res_tmp = LIFT_CTX_NEW_TMP(ctx->lift_ctx, operand_size);

    // update CF
    LIFT_CTX_EMIT(ctx->lift_ctx, PIS_INSN3(PIS_OPCODE_SIGNED_MUL_OVERFLOW, FLAGS_CF, *a, *b));

    // update OF
    LIFT_CTX_EMIT(ctx->lift_ctx, PIS_INSN2(PIS_OPCODE_MOVE, FLAGS_OF, FLAGS_CF));

    // perform the actual multiplication
    pis_operand_t tmp = LIFT_CTX_NEW_TMP(ctx->lift_ctx, operand_size);
    LIFT_CTX_EMIT(ctx->lift_ctx, PIS_INSN3(PIS_OPCODE_SIGNED_MUL, tmp, *a, *b));

    *result = res_tmp;

cleanup:
    return err;
}

static err_t do_xor(
    const post_prefixes_ctx_t* ctx,
    const pis_operand_t* a,
    const pis_operand_t* b,
    pis_operand_t* result
) {
    err_t err = SUCCESS;

    CHECK(a->size == b->size);
    pis_operand_size_t operand_size = a->size;

    pis_operand_t res_tmp = LIFT_CTX_NEW_TMP(ctx->lift_ctx, operand_size);

    // carry flag
    LIFT_CTX_EMIT(
        ctx->lift_ctx,
        PIS_INSN2(PIS_OPCODE_MOVE, FLAGS_CF, PIS_OPERAND_CONST(0, PIS_OPERAND_SIZE_1))
    );

    // overflow flag
    LIFT_CTX_EMIT(
        ctx->lift_ctx,
        PIS_INSN2(PIS_OPCODE_MOVE, FLAGS_OF, PIS_OPERAND_CONST(0, PIS_OPERAND_SIZE_1))
    );

    // perform the actual xor operation
    LIFT_CTX_EMIT(ctx->lift_ctx, PIS_INSN3(PIS_OPCODE_XOR, res_tmp, *a, *b));

    CHECK_RETHROW(calc_parity_zero_sign_flags(ctx, &res_tmp));

    *result = res_tmp;

cleanup:
    return err;
}

static err_t do_or(
    const post_prefixes_ctx_t* ctx,
    const pis_operand_t* a,
    const pis_operand_t* b,
    pis_operand_t* result
) {
    err_t err = SUCCESS;

    CHECK(a->size == b->size);
    pis_operand_size_t operand_size = a->size;

    pis_operand_t res_tmp = LIFT_CTX_NEW_TMP(ctx->lift_ctx, operand_size);

    // carry flag
    LIFT_CTX_EMIT(
        ctx->lift_ctx,
        PIS_INSN2(PIS_OPCODE_MOVE, FLAGS_CF, PIS_OPERAND_CONST(0, PIS_OPERAND_SIZE_1))
    );

    // overflow flag
    LIFT_CTX_EMIT(
        ctx->lift_ctx,
        PIS_INSN2(PIS_OPCODE_MOVE, FLAGS_OF, PIS_OPERAND_CONST(0, PIS_OPERAND_SIZE_1))
    );

    // perform the actual or operation
    LIFT_CTX_EMIT(ctx->lift_ctx, PIS_INSN3(PIS_OPCODE_OR, res_tmp, *a, *b));

    CHECK_RETHROW(calc_parity_zero_sign_flags(ctx, &res_tmp));

    *result = res_tmp;

cleanup:
    return err;
}

typedef err_t (*modrm_binop_fn_t
)(const post_prefixes_ctx_t* ctx,
  const pis_operand_t* a,
  const pis_operand_t* b,
  pis_operand_t* result);

static err_t calc_binop_modrm(
    const post_prefixes_ctx_t* ctx,
    modrm_binop_fn_t fn,
    const modrm_operand_t* dst,
    const modrm_operand_t* src,
    pis_operand_t* result
) {
    err_t err = SUCCESS;

    pis_operand_size_t operand_size = ctx->operand_sizes.insn_default_not_64_bit;
    pis_operand_t dst_tmp = LIFT_CTX_NEW_TMP(ctx->lift_ctx, operand_size);
    pis_operand_t src_tmp = LIFT_CTX_NEW_TMP(ctx->lift_ctx, operand_size);

    CHECK_RETHROW(modrm_operand_read(ctx, &dst_tmp, dst));
    CHECK_RETHROW(modrm_operand_read(ctx, &src_tmp, src));

    CHECK_RETHROW(fn(ctx, &dst_tmp, &src_tmp, result));

cleanup:
    return err;
}

static err_t calc_binop_modrm_imm(
    const post_prefixes_ctx_t* ctx,
    modrm_binop_fn_t fn,
    const modrm_operand_t* dst,
    const pis_operand_t* src_imm,
    pis_operand_t* result
) {
    err_t err = SUCCESS;

    pis_operand_size_t operand_size = ctx->operand_sizes.insn_default_not_64_bit;
    pis_operand_t dst_tmp = LIFT_CTX_NEW_TMP(ctx->lift_ctx, operand_size);

    CHECK_RETHROW(modrm_operand_read(ctx, &dst_tmp, dst));

    CHECK_RETHROW(fn(ctx, &dst_tmp, src_imm, result));

cleanup:
    return err;
}

static err_t calc_and_store_binop_modrm(
    const post_prefixes_ctx_t* ctx,
    modrm_binop_fn_t fn,
    const modrm_operand_t* dst,
    const modrm_operand_t* src
) {
    err_t err = SUCCESS;

    pis_operand_t res_tmp = {};
    CHECK_RETHROW(calc_binop_modrm(ctx, fn, dst, src, &res_tmp));
    CHECK_RETHROW(modrm_operand_write(ctx, dst, &res_tmp));

cleanup:
    return err;
}

static err_t calc_and_store_binop_modrm_imm(
    const post_prefixes_ctx_t* ctx,
    modrm_binop_fn_t fn,
    const modrm_operand_t* dst,
    const pis_operand_t* src_imm
) {
    err_t err = SUCCESS;

    pis_operand_t res_tmp = {};
    CHECK_RETHROW(calc_binop_modrm_imm(ctx, fn, dst, src_imm, &res_tmp));
    CHECK_RETHROW(modrm_operand_write(ctx, dst, &res_tmp));

cleanup:
    return err;
}

/// the operand size for relative jumps which use 16/32 bit displacements.
/// please not that the operand size is not the size of the displacement immediate. for example, for
/// an operand size of 8, the displacement is 4 bytes.
static pis_operand_size_t rel_jmp_operand_size_16_32(const post_prefixes_ctx_t* ctx) {
    if (ctx->lift_ctx->pis_x86_ctx->cpumode == PIS_X86_CPUMODE_64_BIT) {
        // from the intel ia-32 spec:
        // "In 64-bit mode the target operand will always be 64-bits because the operand size is
        // forced to 64-bits for near branches"
        return PIS_OPERAND_SIZE_8;
    } else {
        return ctx->operand_sizes.insn_default_not_64_bit;
    }
}

/// fetches an immediate of the given operand size and sign extends it to 64 bits.
static err_t fetch_and_sign_extend_imm(
    const post_prefixes_ctx_t* ctx, pis_operand_size_t operand_size, u64* disp
) {
    err_t err = SUCCESS;
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
    case PIS_OPERAND_SIZE_1: {
        i8 disp8 = LIFT_CTX_CUR1_ADVANCE(ctx->lift_ctx);
        *disp = (i64) disp8;
        break;
    }
    }
cleanup:
    return err;
}

/// the instruction points size of a relative jump using a 16/32 bit displacement.
static pis_operand_size_t rel_jmp_ip_operand_size(const post_prefixes_ctx_t* ctx) {
    return rel_jmp_operand_size_16_32(ctx);
}

/// masks the ip value which is the result of performing a relative jump with a 16/32 bit
/// displacement.
static u64 rel_jmp_mask_ip_value(const post_prefixes_ctx_t* ctx, u64 ip_value) {
    pis_operand_size_t ip_operand_size = rel_jmp_ip_operand_size(ctx);
    u64 mask = pis_operand_size_max_unsigned_value(ip_operand_size);
    return ip_value & mask;
}

/// fetches the displacement and calculates the target address of a relative jump with a 16/32 bit
/// displacement.
static err_t rel_jmp_fetch_disp_and_calc_target_addr(
    const post_prefixes_ctx_t* ctx, pis_operand_size_t operand_size, u64* target
) {
    err_t err = SUCCESS;

    u64 disp = 0;
    CHECK_RETHROW(fetch_and_sign_extend_imm(ctx, operand_size, &disp));

    u64 cur_insn_end_addr = ctx->lift_ctx->cur_insn_addr + lift_ctx_index(ctx->lift_ctx);
    *target = rel_jmp_mask_ip_value(ctx, cur_insn_end_addr + disp);

cleanup:
    return err;
}

/// fetches the displacement and calculates the target of a relative jump with a 16/32 bit
/// displacement.
static err_t rel_jmp_fetch_disp_and_calc_target(
    const post_prefixes_ctx_t* ctx, pis_operand_size_t operand_size, pis_operand_t* target
) {
    err_t err = SUCCESS;

    u64 target_addr = 0;
    CHECK_RETHROW(rel_jmp_fetch_disp_and_calc_target_addr(ctx, operand_size, &target_addr));

    *target = PIS_OPERAND_RAM(target_addr, PIS_OPERAND_SIZE_1);

cleanup:
    return err;
}

/// emits a conditional relative jump with a 16/32bit displacement, using the given condition.
static err_t do_cond_rel_jmp(
    const post_prefixes_ctx_t* ctx, const pis_operand_t* cond, pis_operand_size_t operand_size
) {
    err_t err = SUCCESS;

    u64 target = 0;
    CHECK_RETHROW(rel_jmp_fetch_disp_and_calc_target_addr(ctx, operand_size, &target));

    LIFT_CTX_EMIT(
        ctx->lift_ctx,
        PIS_INSN2(PIS_OPCODE_JMP_COND, *cond, PIS_OPERAND_RAM(target, PIS_OPERAND_SIZE_1))
    );

cleanup:
    return err;
}


/// generates a ternary expression.
static err_t ternary(
    const post_prefixes_ctx_t* ctx,
    const pis_operand_t* cond,
    const pis_operand_t* then_value,
    const pis_operand_t* else_value,
    const pis_operand_t* result
) {
    err_t err = SUCCESS;

    CHECK(cond->size == PIS_OPERAND_SIZE_1);
    CHECK(then_value->size == else_value->size);
    CHECK(then_value->size == result->size);

    pis_operand_size_t operand_size = then_value->size;
    CHECK(operand_size > PIS_OPERAND_SIZE_1);

    // calculate the negative condition
    pis_operand_t not_cond = LIFT_CTX_NEW_TMP(ctx->lift_ctx, PIS_OPERAND_SIZE_1);
    CHECK_RETHROW(cond_negate(ctx, cond, &not_cond));

    // zero extend the condition and its negative
    pis_operand_t cond_zero_extended = LIFT_CTX_NEW_TMP(ctx->lift_ctx, operand_size);
    LIFT_CTX_EMIT(ctx->lift_ctx, PIS_INSN2(PIS_OPCODE_ZERO_EXTEND, cond_zero_extended, *cond));

    pis_operand_t not_cond_zero_extended = LIFT_CTX_NEW_TMP(ctx->lift_ctx, operand_size);
    LIFT_CTX_EMIT(
        ctx->lift_ctx,
        PIS_INSN2(PIS_OPCODE_ZERO_EXTEND, not_cond_zero_extended, not_cond)
    );

    pis_operand_t true_case = LIFT_CTX_NEW_TMP(ctx->lift_ctx, operand_size);
    LIFT_CTX_EMIT(
        ctx->lift_ctx,
        PIS_INSN3(PIS_OPCODE_AND, true_case, cond_zero_extended, *then_value)
    );

    pis_operand_t false_case = LIFT_CTX_NEW_TMP(ctx->lift_ctx, operand_size);
    LIFT_CTX_EMIT(
        ctx->lift_ctx,
        PIS_INSN3(PIS_OPCODE_AND, false_case, not_cond_zero_extended, *else_value)
    );

    LIFT_CTX_EMIT(ctx->lift_ctx, PIS_INSN3(PIS_OPCODE_OR, *result, true_case, false_case));

cleanup:
    return err;
}

static err_t lift_second_opcode_byte(const post_prefixes_ctx_t* ctx, u8 second_opcode_byte) {
    err_t err = SUCCESS;
    modrm_operands_t modrm_operands = {};

    if (second_opcode_byte >= 0x80 && second_opcode_byte <= 0x80 + X86_COND_ENCODING_MAX_VALUE) {
        // jcc rel

        pis_operand_t cond = {};
        CHECK_RETHROW(cond_decode_and_calc(ctx, second_opcode_byte - 0x80, &cond));

        CHECK_RETHROW(do_cond_rel_jmp(ctx, &cond, rel_jmp_operand_size_16_32(ctx)));
    } else if (second_opcode_byte >= 0x90 && second_opcode_byte <= 0x90 + X86_COND_ENCODING_MAX_VALUE) {
        // setcc r/m8
        CHECK_RETHROW(modrm_fetch_and_process_with_operand_sizes(
            ctx,
            &modrm_operands,
            PIS_OPERAND_SIZE_1,
            // don't care
            PIS_OPERAND_SIZE_1
        ));

        pis_operand_t cond = {};
        CHECK_RETHROW(cond_decode_and_calc(ctx, second_opcode_byte - 0x90, &cond));

        CHECK_RETHROW(modrm_rm_write(ctx, &modrm_operands.rm_operand.rm, &cond));
    } else if (second_opcode_byte == 0xaf) {
        // imul r, r/m
        CHECK_RETHROW(modrm_fetch_and_process(ctx, &modrm_operands));
        CHECK_RETHROW(calc_and_store_binop_modrm(
            ctx,
            do_imul,
            &modrm_operands.reg_operand,
            &modrm_operands.rm_operand
        ));
    } else if (second_opcode_byte == 0x1f) {
        // xxx r/m
        CHECK_RETHROW(modrm_fetch_and_process(ctx, &modrm_operands));

        if (modrm_operands.modrm.reg == 0) {
            // nop r/m

            // don't emit anything, this is a nop
        } else {
            CHECK_FAIL_CODE(PIS_ERR_UNSUPPORTED_INSN);
        }
    } else if (second_opcode_byte == 0xb6) {
        // movzx r, r/m8
        pis_operand_size_t dst_size = ctx->operand_sizes.insn_default_not_64_bit;
        CHECK_RETHROW(modrm_fetch_and_process_with_operand_sizes(
            ctx,
            &modrm_operands,
            PIS_OPERAND_SIZE_1,
            dst_size
        ));

        pis_operand_t tmp8 = LIFT_CTX_NEW_TMP(ctx->lift_ctx, PIS_OPERAND_SIZE_1);
        CHECK_RETHROW(modrm_rm_read(ctx, &tmp8, &modrm_operands.rm_operand.rm));

        pis_operand_t tmp = LIFT_CTX_NEW_TMP(ctx->lift_ctx, dst_size);
        LIFT_CTX_EMIT(ctx->lift_ctx, PIS_INSN2(PIS_OPCODE_ZERO_EXTEND, tmp, tmp8));
        CHECK_RETHROW(write_gpr(ctx, &modrm_operands.reg_operand.reg, &tmp));
    } else if (second_opcode_byte == 0xb7) {
        // movzx r, r/m16
        pis_operand_size_t dst_size = ctx->operand_sizes.insn_default_not_64_bit;
        if (dst_size == PIS_OPERAND_SIZE_2) {
            dst_size = PIS_OPERAND_SIZE_4;
        }
        CHECK_RETHROW(modrm_fetch_and_process_with_operand_sizes(
            ctx,
            &modrm_operands,
            PIS_OPERAND_SIZE_2,
            dst_size
        ));

        pis_operand_t tmp16 = LIFT_CTX_NEW_TMP(ctx->lift_ctx, PIS_OPERAND_SIZE_2);
        CHECK_RETHROW(modrm_rm_read(ctx, &tmp16, &modrm_operands.rm_operand.rm));

        pis_operand_t tmp = LIFT_CTX_NEW_TMP(ctx->lift_ctx, dst_size);
        LIFT_CTX_EMIT(ctx->lift_ctx, PIS_INSN2(PIS_OPCODE_ZERO_EXTEND, tmp, tmp16));
        CHECK_RETHROW(write_gpr(ctx, &modrm_operands.reg_operand.reg, &tmp));
    } else if (second_opcode_byte == 0xbe) {
        // movsx r, r/m8
        pis_operand_size_t dst_size = ctx->operand_sizes.insn_default_not_64_bit;
        CHECK_RETHROW(modrm_fetch_and_process_with_operand_sizes(
            ctx,
            &modrm_operands,
            PIS_OPERAND_SIZE_1,
            dst_size
        ));

        pis_operand_t tmp8 = LIFT_CTX_NEW_TMP(ctx->lift_ctx, PIS_OPERAND_SIZE_1);
        CHECK_RETHROW(modrm_rm_read(ctx, &tmp8, &modrm_operands.rm_operand.rm));

        pis_operand_t tmp = LIFT_CTX_NEW_TMP(ctx->lift_ctx, dst_size);
        LIFT_CTX_EMIT(ctx->lift_ctx, PIS_INSN2(PIS_OPCODE_SIGN_EXTEND, tmp, tmp8));
        CHECK_RETHROW(write_gpr(ctx, &modrm_operands.reg_operand.reg, &tmp));
    } else if (second_opcode_byte == 0xbf) {
        // movsx r, r/m16
        pis_operand_size_t reg_size;
        if (ctx->prefixes->rex.w) {
            reg_size = PIS_OPERAND_SIZE_8;
        } else {
            reg_size = PIS_OPERAND_SIZE_4;
        }
        CHECK_RETHROW(modrm_fetch_and_process_with_operand_sizes(
            ctx,
            &modrm_operands,
            PIS_OPERAND_SIZE_2,
            reg_size
        ));

        pis_operand_t rm_tmp = LIFT_CTX_NEW_TMP(ctx->lift_ctx, PIS_OPERAND_SIZE_2);
        CHECK_RETHROW(modrm_rm_read(ctx, &rm_tmp, &modrm_operands.rm_operand.rm));

        pis_operand_t res_tmp = LIFT_CTX_NEW_TMP(ctx->lift_ctx, reg_size);
        LIFT_CTX_EMIT(ctx->lift_ctx, PIS_INSN2(PIS_OPCODE_SIGN_EXTEND, res_tmp, rm_tmp));
        CHECK_RETHROW(write_gpr(ctx, &modrm_operands.reg_operand.reg, &res_tmp));
    } else if (second_opcode_byte >= 0x40 && second_opcode_byte <= 0x40 + X86_COND_ENCODING_MAX_VALUE) {
        // cmovne r, r/m
        CHECK_RETHROW(modrm_fetch_and_process(ctx, &modrm_operands));

        pis_operand_t cond = {};
        CHECK_RETHROW(cond_decode_and_calc(ctx, second_opcode_byte - 0x40, &cond));

        pis_operand_size_t operand_size = ctx->operand_sizes.insn_default_not_64_bit;
        pis_operand_t rm_value = LIFT_CTX_NEW_TMP(ctx->lift_ctx, operand_size);
        CHECK_RETHROW(modrm_rm_read(ctx, &rm_value, &modrm_operands.rm_operand.rm));

        pis_operand_t final_value = LIFT_CTX_NEW_TMP(ctx->lift_ctx, operand_size);
        CHECK_RETHROW(ternary(ctx, &cond, &rm_value, &modrm_operands.reg_operand.reg, &final_value)
        );

        CHECK_RETHROW(write_gpr(ctx, &modrm_operands.reg_operand.reg, &final_value));
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

static err_t do_push(const post_prefixes_ctx_t* ctx, const pis_operand_t* operand_to_push) {
    err_t err = SUCCESS;

    pis_operand_t sp = ctx->lift_ctx->sp;
    u64 operand_size_bytes = pis_operand_size_to_bytes(operand_to_push->size);

    // read the pushed operand into a tmp before subtracting sp. this makes sure that instructions
    // like `push rsp` behave properly, by pushing the original value, before the subtraction.
    pis_operand_t tmp = LIFT_CTX_NEW_TMP(ctx->lift_ctx, operand_to_push->size);
    LIFT_CTX_EMIT(ctx->lift_ctx, PIS_INSN2(PIS_OPCODE_MOVE, tmp, *operand_to_push));

    // subtract sp
    LIFT_CTX_EMIT(
        ctx->lift_ctx,
        PIS_INSN_ADD2(sp, PIS_OPERAND_CONST_NEG(operand_size_bytes, sp.size))
    );

    // write the memory
    LIFT_CTX_EMIT(ctx->lift_ctx, PIS_INSN2(PIS_OPCODE_STORE, sp, tmp));
cleanup:
    return err;
}

static err_t fetch_imm_operand(
    const post_prefixes_ctx_t* ctx, pis_operand_size_t size, pis_operand_t* operand
) {
    err_t err = SUCCESS;
    switch (size) {
    case PIS_OPERAND_SIZE_1:
        *operand = PIS_OPERAND_CONST(LIFT_CTX_CUR1_ADVANCE(ctx->lift_ctx), PIS_OPERAND_SIZE_1);
        break;
    case PIS_OPERAND_SIZE_2:
        *operand = PIS_OPERAND_CONST(LIFT_CTX_CUR2_ADVANCE(ctx->lift_ctx), PIS_OPERAND_SIZE_2);
        break;
    case PIS_OPERAND_SIZE_4:
        *operand = PIS_OPERAND_CONST(LIFT_CTX_CUR4_ADVANCE(ctx->lift_ctx), PIS_OPERAND_SIZE_4);
        break;
    case PIS_OPERAND_SIZE_8:
        *operand = PIS_OPERAND_CONST(LIFT_CTX_CUR8_ADVANCE(ctx->lift_ctx), PIS_OPERAND_SIZE_8);
        break;
    default:
        UNREACHABLE();
    }
cleanup:
    return err;
}

static err_t
    fetch_sign_extended_imm_operand(const post_prefixes_ctx_t* ctx, pis_operand_t* operand) {
    err_t err = SUCCESS;
    pis_operand_size_t operand_size = ctx->operand_sizes.insn_default_not_64_bit;

    pis_operand_size_t imm_operand_size =
        operand_size == PIS_OPERAND_SIZE_8 ? PIS_OPERAND_SIZE_4 : operand_size;

    pis_operand_t imm = {};
    CHECK_RETHROW(fetch_imm_operand(ctx, imm_operand_size, &imm));

    pis_operand_t sign_extended_imm;
    if (operand_size == PIS_OPERAND_SIZE_8) {
        sign_extended_imm = LIFT_CTX_NEW_TMP(ctx->lift_ctx, operand_size);
        LIFT_CTX_EMIT(ctx->lift_ctx, PIS_INSN2(PIS_OPCODE_SIGN_EXTEND, sign_extended_imm, imm));
    } else {
        sign_extended_imm = imm;
    }

    *operand = sign_extended_imm;
cleanup:
    return err;
}

/// generates a ternary expression with conditional expressions.
static err_t cond_expr_ternary(
    const post_prefixes_ctx_t* ctx,
    const pis_operand_t* cond,
    const pis_operand_t* then_value,
    const pis_operand_t* else_value,
    const pis_operand_t* result
) {
    err_t err = SUCCESS;

    // make sure that all operands are one byte conditional expressions.
    CHECK(cond->size == PIS_OPERAND_SIZE_1);
    CHECK(then_value->size == PIS_OPERAND_SIZE_1);
    CHECK(else_value->size == PIS_OPERAND_SIZE_1);

    pis_operand_t not_cond = LIFT_CTX_NEW_TMP(ctx->lift_ctx, PIS_OPERAND_SIZE_1);
    CHECK_RETHROW(cond_negate(ctx, cond, &not_cond));

    pis_operand_t true_case = LIFT_CTX_NEW_TMP(ctx->lift_ctx, PIS_OPERAND_SIZE_1);
    LIFT_CTX_EMIT(ctx->lift_ctx, PIS_INSN3(PIS_OPCODE_AND, true_case, *cond, *then_value));

    pis_operand_t false_case = LIFT_CTX_NEW_TMP(ctx->lift_ctx, PIS_OPERAND_SIZE_1);
    LIFT_CTX_EMIT(ctx->lift_ctx, PIS_INSN3(PIS_OPCODE_AND, false_case, not_cond, *else_value));

    LIFT_CTX_EMIT(ctx->lift_ctx, PIS_INSN3(PIS_OPCODE_OR, *result, true_case, false_case));

cleanup:
    return err;
}

static err_t shl_calc_carry_flag(
    const post_prefixes_ctx_t* ctx, const pis_operand_t* to_shift, const pis_operand_t* count
) {
    err_t err = SUCCESS;

    CHECK(count->size == to_shift->size);

    pis_operand_size_t operand_size = to_shift->size;

    // to get the last shifted out but, shift the original value `count - 1` bits, and then extract
    // its most significant bit.
    pis_operand_t count_minus_1 = LIFT_CTX_NEW_TMP(ctx->lift_ctx, operand_size);
    LIFT_CTX_EMIT(
        ctx->lift_ctx,
        PIS_INSN3(PIS_OPCODE_SUB, count_minus_1, *count, PIS_OPERAND_CONST(1, operand_size))
    );
    pis_operand_t shifted_by_count_minus_1 = LIFT_CTX_NEW_TMP(ctx->lift_ctx, operand_size);
    LIFT_CTX_EMIT(
        ctx->lift_ctx,
        PIS_INSN3(PIS_OPCODE_SHIFT_LEFT, shifted_by_count_minus_1, *to_shift, count_minus_1)
    );
    pis_operand_t last_extracted_bit = LIFT_CTX_NEW_TMP(ctx->lift_ctx, PIS_OPERAND_SIZE_1);
    CHECK_RETHROW(extract_most_significant_bit(ctx, &shifted_by_count_minus_1, &last_extracted_bit)
    );

    // now, we only want to set the carry flag if the count is non-zero, otherwise we want to use
    // the original CF value.
    pis_operand_t is_count_0 = LIFT_CTX_NEW_TMP(ctx->lift_ctx, PIS_OPERAND_SIZE_1);
    LIFT_CTX_EMIT(
        ctx->lift_ctx,
        PIS_INSN3(PIS_OPCODE_EQUALS, is_count_0, *count, PIS_OPERAND_CONST(0, operand_size))
    );

    CHECK_RETHROW(cond_expr_ternary(ctx, &is_count_0, &FLAGS_CF, &last_extracted_bit, &FLAGS_CF));

cleanup:
    return err;
}

static err_t shr_calc_carry_flag(
    const post_prefixes_ctx_t* ctx, const pis_operand_t* to_shift, const pis_operand_t* count
) {
    err_t err = SUCCESS;

    CHECK(count->size == to_shift->size);

    pis_operand_size_t operand_size = to_shift->size;

    // to get the last shifted out but, shift the original value `count - 1` bits, and then extract
    // its least significant bit.
    pis_operand_t count_minus_1 = LIFT_CTX_NEW_TMP(ctx->lift_ctx, operand_size);
    LIFT_CTX_EMIT(
        ctx->lift_ctx,
        PIS_INSN3(PIS_OPCODE_SUB, count_minus_1, *count, PIS_OPERAND_CONST(1, operand_size))
    );
    pis_operand_t shifted_by_count_minus_1 = LIFT_CTX_NEW_TMP(ctx->lift_ctx, operand_size);
    LIFT_CTX_EMIT(
        ctx->lift_ctx,
        PIS_INSN3(PIS_OPCODE_SHIFT_RIGHT, shifted_by_count_minus_1, *to_shift, count_minus_1)
    );
    pis_operand_t last_extracted_bit = LIFT_CTX_NEW_TMP(ctx->lift_ctx, PIS_OPERAND_SIZE_1);
    CHECK_RETHROW(extract_least_significant_bit(ctx, &shifted_by_count_minus_1, &last_extracted_bit)
    );

    // now, we only want to set the carry flag if the count is non-zero, otherwise we want to use
    // the original CF value.
    pis_operand_t is_count_0 = LIFT_CTX_NEW_TMP(ctx->lift_ctx, PIS_OPERAND_SIZE_1);
    LIFT_CTX_EMIT(
        ctx->lift_ctx,
        PIS_INSN3(PIS_OPCODE_EQUALS, is_count_0, *count, PIS_OPERAND_CONST(0, operand_size))
    );

    CHECK_RETHROW(cond_expr_ternary(ctx, &is_count_0, &FLAGS_CF, &last_extracted_bit, &FLAGS_CF));

cleanup:
    return err;
}

static err_t shl_calc_overflow_flag(
    const post_prefixes_ctx_t* ctx, const pis_operand_t* to_shift, const pis_operand_t* count
) {
    err_t err = SUCCESS;

    CHECK(count->size == to_shift->size);

    pis_operand_size_t operand_size = to_shift->size;

    // the overflow flag is set to `MSB(A << B) ^ CF`
    pis_operand_t shifted = LIFT_CTX_NEW_TMP(ctx->lift_ctx, operand_size);
    LIFT_CTX_EMIT(ctx->lift_ctx, PIS_INSN3(PIS_OPCODE_SHIFT_LEFT, shifted, *to_shift, *count));

    pis_operand_t msb = LIFT_CTX_NEW_TMP(ctx->lift_ctx, PIS_OPERAND_SIZE_1);
    CHECK_RETHROW(extract_most_significant_bit(ctx, &shifted, &msb));

    pis_operand_t new_overflow_flag_value = LIFT_CTX_NEW_TMP(ctx->lift_ctx, PIS_OPERAND_SIZE_1);
    LIFT_CTX_EMIT(ctx->lift_ctx, PIS_INSN3(PIS_OPCODE_XOR, new_overflow_flag_value, msb, FLAGS_CF));

    // we only want to set the overflow flag if the count is 1, otherwise we want to use
    // the original OF value.
    pis_operand_t is_count_1 = LIFT_CTX_NEW_TMP(ctx->lift_ctx, PIS_OPERAND_SIZE_1);
    LIFT_CTX_EMIT(
        ctx->lift_ctx,
        PIS_INSN3(PIS_OPCODE_EQUALS, is_count_1, *count, PIS_OPERAND_CONST(1, operand_size))
    );

    CHECK_RETHROW(
        cond_expr_ternary(ctx, &is_count_1, &new_overflow_flag_value, &FLAGS_OF, &FLAGS_OF)
    );

cleanup:
    return err;
}

static err_t shl_calc_parity_zero_sign_flags(
    const post_prefixes_ctx_t* ctx, const pis_operand_t* count, const pis_operand_t* shift_result
) {
    err_t err = SUCCESS;

    CHECK(count->size == shift_result->size);
    pis_operand_size_t operand_size = shift_result->size;

    // only modify the flags if the count is non-zero
    pis_operand_t is_count_0 = LIFT_CTX_NEW_TMP(ctx->lift_ctx, PIS_OPERAND_SIZE_1);
    LIFT_CTX_EMIT(
        ctx->lift_ctx,
        PIS_INSN3(PIS_OPCODE_EQUALS, is_count_0, *count, PIS_OPERAND_CONST(0, operand_size))
    );

    pis_operand_t new_pf = LIFT_CTX_NEW_TMP(ctx->lift_ctx, PIS_OPERAND_SIZE_1);
    CHECK_RETHROW(calc_parity_flag_into(ctx, shift_result, &new_pf));
    CHECK_RETHROW(cond_expr_ternary(ctx, &is_count_0, &FLAGS_PF, &new_pf, &FLAGS_PF));

    pis_operand_t new_zf = LIFT_CTX_NEW_TMP(ctx->lift_ctx, PIS_OPERAND_SIZE_1);
    CHECK_RETHROW(calc_zero_flag_into(ctx, shift_result, &new_zf));
    CHECK_RETHROW(cond_expr_ternary(ctx, &is_count_0, &FLAGS_ZF, &new_zf, &FLAGS_ZF));

    pis_operand_t new_sf = LIFT_CTX_NEW_TMP(ctx->lift_ctx, PIS_OPERAND_SIZE_1);
    CHECK_RETHROW(extract_most_significant_bit(ctx, shift_result, &new_sf));
    CHECK_RETHROW(cond_expr_ternary(ctx, &is_count_0, &FLAGS_SF, &new_sf, &FLAGS_SF));

cleanup:
    return err;
}

static err_t mask_shift_count(
    const post_prefixes_ctx_t* ctx,
    const pis_operand_t* count,
    const pis_operand_t* masked_count,
    pis_operand_size_t operand_size
) {
    err_t err = SUCCESS;

    u64 count_mask = operand_size == PIS_OPERAND_SIZE_8 ? 0b111111 : 0b11111;
    LIFT_CTX_EMIT(
        ctx->lift_ctx,
        PIS_INSN3(
            PIS_OPCODE_AND,
            *masked_count,
            *count,
            PIS_OPERAND_CONST(count_mask, operand_size)
        )
    );
cleanup:
    return err;
}

static err_t do_shl(
    const post_prefixes_ctx_t* ctx,
    const pis_operand_t* a,
    const pis_operand_t* b,
    pis_operand_t* result
) {
    err_t err = SUCCESS;

    CHECK(a->size == b->size);
    pis_operand_size_t operand_size = a->size;

    pis_operand_t res_tmp = LIFT_CTX_NEW_TMP(ctx->lift_ctx, operand_size);

    pis_operand_t count = LIFT_CTX_NEW_TMP(ctx->lift_ctx, operand_size);
    CHECK_RETHROW(mask_shift_count(ctx, b, &count, operand_size));

    // carry flag
    CHECK_RETHROW(shl_calc_carry_flag(ctx, a, &count));

    // overflow flag
    CHECK_RETHROW(shl_calc_overflow_flag(ctx, a, &count));

    // perform the actual shift
    LIFT_CTX_EMIT(ctx->lift_ctx, PIS_INSN3(PIS_OPCODE_SHIFT_LEFT, res_tmp, *a, count));

    CHECK_RETHROW(shl_calc_parity_zero_sign_flags(ctx, &count, &res_tmp));

    *result = res_tmp;

cleanup:
    return err;
}

static err_t shr_calc_overflow_flag(
    const post_prefixes_ctx_t* ctx, const pis_operand_t* to_shift, const pis_operand_t* count
) {
    err_t err = SUCCESS;

    CHECK(count->size == to_shift->size);

    pis_operand_size_t operand_size = to_shift->size;

    // the overflow flag is set to the msb of the original operand
    pis_operand_t new_overflow_flag_value = LIFT_CTX_NEW_TMP(ctx->lift_ctx, PIS_OPERAND_SIZE_1);
    CHECK_RETHROW(extract_most_significant_bit(ctx, to_shift, &new_overflow_flag_value));

    // we only want to set the overflow flag if the count is 1, otherwise we want to use
    // the original OF value.
    pis_operand_t is_count_1 = LIFT_CTX_NEW_TMP(ctx->lift_ctx, PIS_OPERAND_SIZE_1);
    LIFT_CTX_EMIT(
        ctx->lift_ctx,
        PIS_INSN3(PIS_OPCODE_EQUALS, is_count_1, *count, PIS_OPERAND_CONST(1, operand_size))
    );

    CHECK_RETHROW(
        cond_expr_ternary(ctx, &is_count_1, &new_overflow_flag_value, &FLAGS_OF, &FLAGS_OF)
    );

cleanup:
    return err;
}

static err_t sar_calc_overflow_flag(
    const post_prefixes_ctx_t* ctx, const pis_operand_t* to_shift, const pis_operand_t* count
) {
    err_t err = SUCCESS;

    CHECK(count->size == to_shift->size);

    pis_operand_size_t operand_size = to_shift->size;

    // the overflow flag is set to 0 if the count is 1
    pis_operand_t new_overflow_flag_value = PIS_OPERAND_CONST(0, PIS_OPERAND_SIZE_1);

    // we only want to set the overflow flag if the count is 1, otherwise we want to use
    // the original OF value.
    pis_operand_t is_count_1 = LIFT_CTX_NEW_TMP(ctx->lift_ctx, PIS_OPERAND_SIZE_1);
    LIFT_CTX_EMIT(
        ctx->lift_ctx,
        PIS_INSN3(PIS_OPCODE_EQUALS, is_count_1, *count, PIS_OPERAND_CONST(1, operand_size))
    );

    CHECK_RETHROW(
        cond_expr_ternary(ctx, &is_count_1, &new_overflow_flag_value, &FLAGS_OF, &FLAGS_OF)
    );

cleanup:
    return err;
}

static err_t do_shr(
    const post_prefixes_ctx_t* ctx,
    const pis_operand_t* a,
    const pis_operand_t* b,
    pis_operand_t* result
) {
    err_t err = SUCCESS;

    CHECK(a->size == b->size);
    pis_operand_size_t operand_size = a->size;

    pis_operand_t res_tmp = LIFT_CTX_NEW_TMP(ctx->lift_ctx, operand_size);

    pis_operand_t count = LIFT_CTX_NEW_TMP(ctx->lift_ctx, operand_size);
    CHECK_RETHROW(mask_shift_count(ctx, b, &count, operand_size));

    // carry flag
    CHECK_RETHROW(shr_calc_carry_flag(ctx, a, &count));

    // overflow flag
    CHECK_RETHROW(shr_calc_overflow_flag(ctx, a, &count));

    // perform the actual shift
    LIFT_CTX_EMIT(ctx->lift_ctx, PIS_INSN3(PIS_OPCODE_SHIFT_RIGHT, res_tmp, *a, count));

    CHECK_RETHROW(shl_calc_parity_zero_sign_flags(ctx, &count, &res_tmp));

    *result = res_tmp;

cleanup:
    return err;
}

static err_t do_sar(
    const post_prefixes_ctx_t* ctx,
    const pis_operand_t* a,
    const pis_operand_t* b,
    pis_operand_t* result
) {
    err_t err = SUCCESS;

    CHECK(a->size == b->size);
    pis_operand_size_t operand_size = a->size;

    pis_operand_t res_tmp = LIFT_CTX_NEW_TMP(ctx->lift_ctx, operand_size);

    pis_operand_t count = LIFT_CTX_NEW_TMP(ctx->lift_ctx, operand_size);
    CHECK_RETHROW(mask_shift_count(ctx, b, &count, operand_size));

    // carry flag
    CHECK_RETHROW(shr_calc_carry_flag(ctx, a, &count));

    // overflow flag
    CHECK_RETHROW(sar_calc_overflow_flag(ctx, a, &count));

    // perform the actual shift
    LIFT_CTX_EMIT(ctx->lift_ctx, PIS_INSN3(PIS_OPCODE_SHIFT_RIGHT_SIGNED, res_tmp, *a, count));

    CHECK_RETHROW(shl_calc_parity_zero_sign_flags(ctx, &count, &res_tmp));

    *result = res_tmp;

cleanup:
    return err;
}

static err_t push_rip(const post_prefixes_ctx_t* ctx) {
    err_t err = SUCCESS;
    u64 cur_insn_end_addr = ctx->lift_ctx->cur_insn_addr + lift_ctx_index(ctx->lift_ctx);
    u64 push_value = rel_jmp_mask_ip_value(ctx, cur_insn_end_addr);
    CHECK_RETHROW(do_push(ctx, &PIS_OPERAND_CONST(push_value, rel_jmp_operand_size_16_32(ctx))));
cleanup:
    return err;
}

static err_t lift_first_opcode_byte(const post_prefixes_ctx_t* ctx, u8 first_opcode_byte) {
    err_t err = SUCCESS;
    modrm_operands_t modrm_operands = {};

    if (opcode_reg_opcode_only(first_opcode_byte) == 0x50) {
        // push <reg>
        u8 reg_encoding = opcode_reg_extract(ctx, first_opcode_byte);

        pis_operand_size_t operand_size = ctx->operand_sizes.insn_default_64_bit;
        pis_operand_t pushed_reg = reg_get_operand(reg_encoding, operand_size, ctx->prefixes);

        CHECK_RETHROW(do_push(ctx, &pushed_reg));
    } else if (opcode_reg_opcode_only(first_opcode_byte) == 0x58) {
        // pop <reg>
        u8 reg_encoding = opcode_reg_extract(ctx, first_opcode_byte);

        pis_operand_size_t operand_size = ctx->operand_sizes.insn_default_64_bit;
        pis_operand_t sp = ctx->lift_ctx->sp;
        u64 operand_size_bytes = pis_operand_size_to_bytes(operand_size);

        pis_operand_t tmp = LIFT_CTX_NEW_TMP(ctx->lift_ctx, operand_size);

        LIFT_CTX_EMIT(ctx->lift_ctx, PIS_INSN2(PIS_OPCODE_LOAD, tmp, sp));

        LIFT_CTX_EMIT(
            ctx->lift_ctx,
            PIS_INSN_ADD2(sp, PIS_OPERAND_CONST(operand_size_bytes, sp.size))
        );

        pis_operand_t reg_operand = reg_get_operand(reg_encoding, operand_size, ctx->prefixes);
        CHECK_RETHROW(write_gpr(ctx, &reg_operand, &tmp));
    } else if (opcode_reg_opcode_only(first_opcode_byte) == 0x90) {
        // xchg [e/r]ax, r
        u8 reg_encoding = opcode_reg_extract(ctx, first_opcode_byte);

        pis_operand_size_t operand_size = ctx->operand_sizes.insn_default_not_64_bit;

        pis_operand_t ax_operand = PIS_OPERAND(RAX.addr, operand_size);
        pis_operand_t reg_operand = reg_get_operand(reg_encoding, operand_size, ctx->prefixes);

        if (pis_operand_equals(&ax_operand, &reg_operand)) {
            // exchange [e/r]ax with itself, this is a nop, so don't emit anything
        } else {
            // actual exchange operation
            pis_operand_t tmp = LIFT_CTX_NEW_TMP(ctx->lift_ctx, operand_size);

            LIFT_CTX_EMIT(ctx->lift_ctx, PIS_INSN2(PIS_OPCODE_MOVE, tmp, ax_operand));
            CHECK_RETHROW(write_gpr(ctx, &ax_operand, &reg_operand));
            CHECK_RETHROW(write_gpr(ctx, &reg_operand, &tmp));
        }
    } else if (first_opcode_byte == 0x89) {
        // move r/m, r
        CHECK_RETHROW(modrm_fetch_and_process(ctx, &modrm_operands));
        CHECK_RETHROW(
            modrm_rm_write(ctx, &modrm_operands.rm_operand.rm, &modrm_operands.reg_operand.reg)
        );
    } else if (first_opcode_byte == 0xf7) {
        // xxx r/m
        CHECK_RETHROW(modrm_fetch_and_process(ctx, &modrm_operands));

        pis_operand_size_t operand_size = ctx->operand_sizes.insn_default_not_64_bit;

        pis_operand_t divisor = LIFT_CTX_NEW_TMP(ctx->lift_ctx, operand_size);
        CHECK_RETHROW(modrm_rm_read(ctx, &divisor, &modrm_operands.rm_operand.rm));

        if (modrm_operands.modrm.reg == 6) {
            // div r/m
            if (operand_size == PIS_OPERAND_SIZE_8) {
                // divide `rdx:rax`.

                // perform the division
                LIFT_CTX_EMIT(
                    ctx->lift_ctx,
                    PIS_INSN4(PIS_OPCODE_UNSIGNED_DIV_16, RAX, RDX, RAX, divisor)
                );

                // perform the remainder calculation
                LIFT_CTX_EMIT(
                    ctx->lift_ctx,
                    PIS_INSN4(PIS_OPCODE_UNSIGNED_REM_16, RDX, RDX, RAX, divisor)
                );
            } else {
                // divide `dx:ax` or `edx:eax`.

                // first, combine the 2 registers into a single operand.
                pis_operand_size_t double_operand_size = operand_size * 2;
                pis_operand_t divide_lhs = LIFT_CTX_NEW_TMP(ctx->lift_ctx, double_operand_size);
                LIFT_CTX_EMIT(
                    ctx->lift_ctx,
                    PIS_INSN2(
                        PIS_OPCODE_ZERO_EXTEND,
                        divide_lhs,
                        get_ax_operand_of_size(operand_size)
                    )
                );

                // zero extend the dx part and shift it left
                pis_operand_t zero_extended_dx =
                    LIFT_CTX_NEW_TMP(ctx->lift_ctx, double_operand_size);
                LIFT_CTX_EMIT(
                    ctx->lift_ctx,
                    PIS_INSN2(
                        PIS_OPCODE_ZERO_EXTEND,
                        zero_extended_dx,
                        get_dx_operand_of_size(operand_size)
                    )
                );
                LIFT_CTX_EMIT(
                    ctx->lift_ctx,
                    PIS_INSN3(
                        PIS_OPCODE_SHIFT_LEFT,
                        zero_extended_dx,
                        zero_extended_dx,
                        PIS_OPERAND_CONST(
                            pis_operand_size_to_bits(operand_size),
                            double_operand_size
                        )
                    )
                );

                // or the shifted dx value into the result operand
                LIFT_CTX_EMIT(
                    ctx->lift_ctx,
                    PIS_INSN3(PIS_OPCODE_OR, divide_lhs, divide_lhs, zero_extended_dx)
                );

                // zero extend the divisor
                pis_operand_t zero_extended_divisor =
                    LIFT_CTX_NEW_TMP(ctx->lift_ctx, double_operand_size);
                LIFT_CTX_EMIT(
                    ctx->lift_ctx,
                    PIS_INSN2(PIS_OPCODE_ZERO_EXTEND, zero_extended_divisor, divisor)
                );

                // perform the division
                pis_operand_t div_result = LIFT_CTX_NEW_TMP(ctx->lift_ctx, double_operand_size);
                LIFT_CTX_EMIT(
                    ctx->lift_ctx,
                    PIS_INSN3(PIS_OPCODE_UNSIGNED_DIV, div_result, divide_lhs, divisor)
                );

                // store the division result in ax
                LIFT_CTX_EMIT(
                    ctx->lift_ctx,
                    PIS_INSN2(
                        PIS_OPCODE_GET_LOW_BITS,
                        get_ax_operand_of_size(operand_size),
                        div_result
                    )
                );

                // perform the remainder calculation
                pis_operand_t rem_result = LIFT_CTX_NEW_TMP(ctx->lift_ctx, double_operand_size);
                LIFT_CTX_EMIT(
                    ctx->lift_ctx,
                    PIS_INSN3(PIS_OPCODE_UNSIGNED_REM, rem_result, divide_lhs, divisor)
                );

                // store the division result in dx
                LIFT_CTX_EMIT(
                    ctx->lift_ctx,
                    PIS_INSN2(
                        PIS_OPCODE_GET_LOW_BITS,
                        get_dx_operand_of_size(operand_size),
                        rem_result
                    )
                );
            }
        } else {
            CHECK_FAIL_CODE(PIS_ERR_UNSUPPORTED_INSN);
        }
    } else if (first_opcode_byte == 0x8b) {
        // move r, r/m
        CHECK_RETHROW(modrm_fetch_and_process(ctx, &modrm_operands));

        pis_operand_size_t operand_size = ctx->operand_sizes.insn_default_not_64_bit;
        pis_operand_t tmp = LIFT_CTX_NEW_TMP(ctx->lift_ctx, operand_size);
        CHECK_RETHROW(modrm_rm_read(ctx, &tmp, &modrm_operands.rm_operand.rm));
        CHECK_RETHROW(write_gpr(ctx, &modrm_operands.reg_operand.reg, &tmp));
    } else if (first_opcode_byte == 0x63) {
        // movsxd r, r/m
        CHECK_RETHROW(modrm_fetch_and_process(ctx, &modrm_operands));
        pis_operand_size_t operand_size = ctx->operand_sizes.insn_default_not_64_bit;
        if (operand_size == PIS_OPERAND_SIZE_8) {
            pis_operand_t tmp32 = LIFT_CTX_NEW_TMP(ctx->lift_ctx, PIS_OPERAND_SIZE_4);
            CHECK_RETHROW(modrm_rm_read(ctx, &tmp32, &modrm_operands.rm_operand.rm));

            pis_operand_t tmp64 = LIFT_CTX_NEW_TMP(ctx->lift_ctx, PIS_OPERAND_SIZE_8);
            LIFT_CTX_EMIT(ctx->lift_ctx, PIS_INSN2(PIS_OPCODE_SIGN_EXTEND, tmp64, tmp32));

            CHECK_RETHROW(write_gpr(ctx, &modrm_operands.reg_operand.reg, &tmp64));
        } else {
            // regular mov
            pis_operand_t tmp = LIFT_CTX_NEW_TMP(ctx->lift_ctx, operand_size);
            CHECK_RETHROW(modrm_rm_read(ctx, &tmp, &modrm_operands.rm_operand.rm));
            CHECK_RETHROW(write_gpr(ctx, &modrm_operands.reg_operand.reg, &tmp));
        }
    } else if (first_opcode_byte == 0x01) {
        // add r/m, r
        CHECK_RETHROW(modrm_fetch_and_process(ctx, &modrm_operands));
        CHECK_RETHROW(calc_and_store_binop_modrm(
            ctx,
            do_add,
            &modrm_operands.rm_operand,
            &modrm_operands.reg_operand
        ));
    } else if (first_opcode_byte == 0x03) {
        // add r, r/m
        CHECK_RETHROW(modrm_fetch_and_process(ctx, &modrm_operands));
        CHECK_RETHROW(calc_and_store_binop_modrm(
            ctx,
            do_add,
            &modrm_operands.reg_operand,
            &modrm_operands.rm_operand
        ));
    } else if (first_opcode_byte == 0x0b) {
        // or r, r/m
        CHECK_RETHROW(modrm_fetch_and_process(ctx, &modrm_operands));
        CHECK_RETHROW(calc_and_store_binop_modrm(
            ctx,
            do_or,
            &modrm_operands.reg_operand,
            &modrm_operands.rm_operand
        ));
    } else if (first_opcode_byte == 0x09) {
        // or r/m, r
        CHECK_RETHROW(modrm_fetch_and_process(ctx, &modrm_operands));
        CHECK_RETHROW(calc_and_store_binop_modrm(
            ctx,
            do_or,
            &modrm_operands.rm_operand,
            &modrm_operands.reg_operand
        ));
    } else if (first_opcode_byte == 0x23) {
        // and r, r/m
        CHECK_RETHROW(modrm_fetch_and_process(ctx, &modrm_operands));
        CHECK_RETHROW(calc_and_store_binop_modrm(
            ctx,
            do_and,
            &modrm_operands.reg_operand,
            &modrm_operands.rm_operand
        ));
    } else if (first_opcode_byte == 0x29) {
        // sub r/m, r
        CHECK_RETHROW(modrm_fetch_and_process(ctx, &modrm_operands));
        CHECK_RETHROW(calc_and_store_binop_modrm(
            ctx,
            do_sub,
            &modrm_operands.rm_operand,
            &modrm_operands.reg_operand
        ));
    } else if (first_opcode_byte == 0x2b) {
        // sub r, r/m
        CHECK_RETHROW(modrm_fetch_and_process(ctx, &modrm_operands));
        CHECK_RETHROW(calc_and_store_binop_modrm(
            ctx,
            do_sub,
            &modrm_operands.reg_operand,
            &modrm_operands.rm_operand
        ));
    } else if (first_opcode_byte == 0x31) {
        // xor r/m, r
        CHECK_RETHROW(modrm_fetch_and_process(ctx, &modrm_operands));
        CHECK_RETHROW(calc_and_store_binop_modrm(
            ctx,
            do_xor,
            &modrm_operands.rm_operand,
            &modrm_operands.reg_operand
        ));
    } else if (first_opcode_byte == 0x33) {
        // xor r, r/m
        CHECK_RETHROW(modrm_fetch_and_process(ctx, &modrm_operands));
        CHECK_RETHROW(calc_and_store_binop_modrm(
            ctx,
            do_xor,
            &modrm_operands.reg_operand,
            &modrm_operands.rm_operand
        ));
    } else if (first_opcode_byte == 0x39) {
        // cmp r/m, r
        CHECK_RETHROW(modrm_fetch_and_process(ctx, &modrm_operands));

        // perform subtraction but ignore the result
        pis_operand_t res_tmp = {};
        CHECK_RETHROW(calc_binop_modrm(
            ctx,
            do_sub,
            &modrm_operands.rm_operand,
            &modrm_operands.reg_operand,
            &res_tmp
        ));
    } else if (first_opcode_byte == 0x3b) {
        // cmp r, r/m
        CHECK_RETHROW(modrm_fetch_and_process(ctx, &modrm_operands));

        // perform subtraction but ignore the result
        pis_operand_t res_tmp = {};
        CHECK_RETHROW(calc_binop_modrm(
            ctx,
            do_sub,
            &modrm_operands.reg_operand,
            &modrm_operands.rm_operand,
            &res_tmp
        ));
    } else if (first_opcode_byte == 0x8d) {
        // lea r, m

        CHECK_RETHROW(modrm_fetch_and_process(ctx, &modrm_operands));

        // the rm operand must be a memory operand in case of `lea`.
        CHECK(modrm_operands.rm_operand.rm.is_memory);

        CHECK_RETHROW(write_gpr(
            ctx,
            &modrm_operands.reg_operand.reg,
            &modrm_operands.rm_operand.rm.addr_or_reg
        ));
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

            pis_operand_t rm_tmp = LIFT_CTX_NEW_TMP(ctx->lift_ctx, operand_size);
            CHECK_RETHROW(modrm_rm_read(ctx, &rm_tmp, &rm_operand));

            LIFT_CTX_EMIT(ctx->lift_ctx, PIS_INSN1(PIS_OPCODE_JMP, rm_tmp));
        } else if (modrm.reg == 2) {
            // call r/m

            // decide the operand size
            pis_operand_size_t operand_size = ctx->operand_sizes.insn_default_not_64_bit;
            if (ctx->lift_ctx->pis_x86_ctx->cpumode == PIS_X86_CPUMODE_64_BIT) {
                operand_size = PIS_OPERAND_SIZE_8;
            }

            modrm_rm_operand_t rm_operand = {};
            CHECK_RETHROW(modrm_decode_rm_operand(ctx, &modrm, operand_size, &rm_operand));

            pis_operand_t rm_tmp = LIFT_CTX_NEW_TMP(ctx->lift_ctx, operand_size);
            CHECK_RETHROW(modrm_rm_read(ctx, &rm_tmp, &rm_operand));

            CHECK_RETHROW(push_rip(ctx));

            LIFT_CTX_EMIT(ctx->lift_ctx, PIS_INSN1(PIS_OPCODE_JMP, rm_tmp));
        } else if (modrm.reg == 1) {
            // dec r/m

            pis_operand_size_t operand_size = ctx->operand_sizes.insn_default_not_64_bit;

            modrm_rm_operand_t rm_operand = {};
            CHECK_RETHROW(modrm_decode_rm_operand(ctx, &modrm, operand_size, &rm_operand));

            pis_operand_t rm_tmp = LIFT_CTX_NEW_TMP(ctx->lift_ctx, operand_size);
            CHECK_RETHROW(modrm_rm_read(ctx, &rm_tmp, &rm_operand));

            pis_operand_t result = {};
            CHECK_RETHROW(do_dec(ctx, &rm_tmp, &result));

            CHECK_RETHROW(modrm_rm_write(ctx, &rm_operand, &result));
        } else {
            CHECK_FAIL_CODE(PIS_ERR_UNSUPPORTED_INSN);
        }

    } else if (first_opcode_byte == 0x83) {
        // xxx r/m, imm8
        CHECK_RETHROW(modrm_fetch_and_process(ctx, &modrm_operands));

        pis_operand_size_t operand_size = ctx->operand_sizes.insn_default_not_64_bit;
        pis_operand_t rm_tmp = LIFT_CTX_NEW_TMP(ctx->lift_ctx, operand_size);
        CHECK_RETHROW(modrm_operand_read(ctx, &rm_tmp, &modrm_operands.rm_operand));

        i8 imm8 = LIFT_CTX_CUR1_ADVANCE(ctx->lift_ctx);
        u64 imm64 = pis_sign_extend_byte(imm8, operand_size);

        if (modrm_operands.modrm.reg == 5) {
            // sub r/m, imm8
            pis_operand_t res_tmp = {};
            CHECK_RETHROW(do_sub(ctx, &rm_tmp, &PIS_OPERAND_CONST(imm64, operand_size), &res_tmp));

            CHECK_RETHROW(modrm_rm_write(ctx, &modrm_operands.rm_operand.rm, &res_tmp));
        } else if (modrm_operands.modrm.reg == 0) {
            // add r/m, imm8
            pis_operand_t res_tmp = {};
            CHECK_RETHROW(do_add(ctx, &rm_tmp, &PIS_OPERAND_CONST(imm64, operand_size), &res_tmp));

            CHECK_RETHROW(modrm_rm_write(ctx, &modrm_operands.rm_operand.rm, &res_tmp));
        } else if (modrm_operands.modrm.reg == 6) {
            // xor r/m, imm8
            pis_operand_t res_tmp = {};
            CHECK_RETHROW(do_xor(ctx, &rm_tmp, &PIS_OPERAND_CONST(imm64, operand_size), &res_tmp));

            CHECK_RETHROW(modrm_rm_write(ctx, &modrm_operands.rm_operand.rm, &res_tmp));
        } else if (modrm_operands.modrm.reg == 4) {
            // and r/m, imm8
            pis_operand_t res_tmp = {};
            CHECK_RETHROW(do_and(ctx, &rm_tmp, &PIS_OPERAND_CONST(imm64, operand_size), &res_tmp));

            CHECK_RETHROW(modrm_rm_write(ctx, &modrm_operands.rm_operand.rm, &res_tmp));
        } else if (modrm_operands.modrm.reg == 7) {
            // cmp r/m, imm8
            pis_operand_t res_tmp = {};
            CHECK_RETHROW(do_sub(ctx, &rm_tmp, &PIS_OPERAND_CONST(imm64, operand_size), &res_tmp));
        } else {
            CHECK_FAIL_CODE(PIS_ERR_UNSUPPORTED_INSN);
        }
    } else if (first_opcode_byte == 0xc0) {
        // xxx r/m8, imm8
        CHECK_RETHROW(modrm_fetch_and_process_with_operand_sizes(
            ctx,
            &modrm_operands,
            PIS_OPERAND_SIZE_1,
            PIS_OPERAND_SIZE_1
        ));

        u8 imm = LIFT_CTX_CUR1_ADVANCE(ctx->lift_ctx);
        pis_operand_t imm_operand = PIS_OPERAND_CONST(imm, PIS_OPERAND_SIZE_1);

        if (modrm_operands.modrm.reg == 5) {
            // shr r/m8, imm8
            pis_operand_t rm_tmp = LIFT_CTX_NEW_TMP(ctx->lift_ctx, PIS_OPERAND_SIZE_1);
            CHECK_RETHROW(modrm_operand_read(ctx, &rm_tmp, &modrm_operands.rm_operand));

            pis_operand_t res_tmp = {};
            CHECK_RETHROW(do_shr(ctx, &rm_tmp, &imm_operand, &res_tmp));

            CHECK_RETHROW(modrm_rm_write(ctx, &modrm_operands.rm_operand.rm, &res_tmp));
        } else {
            CHECK_FAIL_CODE(PIS_ERR_UNSUPPORTED_INSN);
        }
    } else if (first_opcode_byte == 0xf6) {
        // xxx r/m8, imm8
        CHECK_RETHROW(modrm_fetch_and_process_with_operand_sizes(
            ctx,
            &modrm_operands,
            PIS_OPERAND_SIZE_1,
            PIS_OPERAND_SIZE_1
        ));

        u8 imm = LIFT_CTX_CUR1_ADVANCE(ctx->lift_ctx);
        pis_operand_t imm_operand = PIS_OPERAND_CONST(imm, PIS_OPERAND_SIZE_1);

        if (modrm_operands.modrm.reg == 0) {
            // test r/m8, imm8
            pis_operand_t rm_tmp = LIFT_CTX_NEW_TMP(ctx->lift_ctx, PIS_OPERAND_SIZE_1);
            CHECK_RETHROW(modrm_operand_read(ctx, &rm_tmp, &modrm_operands.rm_operand));

            pis_operand_t res_tmp = {};
            CHECK_RETHROW(do_and(ctx, &rm_tmp, &imm_operand, &res_tmp));
        } else {
            CHECK_FAIL_CODE(PIS_ERR_UNSUPPORTED_INSN);
        }
    } else if (first_opcode_byte == 0xc6) {
        // xxx r/m8, imm8
        CHECK_RETHROW(modrm_fetch_and_process_with_operand_sizes(
            ctx,
            &modrm_operands,
            PIS_OPERAND_SIZE_1,
            PIS_OPERAND_SIZE_1
        ));

        u8 imm = LIFT_CTX_CUR1_ADVANCE(ctx->lift_ctx);
        pis_operand_t imm_operand = PIS_OPERAND_CONST(imm, PIS_OPERAND_SIZE_1);

        if (modrm_operands.modrm.reg == 0) {
            // mov r/m8, imm8
            CHECK_RETHROW(modrm_rm_write(ctx, &modrm_operands.rm_operand.rm, &imm_operand));
        } else {
            CHECK_FAIL_CODE(PIS_ERR_UNSUPPORTED_INSN);
        }
    } else if (first_opcode_byte == 0x80) {
        // xxx r/m8, imm8
        CHECK_RETHROW(modrm_fetch_and_process_with_operand_sizes(
            ctx,
            &modrm_operands,
            PIS_OPERAND_SIZE_1,
            PIS_OPERAND_SIZE_1
        ));

        u8 imm = LIFT_CTX_CUR1_ADVANCE(ctx->lift_ctx);
        pis_operand_t imm_operand = PIS_OPERAND_CONST(imm, PIS_OPERAND_SIZE_1);

        if (modrm_operands.modrm.reg == 7) {
            // cmp r/m8, imm8

            pis_operand_t dst_tmp = LIFT_CTX_NEW_TMP(ctx->lift_ctx, PIS_OPERAND_SIZE_1);
            CHECK_RETHROW(modrm_rm_read(ctx, &dst_tmp, &modrm_operands.rm_operand.rm));

            // perform subtraction but ignore the result
            pis_operand_t res = {};
            CHECK_RETHROW(do_sub(ctx, &dst_tmp, &imm_operand, &res));
        } else {
            CHECK_FAIL_CODE(PIS_ERR_UNSUPPORTED_INSN);
        }
    } else if (first_opcode_byte == 0xe9) {
        // jmp rel
        pis_operand_t target = {};
        CHECK_RETHROW(
            rel_jmp_fetch_disp_and_calc_target(ctx, rel_jmp_operand_size_16_32(ctx), &target)
        );

        LIFT_CTX_EMIT(ctx->lift_ctx, PIS_INSN1(PIS_OPCODE_JMP, target));
    } else if (first_opcode_byte == 0x74) {
        // je rel8
        CHECK_RETHROW(do_cond_rel_jmp(ctx, &FLAGS_ZF, PIS_OPERAND_SIZE_1));
    } else if (first_opcode_byte == 0x75) {
        // jne rel8
        pis_operand_t res_tmp = LIFT_CTX_NEW_TMP(ctx->lift_ctx, PIS_OPERAND_SIZE_1);
        CHECK_RETHROW(cond_negate(ctx, &res_tmp, &FLAGS_ZF));

        CHECK_RETHROW(do_cond_rel_jmp(ctx, &res_tmp, PIS_OPERAND_SIZE_1));
    } else if (first_opcode_byte == 0xe8) {
        // call rel
        pis_operand_t target = {};
        CHECK_RETHROW(
            rel_jmp_fetch_disp_and_calc_target(ctx, rel_jmp_operand_size_16_32(ctx), &target)
        );

        CHECK_RETHROW(push_rip(ctx));

        LIFT_CTX_EMIT(ctx->lift_ctx, PIS_INSN1(PIS_OPCODE_JMP, target));
    } else if (first_opcode_byte == 0xc3) {
        // ret
        pis_operand_size_t operand_size = ctx->lift_ctx->stack_addr_size;
        pis_operand_t sp = ctx->lift_ctx->sp;
        u64 operand_size_bytes = pis_operand_size_to_bytes(operand_size);

        pis_operand_t tmp = LIFT_CTX_NEW_TMP(ctx->lift_ctx, operand_size);

        LIFT_CTX_EMIT(ctx->lift_ctx, PIS_INSN2(PIS_OPCODE_LOAD, tmp, sp));

        LIFT_CTX_EMIT(
            ctx->lift_ctx,
            PIS_INSN_ADD2(sp, PIS_OPERAND_CONST(operand_size_bytes, sp.size))
        );

        LIFT_CTX_EMIT(ctx->lift_ctx, PIS_INSN1(PIS_OPCODE_JMP, tmp));
    } else if (opcode_reg_opcode_only(first_opcode_byte) == 0xb0) {
        // mov r8, imm8
        u8 imm = LIFT_CTX_CUR1_ADVANCE(ctx->lift_ctx);
        u8 reg_encoding = opcode_reg_extract(ctx, first_opcode_byte);
        pis_operand_t reg_operand =
            reg_get_operand(reg_encoding, PIS_OPERAND_SIZE_1, ctx->prefixes);
        CHECK_RETHROW(write_gpr(ctx, &reg_operand, &PIS_OPERAND_CONST(imm, PIS_OPERAND_SIZE_1)));
    } else if (first_opcode_byte == 0x88) {
        // mov r/m8, r8
        CHECK_RETHROW(modrm_fetch_and_process_with_operand_sizes(
            ctx,
            &modrm_operands,
            PIS_OPERAND_SIZE_1,
            PIS_OPERAND_SIZE_1
        ));
        CHECK_RETHROW(
            modrm_rm_write(ctx, &modrm_operands.rm_operand.rm, &modrm_operands.reg_operand.reg)
        );
    } else if (first_opcode_byte == 0x84) {
        // test r/m8, r8
        CHECK_RETHROW(modrm_fetch_and_process_with_operand_sizes(
            ctx,
            &modrm_operands,
            PIS_OPERAND_SIZE_1,
            PIS_OPERAND_SIZE_1
        ));

        pis_operand_t res = {};
        CHECK_RETHROW(calc_binop_modrm(
            ctx,
            do_and,
            &modrm_operands.rm_operand,
            &modrm_operands.reg_operand,
            &res
        ));
    } else if (first_opcode_byte == 0x8a) {
        // mov r8, r/m8
        CHECK_RETHROW(modrm_fetch_and_process_with_operand_sizes(
            ctx,
            &modrm_operands,
            PIS_OPERAND_SIZE_1,
            PIS_OPERAND_SIZE_1
        ));
        pis_operand_t tmp = LIFT_CTX_NEW_TMP(ctx->lift_ctx, PIS_OPERAND_SIZE_1);
        CHECK_RETHROW(modrm_rm_read(ctx, &tmp, &modrm_operands.rm_operand.rm));
        CHECK_RETHROW(write_gpr(ctx, &modrm_operands.reg_operand.reg, &tmp));
    } else if (first_opcode_byte == 0x24) {
        // mov al, imm8
        u8 imm = LIFT_CTX_CUR1_ADVANCE(ctx->lift_ctx);
        CHECK_RETHROW(write_gpr(ctx, &AL, &PIS_OPERAND_CONST(imm, PIS_OPERAND_SIZE_1)));
    } else if (first_opcode_byte == 0x34) {
        // xor al, imm8
        u8 imm = LIFT_CTX_CUR1_ADVANCE(ctx->lift_ctx);

        pis_operand_t res = {};
        CHECK_RETHROW(do_xor(ctx, &AL, &PIS_OPERAND_CONST(imm, PIS_OPERAND_SIZE_1), &res));
        CHECK_RETHROW(write_gpr(ctx, &AL, &res));
    } else if (opcode_reg_opcode_only(first_opcode_byte) == 0xb8) {
        // mov <reg>, imm
        u8 reg_encoding = opcode_reg_extract(ctx, first_opcode_byte);
        pis_operand_size_t operand_size = ctx->operand_sizes.insn_default_not_64_bit;
        pis_operand_t dst_reg = reg_get_operand(reg_encoding, operand_size, ctx->prefixes);

        pis_operand_t imm = {};
        CHECK_RETHROW(fetch_imm_operand(ctx, operand_size, &imm));

        CHECK_RETHROW(write_gpr(ctx, &dst_reg, &imm));
    } else if (first_opcode_byte == 0xc7) {
        // xxx r/m, imm
        CHECK_RETHROW(modrm_fetch_and_process(ctx, &modrm_operands));

        pis_operand_t imm = {};
        CHECK_RETHROW(fetch_sign_extended_imm_operand(ctx, &imm));

        if (modrm_operands.modrm.reg == 0) {
            // mov r/m, imm
            CHECK_RETHROW(modrm_rm_write(ctx, &modrm_operands.rm_operand.rm, &imm));
        } else {
            CHECK_FAIL_CODE(PIS_ERR_UNSUPPORTED_INSN);
        }
    } else if (first_opcode_byte == 0x25) {
        // and [R/E]AX, imm
        pis_operand_t imm = {};
        CHECK_RETHROW(fetch_sign_extended_imm_operand(ctx, &imm));

        pis_operand_t ax = get_ax_operand_of_size(ctx->operand_sizes.insn_default_not_64_bit);

        pis_operand_t res = {};
        CHECK_RETHROW(do_and(ctx, &ax, &imm, &res));

        CHECK_RETHROW(write_gpr(ctx, &ax, &res));
    } else if (first_opcode_byte == 0x2d) {
        // sub [R/E]AX, imm
        pis_operand_t imm = {};
        CHECK_RETHROW(fetch_sign_extended_imm_operand(ctx, &imm));

        pis_operand_t ax = get_ax_operand_of_size(ctx->operand_sizes.insn_default_not_64_bit);

        pis_operand_t res = {};
        CHECK_RETHROW(do_sub(ctx, &ax, &imm, &res));

        CHECK_RETHROW(write_gpr(ctx, &ax, &res));
    } else if (first_opcode_byte == 0x05) {
        // add [R/E]AX, imm
        pis_operand_t imm = {};
        CHECK_RETHROW(fetch_sign_extended_imm_operand(ctx, &imm));

        pis_operand_t ax = get_ax_operand_of_size(ctx->operand_sizes.insn_default_not_64_bit);

        pis_operand_t res = {};
        CHECK_RETHROW(do_add(ctx, &ax, &imm, &res));

        CHECK_RETHROW(write_gpr(ctx, &ax, &res));
    } else if (first_opcode_byte == 0x3d) {
        // cmp [R/E]AX, imm
        pis_operand_t imm = {};
        CHECK_RETHROW(fetch_sign_extended_imm_operand(ctx, &imm));

        pis_operand_t ax = get_ax_operand_of_size(ctx->operand_sizes.insn_default_not_64_bit);

        pis_operand_t res = {};
        CHECK_RETHROW(do_sub(ctx, &ax, &imm, &res));
    } else if (first_opcode_byte == 0x81) {
        // xxx r/m, imm
        CHECK_RETHROW(modrm_fetch_and_process(ctx, &modrm_operands));

        pis_operand_t imm = {};
        CHECK_RETHROW(fetch_sign_extended_imm_operand(ctx, &imm));

        if (modrm_operands.modrm.reg == 7) {
            // cmp r/m, imm

            // perform subtraction but ignore the result
            pis_operand_t res = {};
            CHECK_RETHROW(calc_binop_modrm_imm(ctx, do_sub, &modrm_operands.rm_operand, &imm, &res)
            );
        } else if (modrm_operands.modrm.reg == 0) {
            // add r/m, imm
            CHECK_RETHROW(
                calc_and_store_binop_modrm_imm(ctx, do_add, &modrm_operands.rm_operand, &imm)
            );
        } else if (modrm_operands.modrm.reg == 5) {
            // sub r/m, imm
            CHECK_RETHROW(
                calc_and_store_binop_modrm_imm(ctx, do_sub, &modrm_operands.rm_operand, &imm)
            );
        } else {
            CHECK_FAIL_CODE(PIS_ERR_UNSUPPORTED_INSN);
        }
    } else if (first_opcode_byte == 0xa8) {
        // test al, imm8
        u8 imm = LIFT_CTX_CUR1_ADVANCE(ctx->lift_ctx);

        pis_operand_t res = {};
        CHECK_RETHROW(do_and(ctx, &AL, &PIS_OPERAND_CONST(imm, PIS_OPERAND_SIZE_1), &res));
    } else if (first_opcode_byte == 0x85) {
        // test r/m, r
        CHECK_RETHROW(modrm_fetch_and_process(ctx, &modrm_operands));

        pis_operand_t res = {};
        CHECK_RETHROW(calc_binop_modrm(
            ctx,
            do_add,
            &modrm_operands.rm_operand,
            &modrm_operands.reg_operand,
            &res
        ));
    } else if (first_opcode_byte == 0x6b) {
        // imul r, r/m, imm8
        CHECK_RETHROW(modrm_fetch_and_process(ctx, &modrm_operands));

        pis_operand_size_t operand_size = ctx->operand_sizes.insn_default_not_64_bit;

        i8 imm8 = LIFT_CTX_CUR1_ADVANCE(ctx->lift_ctx);
        u64 imm = pis_sign_extend_byte(imm8, operand_size);
        pis_operand_t imm_operand = PIS_OPERAND_CONST(imm, operand_size);

        pis_operand_t rm_value = LIFT_CTX_NEW_TMP(ctx->lift_ctx, operand_size);
        CHECK_RETHROW(modrm_rm_read(ctx, &rm_value, &modrm_operands.rm_operand.rm));

        pis_operand_t res = LIFT_CTX_NEW_TMP(ctx->lift_ctx, operand_size);
        CHECK_RETHROW(do_imul(ctx, &rm_value, &imm_operand, &res));

        CHECK_RETHROW(write_gpr(ctx, &modrm_operands.reg_operand.reg, &res));
    } else if (first_opcode_byte == 0x98) {
        // cbw/cwde/cdqe
        pis_operand_size_t operand_size = ctx->operand_sizes.insn_default_not_64_bit;
        pis_operand_size_t half_operand_size = operand_size / 2;

        pis_operand_t tmp = LIFT_CTX_NEW_TMP(ctx->lift_ctx, operand_size);
        LIFT_CTX_EMIT(
            ctx->lift_ctx,
            PIS_INSN2(
                PIS_OPCODE_SIGN_EXTEND,
                // ,
                tmp,
                get_ax_operand_of_size(half_operand_size)
            )
        );

        pis_operand_t dst = get_ax_operand_of_size(operand_size);
        CHECK_RETHROW(write_gpr(ctx, &dst, &tmp));
    } else if (first_opcode_byte == 0xc1) {
        // xxx r/m, imm8
        CHECK_RETHROW(modrm_fetch_and_process(ctx, &modrm_operands));

        pis_operand_size_t operand_size = ctx->operand_sizes.insn_default_not_64_bit;
        pis_operand_t rm_tmp = LIFT_CTX_NEW_TMP(ctx->lift_ctx, operand_size);
        CHECK_RETHROW(modrm_operand_read(ctx, &rm_tmp, &modrm_operands.rm_operand));

        u8 imm8 = LIFT_CTX_CUR1_ADVANCE(ctx->lift_ctx);

        if (modrm_operands.modrm.reg == 4) {
            // shl/sal r/m, imm8
            pis_operand_t res_tmp = {};
            CHECK_RETHROW(do_shl(ctx, &rm_tmp, &PIS_OPERAND_CONST(imm8, operand_size), &res_tmp));

            CHECK_RETHROW(modrm_rm_write(ctx, &modrm_operands.rm_operand.rm, &res_tmp));
        } else if (modrm_operands.modrm.reg == 5) {
            // shr r/m, imm8
            pis_operand_t res_tmp = {};
            CHECK_RETHROW(do_shr(ctx, &rm_tmp, &PIS_OPERAND_CONST(imm8, operand_size), &res_tmp));

            CHECK_RETHROW(modrm_rm_write(ctx, &modrm_operands.rm_operand.rm, &res_tmp));
        } else if (modrm_operands.modrm.reg == 7) {
            // sar r/m, imm8
            pis_operand_t res_tmp = {};
            CHECK_RETHROW(do_sar(ctx, &rm_tmp, &PIS_OPERAND_CONST(imm8, operand_size), &res_tmp));

            CHECK_RETHROW(modrm_rm_write(ctx, &modrm_operands.rm_operand.rm, &res_tmp));
        } else {
            CHECK_FAIL_CODE(PIS_ERR_UNSUPPORTED_INSN);
        }
    } else if (first_opcode_byte == 0xd1) {
        // xxx r/m, 1
        CHECK_RETHROW(modrm_fetch_and_process(ctx, &modrm_operands));

        pis_operand_size_t operand_size = ctx->operand_sizes.insn_default_not_64_bit;
        pis_operand_t rm_tmp = LIFT_CTX_NEW_TMP(ctx->lift_ctx, operand_size);
        CHECK_RETHROW(modrm_operand_read(ctx, &rm_tmp, &modrm_operands.rm_operand));

        if (modrm_operands.modrm.reg == 4) {
            // shl/sal r/m, 1
            pis_operand_t res_tmp = {};
            CHECK_RETHROW(do_shl(ctx, &rm_tmp, &PIS_OPERAND_CONST(1, operand_size), &res_tmp));

            CHECK_RETHROW(modrm_rm_write(ctx, &modrm_operands.rm_operand.rm, &res_tmp));
        } else if (modrm_operands.modrm.reg == 5) {
            // shr r/m, 1
            pis_operand_t res_tmp = {};
            CHECK_RETHROW(do_shr(ctx, &rm_tmp, &PIS_OPERAND_CONST(1, operand_size), &res_tmp));

            CHECK_RETHROW(modrm_rm_write(ctx, &modrm_operands.rm_operand.rm, &res_tmp));
        } else if (modrm_operands.modrm.reg == 7) {
            // sar r/m, 1
            pis_operand_t res_tmp = {};
            CHECK_RETHROW(do_sar(ctx, &rm_tmp, &PIS_OPERAND_CONST(1, operand_size), &res_tmp));

            CHECK_RETHROW(modrm_rm_write(ctx, &modrm_operands.rm_operand.rm, &res_tmp));
        } else {
            CHECK_FAIL_CODE(PIS_ERR_UNSUPPORTED_INSN);
        }
    } else if (first_opcode_byte == 0xd3) {
        // xxx r/m, cl
        CHECK_RETHROW(modrm_fetch_and_process(ctx, &modrm_operands));

        pis_operand_size_t operand_size = ctx->operand_sizes.insn_default_not_64_bit;
        pis_operand_t rm_tmp = LIFT_CTX_NEW_TMP(ctx->lift_ctx, operand_size);
        CHECK_RETHROW(modrm_operand_read(ctx, &rm_tmp, &modrm_operands.rm_operand));

        pis_operand_t cl_zero_extended = LIFT_CTX_NEW_TMP(ctx->lift_ctx, operand_size);
        LIFT_CTX_EMIT(ctx->lift_ctx, PIS_INSN2(PIS_OPCODE_ZERO_EXTEND, cl_zero_extended, CL));

        if (modrm_operands.modrm.reg == 4) {
            // shl/sal r/m, cl
            pis_operand_t res_tmp = {};
            CHECK_RETHROW(do_shl(ctx, &rm_tmp, &cl_zero_extended, &res_tmp));

            CHECK_RETHROW(modrm_rm_write(ctx, &modrm_operands.rm_operand.rm, &res_tmp));
        } else if (modrm_operands.modrm.reg == 5) {
            // shr r/m, cl
            pis_operand_t res_tmp = {};
            CHECK_RETHROW(do_shr(ctx, &rm_tmp, &cl_zero_extended, &res_tmp));

            CHECK_RETHROW(modrm_rm_write(ctx, &modrm_operands.rm_operand.rm, &res_tmp));
        } else if (modrm_operands.modrm.reg == 5) {
            // shr r/m, cl
            pis_operand_t res_tmp = {};
            CHECK_RETHROW(do_shr(ctx, &rm_tmp, &cl_zero_extended, &res_tmp));

            CHECK_RETHROW(modrm_rm_write(ctx, &modrm_operands.rm_operand.rm, &res_tmp));
        } else if (modrm_operands.modrm.reg == 7) {
            // sar r/m, cl
            pis_operand_t res_tmp = {};
            CHECK_RETHROW(do_sar(ctx, &rm_tmp, &cl_zero_extended, &res_tmp));

            CHECK_RETHROW(modrm_rm_write(ctx, &modrm_operands.rm_operand.rm, &res_tmp));
        } else {
            CHECK_FAIL_CODE(PIS_ERR_UNSUPPORTED_INSN);
        }
    } else if (first_opcode_byte == 0x0f) {
        // opcode is longer than 1 byte
        u8 second_opcode_byte = LIFT_CTX_CUR1_ADVANCE(ctx->lift_ctx);

        CHECK_RETHROW(lift_second_opcode_byte(ctx, second_opcode_byte));
    } else if (first_opcode_byte == 0xf4) {
        // hlt
        LIFT_CTX_EMIT(ctx->lift_ctx, PIS_INSN0(PIS_OPCODE_HALT));
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

static err_t rep_lift_second_opcode_byte(const post_prefixes_ctx_t* ctx, u8 second_opcode_byte) {
    err_t err = SUCCESS;

    if (second_opcode_byte == 0x1e) {
        // endbr32/64

        // endbr must use a REP prefix
        CHECK(prefixes_contain_legacy_prefix(ctx->prefixes, LEGACY_PREFIX_REPZ_OR_REP));

        // endbr must be followed by a 0xfa or 0xfb byte
        u8 next_byte = LIFT_CTX_CUR1_ADVANCE(ctx->lift_ctx);
        CHECK(next_byte == 0xfa || next_byte == 0xfb);

        // endbr is a nop, so emit nothing.
    } else {
        CHECK_FAIL_TRACE_CODE(
            PIS_ERR_UNSUPPORTED_INSN,
            "unsupported second opcode byte with rep prefix: 0x%x",
            second_opcode_byte
        );
    }
cleanup:
    return err;
}

static err_t rep_lift_first_opcode_byte(const post_prefixes_ctx_t* ctx, u8 first_opcode_byte) {
    err_t err = SUCCESS;

    if (first_opcode_byte == 0x0f) {
        // opcode is longer than 1 byte
        u8 second_opcode_byte = LIFT_CTX_CUR1_ADVANCE(ctx->lift_ctx);

        CHECK_RETHROW(rep_lift_second_opcode_byte(ctx, second_opcode_byte));
    } else {
        CHECK_FAIL_TRACE_CODE(
            PIS_ERR_UNSUPPORTED_INSN,
            "unsupported first opcode byte with rep prefix: 0x%x",
            first_opcode_byte
        );
    }
cleanup:
    return err;
}

static err_t post_prefixes_lift(const post_prefixes_ctx_t* ctx) {
    err_t err = SUCCESS;

    u8 first_opcode_byte = LIFT_CTX_CUR1_ADVANCE(ctx->lift_ctx);

    switch (ctx->prefixes->legacy.by_group[LEGACY_PREFIX_GROUP_1]) {
    case LEGACY_PREFIX_LOCK:
        UNREACHABLE();
    case LEGACY_PREFIX_REPNZ_OR_BND:
        UNREACHABLE();
    case LEGACY_PREFIX_REPZ_OR_REP:
        CHECK_RETHROW(rep_lift_first_opcode_byte(ctx, first_opcode_byte));
        break;
    case LEGACY_PREFIX_INVALID:
        // no group-1 prefix, regular opcode
        CHECK_RETHROW(lift_first_opcode_byte(ctx, first_opcode_byte));
        break;
    default:
        UNREACHABLE();
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
        .cur_tmp_offset = 0,
        .result = result,
        .stack_addr_size = get_effective_stack_addr_size(ctx->cpumode),
        .sp = get_sp_operand(ctx->cpumode),
    };
    CHECK_RETHROW(lift(&lift_ctx));

    result->machine_insn_len = lift_ctx_index(&lift_ctx);

cleanup:
    return err;
}
