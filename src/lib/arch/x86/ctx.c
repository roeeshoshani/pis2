#include "ctx.h"
#include "../../errors.h"
#include "../../except.h"
#include "../../pis.h"
#include "lift_ctx.h"
#include "modrm.h"
#include "prefixes.h"
#include "regs.h"

#include "x86_tables/types.h"

#include "x86_tables/tables.h"

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

typedef enum {
    LIFTED_OP_KIND_VALUE,
    LIFTED_OP_KIND_WRITABLE_VALUE,
    LIFTED_OP_KIND_MEM,
    LIFTED_OP_KIND_IMPLICIT,
} lifted_op_kind_t;

typedef struct {
    pis_operand_t addr;
    pis_operand_size_t size;
} lifted_op_mem_t;

typedef struct {
    lifted_op_kind_t kind;
    union {
        pis_operand_t value;
        lifted_op_mem_t mem;
        struct {
            pis_operand_size_t size;
        } implicit;
    };
} lifted_op_t;

typedef err_t (*mnemonic_handler_t
)(const insn_ctx_t* ctx, const lifted_op_t* ops, size_t ops_amount);

/// extracts the condition encoding of an opcode which has a condition encoded in its value.
static u8 opcode_cond_extract(u8 opcode_byte) {
    return opcode_byte & 0b1111;
}

/// returns the base opcode value of an opcode which has a condition encoded in its value.
static u8 opcode_cond_opcode_only(u8 opcode_byte) {
    return opcode_byte & (~0b1111);
}

/// decodes an x86 condition encoding. the encoding can usually be achieved by subtrating the opcode
/// with some base opcode value.
static err_t cond_decode(u8 cond_encoding, x86_cond_t* cond) {
    err_t err = SUCCESS;

    CHECK(cond_encoding <= X86_COND_ENCODING_MAX_VALUE);

    cond->is_negative = cond_encoding & 1;
    cond->kind = cond_encoding >> 1;

cleanup:
    return err;
}

/// calculates the given x86 condition type into the given result operand.
static err_t calc_cond(const insn_ctx_t* ctx, const x86_cond_t cond, pis_operand_t* result) {
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
        LIFT_CTX_EMIT(ctx->lift_ctx, PIS_INSN2(PIS_OPCODE_COND_NEGATE, negated, tmp));
        *result = negated;
    } else {
        *result = tmp;
    }

cleanup:
    return err;
}

/// decodes an x86 condition encoding from the given opcode and calculates its value into the given
/// result operand.
static err_t
    cond_opcode_decode_and_calc(const insn_ctx_t* ctx, u8 opcode_byte, pis_operand_t* result) {
    err_t err = SUCCESS;

    x86_cond_t cond = {};
    CHECK_RETHROW(cond_decode(opcode_cond_extract(opcode_byte), &cond));

    CHECK_RETHROW(calc_cond(ctx, cond, result));

cleanup:
    return err;
}

/// returns the operand size corresponding to the given cpumode.
static pis_operand_size_t cpumode_get_operand_size(pis_x86_cpumode_t cpumode) {
    switch (cpumode) {
        case PIS_X86_CPUMODE_64_BIT:
            return PIS_OPERAND_SIZE_8;
        case PIS_X86_CPUMODE_32_BIT:
            return PIS_OPERAND_SIZE_4;
        default:
            // unreachable
            return PIS_OPERAND_SIZE_1;
    }
}

/// returns the effective stack address size. this is the size of the `sp` register to be used in
/// stack-addressing operations.
static pis_operand_size_t get_effective_stack_addr_size(pis_x86_cpumode_t cpumode) {
    return cpumode_get_operand_size(cpumode);
}

/// resizes the given operand to the given new size.
static pis_operand_t operand_resize(const pis_operand_t* operand, pis_operand_size_t size) {
    return PIS_OPERAND(operand->addr, size);
}

/// calculates the effective operand size for the instruction.
static pis_operand_size_t get_effective_operand_size(
    pis_x86_cpumode_t cpumode, const prefixes_t* prefixes, bool default_to_64_bit
) {
    bool has_size_override =
        prefixes_contain_legacy_prefix(prefixes, LEGACY_PREFIX_OPERAND_SIZE_OVERRIDE);

    switch (cpumode) {
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

/// calculates the effective address size of an instruction.
static pis_operand_size_t
    get_effective_addr_size(pis_x86_cpumode_t cpumode, const prefixes_t* prefixes) {
    bool has_size_override =
        prefixes_contain_legacy_prefix(prefixes, LEGACY_PREFIX_ADDRESS_SIZE_OVERRIDE);

    switch (cpumode) {
        case PIS_X86_CPUMODE_32_BIT:
            return has_size_override ? PIS_OPERAND_SIZE_2 : PIS_OPERAND_SIZE_4;
        case PIS_X86_CPUMODE_64_BIT:
            return has_size_override ? PIS_OPERAND_SIZE_4 : PIS_OPERAND_SIZE_8;
        default:
            // unreachable
            return PIS_OPERAND_SIZE_1;
    }
}

/// calculates the parity flag of the given value into the given result operand.
static err_t calc_parity_flag_into(
    const insn_ctx_t* ctx, const pis_operand_t* value, const pis_operand_t* result
) {
    err_t err = SUCCESS;

    pis_operand_t low_byte;
    if (value->size != PIS_OPERAND_SIZE_1) {
        low_byte = LIFT_CTX_NEW_TMP(ctx->lift_ctx, PIS_OPERAND_SIZE_1);
        LIFT_CTX_EMIT(ctx->lift_ctx, PIS_INSN2(PIS_OPCODE_GET_LOW_BITS, low_byte, *value));
    } else {
        low_byte = *value;
    }
    LIFT_CTX_EMIT(ctx->lift_ctx, PIS_INSN2(PIS_OPCODE_PARITY, *result, low_byte));

cleanup:
    return err;
}

/// calculates the parity flag of the given calculation result into the parity flag register.
static err_t calc_parity_flag(const insn_ctx_t* ctx, const pis_operand_t* calculation_result) {
    err_t err = SUCCESS;

    CHECK_RETHROW(calc_parity_flag_into(ctx, calculation_result, &FLAGS_PF));

cleanup:
    return err;
}

/// calculates the zero flag of the given value into the given result operand.
static err_t calc_zero_flag_into(
    const insn_ctx_t* ctx, const pis_operand_t* value, const pis_operand_t* result
) {
    err_t err = SUCCESS;

    LIFT_CTX_EMIT(
        ctx->lift_ctx,
        PIS_INSN3(PIS_OPCODE_EQUALS, *result, *value, PIS_OPERAND_CONST(0, value->size))
    );

cleanup:
    return err;
}

/// calculates the zero flag of the given calculation result into the zero flag register.
static err_t calc_zero_flag(const insn_ctx_t* ctx, const pis_operand_t* calculation_result) {
    err_t err = SUCCESS;

    CHECK_RETHROW(calc_zero_flag_into(ctx, calculation_result, &FLAGS_ZF));

cleanup:
    return err;
}

/// extracts the most significant bit of the given value into the given result operand.
/// the output is a 1 byte conditional expression which indicates whether the sign bit of the given
/// value is enabled.
static err_t extract_most_significant_bit(
    const insn_ctx_t* ctx, const pis_operand_t* value, const pis_operand_t* result
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

    // write the result into the result operand, while optionally truncating its size
    LIFT_CTX_EMIT(
        ctx->lift_ctx,
        PIS_INSN2(
            value->size == PIS_OPERAND_SIZE_1 ? PIS_OPCODE_MOVE : PIS_OPCODE_GET_LOW_BITS,
            *result,
            tmp
        )
    );

cleanup:
    return err;
}

/// extracts the least significant bit of the given value into the given result operand.
/// the output is a 1 byte conditional expression which indicates whether the sign bit of the given
/// value is enabled.
static err_t extract_least_significant_bit(
    const insn_ctx_t* ctx, const pis_operand_t* value, const pis_operand_t* result
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

/// calculates the sign flag of the given calculation result into the sign flag register.
static err_t calc_sign_flag(const insn_ctx_t* ctx, const pis_operand_t* calculation_result) {
    err_t err = SUCCESS;

    CHECK_RETHROW(extract_most_significant_bit(ctx, calculation_result, &FLAGS_SF));

cleanup:
    return err;
}

/// calculates the parity, zero and sign flags according to the given calculation results and stores
/// the flag values into their appropriate flag registers.
static err_t
    calc_parity_zero_sign_flags(const insn_ctx_t* ctx, const pis_operand_t* calculation_result) {
    err_t err = SUCCESS;

    CHECK_RETHROW(calc_parity_flag(ctx, calculation_result));
    CHECK_RETHROW(calc_zero_flag(ctx, calculation_result));
    CHECK_RETHROW(calc_sign_flag(ctx, calculation_result));

cleanup:
    return err;
}

/// performs an `ADD` operation on the 2 input operands `a` and `b` and returns an operand
/// containing the result of the operation in `result`.
static err_t binop_add(
    const insn_ctx_t* ctx, const pis_operand_t* a, const pis_operand_t* b, pis_operand_t* result
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

/// performs an `ADC` operation on the 2 input operands `a` and `b` and returns an operand
/// containing the result of the operation in `result`.
static err_t binop_adc(
    const insn_ctx_t* ctx, const pis_operand_t* a, const pis_operand_t* b, pis_operand_t* result
) {
    err_t err = SUCCESS;

    CHECK(a->size == b->size);
    pis_operand_size_t operand_size = a->size;

    pis_operand_t orig_cf = LIFT_CTX_NEW_TMP(ctx->lift_ctx, PIS_OPERAND_SIZE_1);
    LIFT_CTX_EMIT(ctx->lift_ctx, PIS_INSN2(PIS_OPCODE_MOVE, orig_cf, FLAGS_CF));

    pis_operand_t a_plus_b = LIFT_CTX_NEW_TMP(ctx->lift_ctx, operand_size);
    LIFT_CTX_EMIT(ctx->lift_ctx, PIS_INSN3(PIS_OPCODE_ADD, a_plus_b, *a, *b));

    // carry flag
    pis_operand_t carry_first_cond = LIFT_CTX_NEW_TMP(ctx->lift_ctx, PIS_OPERAND_SIZE_1);
    LIFT_CTX_EMIT(ctx->lift_ctx, PIS_INSN3(PIS_OPCODE_UNSIGNED_CARRY, carry_first_cond, *a, *b));

    pis_operand_t carry_second_cond = LIFT_CTX_NEW_TMP(ctx->lift_ctx, PIS_OPERAND_SIZE_1);
    LIFT_CTX_EMIT(
        ctx->lift_ctx,
        PIS_INSN3(PIS_OPCODE_UNSIGNED_CARRY, carry_second_cond, a_plus_b, orig_cf)
    );

    LIFT_CTX_EMIT(
        ctx->lift_ctx,
        PIS_INSN3(PIS_OPCODE_OR, FLAGS_CF, carry_first_cond, carry_second_cond)
    );

    // overflow flag
    pis_operand_t overflow_first_cond = LIFT_CTX_NEW_TMP(ctx->lift_ctx, PIS_OPERAND_SIZE_1);
    LIFT_CTX_EMIT(ctx->lift_ctx, PIS_INSN3(PIS_OPCODE_SIGNED_CARRY, overflow_first_cond, *a, *b));

    pis_operand_t overflow_second_cond = LIFT_CTX_NEW_TMP(ctx->lift_ctx, PIS_OPERAND_SIZE_1);
    LIFT_CTX_EMIT(
        ctx->lift_ctx,
        PIS_INSN3(PIS_OPCODE_SIGNED_CARRY, overflow_second_cond, a_plus_b, orig_cf)
    );

    LIFT_CTX_EMIT(
        ctx->lift_ctx,
        PIS_INSN3(PIS_OPCODE_OR, FLAGS_OF, overflow_first_cond, overflow_second_cond)
    );

    // perform the actual addition
    pis_operand_t res_tmp = LIFT_CTX_NEW_TMP(ctx->lift_ctx, operand_size);
    LIFT_CTX_EMIT(ctx->lift_ctx, PIS_INSN3(PIS_OPCODE_ADD, res_tmp, a_plus_b, orig_cf));

    CHECK_RETHROW(calc_parity_zero_sign_flags(ctx, &res_tmp));

    *result = res_tmp;

cleanup:
    return err;
}

/// performs an `SUB` operation on the 2 input operands `a` and `b` and returns an operand
/// containing the result of the operation in `result`.
static err_t binop_sub(
    const insn_ctx_t* ctx, const pis_operand_t* a, const pis_operand_t* b, pis_operand_t* result
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

/// performs a `DEC` operation on the input operand and returns an operand
/// containing the result of the operation in `result`.
static err_t
    unary_op_dec(const insn_ctx_t* ctx, const pis_operand_t* operand, pis_operand_t* result) {
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

/// performs an `INC` operation on the input operand and returns an operand
/// containing the result of the operation in `result`.
static err_t
    unary_op_inc(const insn_ctx_t* ctx, const pis_operand_t* operand, pis_operand_t* result) {
    err_t err = SUCCESS;

    pis_operand_size_t operand_size = operand->size;

    pis_operand_t one = PIS_OPERAND_CONST(1, operand_size);

    // overflow flag
    LIFT_CTX_EMIT(ctx->lift_ctx, PIS_INSN3(PIS_OPCODE_SIGNED_CARRY, FLAGS_OF, *operand, one));

    // perform the actual subtraction
    pis_operand_t res_tmp = LIFT_CTX_NEW_TMP(ctx->lift_ctx, operand_size);
    LIFT_CTX_EMIT(ctx->lift_ctx, PIS_INSN3(PIS_OPCODE_ADD, res_tmp, *operand, one));

    CHECK_RETHROW(calc_parity_zero_sign_flags(ctx, &res_tmp));

    *result = res_tmp;

cleanup:
    return err;
}

/// performs a `NEG` operation on the input operand and returns an operand
/// containing the result of the operation in `result`.
static err_t
    unary_op_neg(const insn_ctx_t* ctx, const pis_operand_t* operand, pis_operand_t* result) {
    err_t err = SUCCESS;

    pis_operand_size_t operand_size = operand->size;

    pis_operand_t zero = PIS_OPERAND_CONST(0, operand_size);

    // carry flag
    pis_operand_t equals_zero = LIFT_CTX_NEW_TMP(ctx->lift_ctx, PIS_OPERAND_SIZE_1);
    LIFT_CTX_EMIT(ctx->lift_ctx, PIS_INSN3(PIS_OPCODE_EQUALS, equals_zero, *operand, zero));
    LIFT_CTX_EMIT(ctx->lift_ctx, PIS_INSN2(PIS_OPCODE_COND_NEGATE, FLAGS_CF, equals_zero));

    // perform the actual negation
    pis_operand_t res_tmp = LIFT_CTX_NEW_TMP(ctx->lift_ctx, operand_size);
    LIFT_CTX_EMIT(ctx->lift_ctx, PIS_INSN2(PIS_OPCODE_NEG, res_tmp, *operand));

    CHECK_RETHROW(calc_parity_zero_sign_flags(ctx, &res_tmp));

    *result = res_tmp;

cleanup:
    return err;
}

/// performs a `NOT` operation on the input operand and returns an operand
/// containing the result of the operation in `result`.
static err_t
    unary_op_not(const insn_ctx_t* ctx, const pis_operand_t* operand, pis_operand_t* result) {
    err_t err = SUCCESS;

    pis_operand_size_t operand_size = operand->size;

    // perform the actual not operation
    pis_operand_t res_tmp = LIFT_CTX_NEW_TMP(ctx->lift_ctx, operand_size);
    LIFT_CTX_EMIT(ctx->lift_ctx, PIS_INSN2(PIS_OPCODE_NOT, res_tmp, *operand));

    *result = res_tmp;

cleanup:
    return err;
}

/// performs an `AND` operation on the 2 input operands `a` and `b` and returns an operand
/// containing the result of the operation in `result`.
static err_t binop_and(
    const insn_ctx_t* ctx, const pis_operand_t* a, const pis_operand_t* b, pis_operand_t* result
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

/// performs an `IMUL` operation on the 2 input operands `a` and `b` and returns an operand
/// containing the result of the operation in `result`.
static err_t binop_imul(
    const insn_ctx_t* ctx, const pis_operand_t* a, const pis_operand_t* b, pis_operand_t* result
) {
    err_t err = SUCCESS;

    CHECK(a->size == b->size);
    pis_operand_size_t operand_size = a->size;

    // update CF
    LIFT_CTX_EMIT(ctx->lift_ctx, PIS_INSN3(PIS_OPCODE_SIGNED_MUL_OVERFLOW, FLAGS_CF, *a, *b));

    // update OF
    LIFT_CTX_EMIT(ctx->lift_ctx, PIS_INSN2(PIS_OPCODE_MOVE, FLAGS_OF, FLAGS_CF));

    // perform the actual multiplication
    pis_operand_t res_tmp = LIFT_CTX_NEW_TMP(ctx->lift_ctx, operand_size);
    LIFT_CTX_EMIT(ctx->lift_ctx, PIS_INSN3(PIS_OPCODE_SIGNED_MUL, res_tmp, *a, *b));

    *result = res_tmp;

cleanup:
    return err;
}

/// performs a `XOR` operation on the 2 input operands `a` and `b` and returns an operand
/// containing the result of the operation in `result`.
static err_t binop_xor(
    const insn_ctx_t* ctx, const pis_operand_t* a, const pis_operand_t* b, pis_operand_t* result
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

/// performs an `OR` operation on the 2 input operands `a` and `b` and returns an operand
/// containing the result of the operation in `result`.
static err_t binop_or(
    const insn_ctx_t* ctx, const pis_operand_t* a, const pis_operand_t* b, pis_operand_t* result
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

/// the prototype for a binary operation function - that is an operation which takes 2 input
/// operands and produces a single result, for example an `ADD` operation.
typedef err_t (*binop_fn_t
)(const insn_ctx_t* ctx, const pis_operand_t* a, const pis_operand_t* b, pis_operand_t* result);

/// the prototype for a unary operation function - that is an operation which takes 1 operand and
/// applies some operation to it, for example a `NOT` operation.
typedef err_t (*unary_op_fn_t
)(const insn_ctx_t* ctx, const pis_operand_t* operand, pis_operand_t* result);

/// calculates a binary operation with modrm operands as inputs using the given operand size.
/// returns an operand containing the result of the operation in `result`.
static err_t calc_binop_modrm_with_size(
    const insn_ctx_t* ctx,
    binop_fn_t binop,
    pis_operand_size_t operand_size,
    const modrm_operand_t* dst,
    const modrm_operand_t* src,
    pis_operand_t* result
) {
    err_t err = SUCCESS;

    pis_operand_t dst_tmp = LIFT_CTX_NEW_TMP(ctx->lift_ctx, operand_size);
    pis_operand_t src_tmp = LIFT_CTX_NEW_TMP(ctx->lift_ctx, operand_size);

    CHECK_RETHROW(modrm_operand_read(ctx, &dst_tmp, dst));
    CHECK_RETHROW(modrm_operand_read(ctx, &src_tmp, src));

    CHECK_RETHROW(binop(ctx, &dst_tmp, &src_tmp, result));

cleanup:
    return err;
}

/// calculates a binary operation with modrm operands as inputs. returns an operand containing the
/// result of the operation in `result`.
static err_t calc_binop_modrm(
    const insn_ctx_t* ctx,
    binop_fn_t binop,
    const modrm_operand_t* dst,
    const modrm_operand_t* src,
    pis_operand_t* result
) {
    err_t err = SUCCESS;

    pis_operand_size_t operand_size = ctx->operand_sizes.insn_default_not_64_bit;
    CHECK_RETHROW(calc_binop_modrm_with_size(ctx, binop, operand_size, dst, src, result));

cleanup:
    return err;
}

/// calculates a binary operation with one modrm and one immediate operand as inputs using the given
/// operand size. returns an operand containing the result of the operation in `result`.
static err_t calc_binop_modrm_imm_with_size(
    const insn_ctx_t* ctx,
    binop_fn_t binop,
    pis_operand_size_t operand_size,
    const modrm_operand_t* dst,
    const pis_operand_t* src_imm,
    pis_operand_t* result
) {
    err_t err = SUCCESS;

    pis_operand_t dst_tmp = LIFT_CTX_NEW_TMP(ctx->lift_ctx, operand_size);

    CHECK_RETHROW(modrm_operand_read(ctx, &dst_tmp, dst));

    CHECK_RETHROW(binop(ctx, &dst_tmp, src_imm, result));

cleanup:
    return err;
}

/// calculates a binary operation with one modrm and one immediate operand as inputs. returns an
/// operand containing the result of the operation in `result`.
static err_t calc_binop_modrm_imm(
    const insn_ctx_t* ctx,
    binop_fn_t binop,
    const modrm_operand_t* dst,
    const pis_operand_t* src_imm,
    pis_operand_t* result
) {
    err_t err = SUCCESS;

    pis_operand_size_t operand_size = ctx->operand_sizes.insn_default_not_64_bit;
    CHECK_RETHROW(calc_binop_modrm_imm_with_size(ctx, binop, operand_size, dst, src_imm, result));

cleanup:
    return err;
}

/// calculates a binary operation with modrm operands as inputs, and stores the result of the
/// operation in the first operand.
static err_t calc_and_store_binop_modrm(
    const insn_ctx_t* ctx, binop_fn_t binop, const modrm_operand_t* dst, const modrm_operand_t* src
) {
    err_t err = SUCCESS;

    pis_operand_t res_tmp = {};
    CHECK_RETHROW(calc_binop_modrm(ctx, binop, dst, src, &res_tmp));
    CHECK_RETHROW(modrm_operand_write(ctx, dst, &res_tmp));

cleanup:
    return err;
}

/// calculates a binary operation with modrm operands as inputs using the given operand size, and
/// stores the result of the operation in the first operand.
static err_t calc_and_store_binop_modrm_with_size(
    const insn_ctx_t* ctx,
    binop_fn_t binop,
    pis_operand_size_t operand_size,
    const modrm_operand_t* dst,
    const modrm_operand_t* src
) {
    err_t err = SUCCESS;

    pis_operand_t res_tmp = {};
    CHECK_RETHROW(calc_binop_modrm_with_size(ctx, binop, operand_size, dst, src, &res_tmp));
    CHECK_RETHROW(modrm_operand_write(ctx, dst, &res_tmp));

cleanup:
    return err;
}

/// calculates a binary operation with one modrm and one immediate operand as inputs using the given
/// operand size, and stores the result of the operation in the first operand.
static err_t calc_and_store_binop_modrm_imm_with_size(
    const insn_ctx_t* ctx,
    binop_fn_t binop,
    pis_operand_size_t operand_size,
    const modrm_operand_t* dst,
    const pis_operand_t* src_imm
) {
    err_t err = SUCCESS;

    pis_operand_t res_tmp = {};
    CHECK_RETHROW(calc_binop_modrm_imm_with_size(ctx, binop, operand_size, dst, src_imm, &res_tmp));
    CHECK_RETHROW(modrm_operand_write(ctx, dst, &res_tmp));

cleanup:
    return err;
}

/// calculates a binary operation with one modrm and one immediate operand as inputs, and stores the
/// result of the operation in the first operand.
static err_t UNUSED_ATTR calc_and_store_binop_modrm_imm(
    const insn_ctx_t* ctx,
    binop_fn_t binop,
    const modrm_operand_t* dst,
    const pis_operand_t* src_imm
) {
    err_t err = SUCCESS;

    pis_operand_t res_tmp = {};
    CHECK_RETHROW(calc_binop_modrm_imm(ctx, binop, dst, src_imm, &res_tmp));
    CHECK_RETHROW(modrm_operand_write(ctx, dst, &res_tmp));

cleanup:
    return err;
}

/// calculates a binary operation with one modrm and one immediate operand as inputs using the given
/// operand size, and optionally stores the result of the operation in the first operand.
static err_t calc_and_maybe_store_binop_modrm_imm_with_size(
    const insn_ctx_t* ctx,
    binop_fn_t binop,
    pis_operand_size_t operand_size,
    bool should_store_result,
    const modrm_operand_t* dst,
    const pis_operand_t* src_imm
) {
    err_t err = SUCCESS;

    pis_operand_t res_tmp = {};
    CHECK_RETHROW(calc_binop_modrm_imm_with_size(ctx, binop, operand_size, dst, src_imm, &res_tmp));

    if (should_store_result) {
        CHECK_RETHROW(modrm_operand_write(ctx, dst, &res_tmp));
    }

cleanup:
    return err;
}

/// the default operand size for near branches.
///
/// please not that the operand size is not the size of the displacement immediate. for example, for
/// an operand size of 8, the displacement is 4 bytes.
static pis_operand_size_t near_branch_operand_default_operand_size(const insn_ctx_t* ctx) {
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
static err_t fetch_imm_of_size_and_sign_extend_to_64_bits(
    const insn_ctx_t* ctx, pis_operand_size_t operand_size, u64* disp
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
static pis_operand_size_t rel_jmp_ip_operand_size(const insn_ctx_t* ctx) {
    return near_branch_operand_default_operand_size(ctx);
}

/// masks the ip value which is the result of performing a relative jump with a 16/32 bit
/// displacement.
static u64 rel_jmp_mask_ip_value(const insn_ctx_t* ctx, u64 ip_value) {
    pis_operand_size_t ip_operand_size = rel_jmp_ip_operand_size(ctx);
    u64 mask = pis_operand_size_max_unsigned_value(ip_operand_size);
    return ip_value & mask;
}

/// fetches the displacement and calculates the target address of a relative jump with a 16/32 bit
/// displacement.
static err_t rel_jmp_fetch_disp_and_calc_target_addr(
    const insn_ctx_t* ctx, pis_operand_size_t operand_size, u64* target
) {
    err_t err = SUCCESS;

    u64 disp = 0;
    CHECK_RETHROW(fetch_imm_of_size_and_sign_extend_to_64_bits(ctx, operand_size, &disp));

    u64 cur_insn_end_addr = ctx->lift_ctx->cur_insn_addr + lift_ctx_index(ctx->lift_ctx);
    *target = rel_jmp_mask_ip_value(ctx, cur_insn_end_addr + disp);

cleanup:
    return err;
}

/// fetches the displacement and calculates the target of a relative jump with a 16/32 bit
/// displacement.
static err_t rel_jmp_fetch_disp_and_calc_target(
    const insn_ctx_t* ctx, pis_operand_size_t operand_size, pis_operand_t* target
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
    const insn_ctx_t* ctx, const pis_operand_t* cond, pis_operand_size_t operand_size
) {
    err_t err = SUCCESS;

    pis_operand_t target = {};
    CHECK_RETHROW(rel_jmp_fetch_disp_and_calc_target(ctx, operand_size, &target));

    LIFT_CTX_EMIT(ctx->lift_ctx, PIS_INSN2(PIS_OPCODE_JMP_COND, *cond, target));

cleanup:
    return err;
}


/// generates a ternary expression.
static err_t ternary(
    const insn_ctx_t* ctx,
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
    LIFT_CTX_EMIT(ctx->lift_ctx, PIS_INSN2(PIS_OPCODE_COND_NEGATE, not_cond, *cond));

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

/// implements a `movzx/movsx r, r/m` operation.
static err_t do_mov_extend_r_rm(
    const insn_ctx_t* ctx,
    pis_opcode_t extend_opcode,
    pis_operand_size_t reg_size,
    pis_operand_size_t rm_size
) {
    err_t err = SUCCESS;
    modrm_operands_t modrm_operands = {};

    CHECK_RETHROW(
        modrm_fetch_and_process_with_operand_sizes(ctx, &modrm_operands, rm_size, reg_size)
    );

    pis_operand_t tmp_rm_value = LIFT_CTX_NEW_TMP(ctx->lift_ctx, rm_size);
    CHECK_RETHROW(modrm_rm_read(ctx, &tmp_rm_value, &modrm_operands.rm_operand.rm));

    pis_operand_t tmp_extended = LIFT_CTX_NEW_TMP(ctx->lift_ctx, reg_size);
    LIFT_CTX_EMIT(ctx->lift_ctx, PIS_INSN2(extend_opcode, tmp_extended, tmp_rm_value));
    CHECK_RETHROW(write_gpr(ctx, &modrm_operands.reg_operand.reg, &tmp_extended));

cleanup:
    return err;
}


/// extracts the register encoding of an opcode which has a register encoded in its value.
/// this also takes into account the `B` bit of the rex prefix of the instruction.
static u8 opcode_reg_extract(const insn_ctx_t* ctx, u8 opcode_byte) {
    return apply_rex_bit_to_reg_encoding(opcode_byte & 0b111, ctx->prefixes->rex.b);
}

/// returns the base opcode value of an opcode which has a register encoded in its value,
/// represented in the spec as `opcode + r[w/d]`.
static u8 opcode_reg_opcode_only(u8 opcode_byte) {
    return opcode_byte & (~0b111);
}

/// pushes the given operand to the stack.
static err_t push(const insn_ctx_t* ctx, const pis_operand_t* operand_to_push) {
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
        PIS_INSN3(PIS_OPCODE_ADD, sp, sp, PIS_OPERAND_CONST_NEG(operand_size_bytes, sp.size))
    );

    // write the memory
    LIFT_CTX_EMIT(ctx->lift_ctx, PIS_INSN2(PIS_OPCODE_STORE, sp, tmp));
cleanup:
    return err;
}

/// fetches an immediate operand of the given size.
static err_t fetch_imm_operand_of_size(
    const insn_ctx_t* ctx, pis_operand_size_t size, pis_operand_t* operand
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

/// fetches and immediate of the given size and zero extends it.
static err_t fetch_imm_of_op_size_zext(const insn_ctx_t* ctx, op_size_t size, u64* operand) {
    err_t err = SUCCESS;
    switch (size) {
        case OP_SIZE_8:
            *operand = LIFT_CTX_CUR1_ADVANCE(ctx->lift_ctx);
            break;
        case OP_SIZE_16:
            *operand = LIFT_CTX_CUR2_ADVANCE(ctx->lift_ctx);
            break;
        case OP_SIZE_32:
            *operand = LIFT_CTX_CUR4_ADVANCE(ctx->lift_ctx);
            break;
        case OP_SIZE_64:
            *operand = LIFT_CTX_CUR8_ADVANCE(ctx->lift_ctx);
            break;
        default:
            UNREACHABLE();
    }
cleanup:
    return err;
}

/// fetches and immediate of the given size and zero extends it.
static err_t
    fetch_imm_of_pis_size_zext(const insn_ctx_t* ctx, pis_operand_size_t size, u64* operand) {
    err_t err = SUCCESS;
    switch (size) {
        case PIS_OPERAND_SIZE_1:
            *operand = LIFT_CTX_CUR1_ADVANCE(ctx->lift_ctx);
            break;
        case PIS_OPERAND_SIZE_2:
            *operand = LIFT_CTX_CUR2_ADVANCE(ctx->lift_ctx);
            break;
        case PIS_OPERAND_SIZE_4:
            *operand = LIFT_CTX_CUR4_ADVANCE(ctx->lift_ctx);
            break;
        case PIS_OPERAND_SIZE_8:
            *operand = LIFT_CTX_CUR8_ADVANCE(ctx->lift_ctx);
            break;
        default:
            UNREACHABLE();
    }
cleanup:
    return err;
}

/// fetches and immediate of the given size and sign extends it.
static err_t fetch_imm_of_op_size_sext(const insn_ctx_t* ctx, op_size_t size, u64* operand) {
    err_t err = SUCCESS;
    switch (size) {
        case OP_SIZE_8:
            *operand = (i64) (i8) LIFT_CTX_CUR1_ADVANCE(ctx->lift_ctx);
            break;
        case OP_SIZE_16:
            *operand = (i64) (i16) LIFT_CTX_CUR2_ADVANCE(ctx->lift_ctx);
            break;
        case OP_SIZE_32:
            *operand = (i64) (i32) LIFT_CTX_CUR4_ADVANCE(ctx->lift_ctx);
            break;
        case OP_SIZE_64:
            *operand = LIFT_CTX_CUR8_ADVANCE(ctx->lift_ctx);
            break;
        default:
            UNREACHABLE();
    }
cleanup:
    return err;
}

/// fetches a 16/32 bit immediate operand and sign extends it to the given operand size.
static err_t fetch_imm_of_size_sign_extended(
    const insn_ctx_t* ctx, pis_operand_size_t operand_size, pis_operand_t* operand
) {
    err_t err = SUCCESS;

    pis_operand_size_t imm_operand_size =
        operand_size == PIS_OPERAND_SIZE_8 ? PIS_OPERAND_SIZE_4 : operand_size;

    pis_operand_t imm = {};
    CHECK_RETHROW(fetch_imm_operand_of_size(ctx, imm_operand_size, &imm));

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
    const insn_ctx_t* ctx,
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
    LIFT_CTX_EMIT(ctx->lift_ctx, PIS_INSN2(PIS_OPCODE_COND_NEGATE, not_cond, *cond));

    pis_operand_t true_case = LIFT_CTX_NEW_TMP(ctx->lift_ctx, PIS_OPERAND_SIZE_1);
    LIFT_CTX_EMIT(ctx->lift_ctx, PIS_INSN3(PIS_OPCODE_AND, true_case, *cond, *then_value));

    pis_operand_t false_case = LIFT_CTX_NEW_TMP(ctx->lift_ctx, PIS_OPERAND_SIZE_1);
    LIFT_CTX_EMIT(ctx->lift_ctx, PIS_INSN3(PIS_OPCODE_AND, false_case, not_cond, *else_value));

    LIFT_CTX_EMIT(ctx->lift_ctx, PIS_INSN3(PIS_OPCODE_OR, *result, true_case, false_case));

cleanup:
    return err;
}

/// calculates the carry flag of a `SHL` operation. `to_shift` is the value to be shifted, `count`
/// is the masked shift count.
static err_t shl_calc_carry_flag(
    const insn_ctx_t* ctx, const pis_operand_t* to_shift, const pis_operand_t* count
) {
    err_t err = SUCCESS;

    CHECK(count->size == to_shift->size);

    pis_operand_size_t operand_size = to_shift->size;

    // to get the last shifted out bit, shift the original value `size - count` bits to the right.
    pis_operand_t right_shift_count = LIFT_CTX_NEW_TMP(ctx->lift_ctx, operand_size);
    LIFT_CTX_EMIT(
        ctx->lift_ctx,
        PIS_INSN3(
            PIS_OPCODE_SUB,
            right_shift_count,
            PIS_OPERAND_CONST(pis_operand_size_to_bits(operand_size), operand_size),
            *count
        )
    );
    pis_operand_t right_shifted = LIFT_CTX_NEW_TMP(ctx->lift_ctx, operand_size);
    LIFT_CTX_EMIT(
        ctx->lift_ctx,
        PIS_INSN3(PIS_OPCODE_SHIFT_RIGHT, right_shifted, *to_shift, right_shift_count)
    );
    pis_operand_t last_extracted_bit = LIFT_CTX_NEW_TMP(ctx->lift_ctx, PIS_OPERAND_SIZE_1);
    LIFT_CTX_EMIT(
        ctx->lift_ctx,
        PIS_INSN2(PIS_OPCODE_GET_LOW_BITS, last_extracted_bit, right_shifted)
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

/// calculates the carry flag of a `SHR` operation. `to_shift` is the value to be shifted, `count`
/// is the masked shift count.
static err_t shr_calc_carry_flag(
    const insn_ctx_t* ctx, const pis_operand_t* to_shift, const pis_operand_t* count
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

/// calculates the overflow flag of a `SHL` operation. `to_shift` is the value to be shifted,
/// `count` is the masked shift count.
/// this must be called after calculating the `CF` flag accordingly, since its calculation relies on
/// the `CF` value.
static err_t shl_calc_overflow_flag(
    const insn_ctx_t* ctx,
    const pis_operand_t* to_shift,
    const pis_operand_t* count,
    const pis_operand_t* shift_result
) {
    err_t err = SUCCESS;

    CHECK(count->size == to_shift->size);

    pis_operand_size_t operand_size = to_shift->size;

    // the overflow flag is set to `MSB(shift_result) ^ CF`
    pis_operand_t msb = LIFT_CTX_NEW_TMP(ctx->lift_ctx, PIS_OPERAND_SIZE_1);
    CHECK_RETHROW(extract_most_significant_bit(ctx, shift_result, &msb));

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

/// calculates the overflow flag of a `SHLD` operation. `to_shift` is the value to be shifted,
/// `count` is the masked shift count.
static err_t shld_calc_overflow_flag(
    const insn_ctx_t* ctx, const pis_operand_t* to_shift, const pis_operand_t* count
) {
    err_t err = SUCCESS;

    CHECK(count->size == to_shift->size);

    pis_operand_size_t operand_size = to_shift->size;

    // the overflow flag is set to `MSB(dst << src) ^ MSB(dst)`
    pis_operand_t shifted = LIFT_CTX_NEW_TMP(ctx->lift_ctx, operand_size);
    LIFT_CTX_EMIT(ctx->lift_ctx, PIS_INSN3(PIS_OPCODE_SHIFT_LEFT, shifted, *to_shift, *count));

    pis_operand_t new_msb = LIFT_CTX_NEW_TMP(ctx->lift_ctx, PIS_OPERAND_SIZE_1);
    CHECK_RETHROW(extract_most_significant_bit(ctx, &shifted, &new_msb));

    pis_operand_t old_msb = LIFT_CTX_NEW_TMP(ctx->lift_ctx, PIS_OPERAND_SIZE_1);
    CHECK_RETHROW(extract_most_significant_bit(ctx, to_shift, &old_msb));

    pis_operand_t new_overflow_flag_value = LIFT_CTX_NEW_TMP(ctx->lift_ctx, PIS_OPERAND_SIZE_1);
    LIFT_CTX_EMIT(
        ctx->lift_ctx,
        PIS_INSN3(PIS_OPCODE_XOR, new_overflow_flag_value, new_msb, old_msb)
    );

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

/// calculates the parity zero and sign flags of a shift operation, and stores the results in the
/// appropriate flag registers. `count` is the masked shift count, and `shift_result` is the shifted
/// value.
static err_t shift_calc_parity_zero_sign_flags(
    const insn_ctx_t* ctx, const pis_operand_t* count, const pis_operand_t* shift_result
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

/// masks the `count` operand of a shift operation. in x86, the `count` operand of shift operations
/// is always first masked before being applied.
static err_t mask_shift_count(
    const insn_ctx_t* ctx,
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

/// performs a `SHL` operation on the 2 input operands `a` and `b` and returns an operand
/// containing the result of the operation in `result`.
static err_t binop_shl(
    const insn_ctx_t* ctx, const pis_operand_t* a, const pis_operand_t* b, pis_operand_t* result
) {
    err_t err = SUCCESS;

    CHECK(a->size == b->size);
    pis_operand_size_t operand_size = a->size;

    pis_operand_t count = LIFT_CTX_NEW_TMP(ctx->lift_ctx, operand_size);
    CHECK_RETHROW(mask_shift_count(ctx, b, &count, operand_size));

    // carry flag
    CHECK_RETHROW(shl_calc_carry_flag(ctx, a, &count));

    // perform the actual shift
    pis_operand_t res_tmp = LIFT_CTX_NEW_TMP(ctx->lift_ctx, operand_size);
    LIFT_CTX_EMIT(ctx->lift_ctx, PIS_INSN3(PIS_OPCODE_SHIFT_LEFT, res_tmp, *a, count));

    // overflow flag
    CHECK_RETHROW(shl_calc_overflow_flag(ctx, a, &count, &res_tmp));

    CHECK_RETHROW(shift_calc_parity_zero_sign_flags(ctx, &count, &res_tmp));

    *result = res_tmp;

cleanup:
    return err;
}

/// performs a `SHLD` operation.
static err_t do_shld(
    const insn_ctx_t* ctx,
    const pis_operand_t* dst,
    const pis_operand_t* src,
    const pis_operand_t* count_operand,
    pis_operand_t* result
) {
    err_t err = SUCCESS;

    CHECK(dst->size == src->size);
    pis_operand_size_t operand_size = dst->size;

    pis_operand_t res_tmp = LIFT_CTX_NEW_TMP(ctx->lift_ctx, operand_size);

    pis_operand_t count = LIFT_CTX_NEW_TMP(ctx->lift_ctx, operand_size);
    CHECK_RETHROW(mask_shift_count(ctx, count_operand, &count, operand_size));

    // carry flag
    CHECK_RETHROW(shl_calc_carry_flag(ctx, dst, &count));

    // overflow flag
    CHECK_RETHROW(shld_calc_overflow_flag(ctx, dst, &count));

    // perform the actual shift
    LIFT_CTX_EMIT(ctx->lift_ctx, PIS_INSN3(PIS_OPCODE_SHIFT_LEFT, res_tmp, *dst, count));

    // copy the bits shifted in from the src operand.
    // to do that, we shift the src operand `size - count` bits, and then OR the result into the
    // result.
    pis_operand_t src_shift_count = LIFT_CTX_NEW_TMP(ctx->lift_ctx, operand_size);
    LIFT_CTX_EMIT(
        ctx->lift_ctx,
        PIS_INSN3(
            PIS_OPCODE_SUB,
            src_shift_count,
            PIS_OPERAND_CONST(pis_operand_size_to_bytes(operand_size), operand_size),
            count
        )
    );

    pis_operand_t shifted_src = LIFT_CTX_NEW_TMP(ctx->lift_ctx, operand_size);
    LIFT_CTX_EMIT(
        ctx->lift_ctx,
        PIS_INSN3(PIS_OPCODE_SHIFT_RIGHT, shifted_src, *src, src_shift_count)
    );

    LIFT_CTX_EMIT(ctx->lift_ctx, PIS_INSN3(PIS_OPCODE_OR, res_tmp, res_tmp, shifted_src));

    CHECK_RETHROW(shift_calc_parity_zero_sign_flags(ctx, &count, &res_tmp));

    *result = res_tmp;

cleanup:
    return err;
}

/// calculates the overflow flag of a `SHR` operation. `to_shift` is the value to be shifted,
/// `count` is the masked shift count.
static err_t shr_calc_overflow_flag(
    const insn_ctx_t* ctx, const pis_operand_t* to_shift, const pis_operand_t* count
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

/// calculates the overflow flag of a `SAR` operation. `to_shift` is the value to be shifted,
/// `count` is the masked shift count.
static err_t sar_calc_overflow_flag(
    const insn_ctx_t* ctx, const pis_operand_t* to_shift, const pis_operand_t* count
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

/// performs a `SHR` operation on the 2 input operands `a` and `b` and returns an operand
/// containing the result of the operation in `result`.
static err_t binop_shr(
    const insn_ctx_t* ctx, const pis_operand_t* a, const pis_operand_t* b, pis_operand_t* result
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

    CHECK_RETHROW(shift_calc_parity_zero_sign_flags(ctx, &count, &res_tmp));

    *result = res_tmp;

cleanup:
    return err;
}

/// performs a `SAR` operation on the 2 input operands `a` and `b` and returns an operand
/// containing the result of the operation in `result`.
static err_t binop_sar(
    const insn_ctx_t* ctx, const pis_operand_t* a, const pis_operand_t* b, pis_operand_t* result
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

    CHECK_RETHROW(shift_calc_parity_zero_sign_flags(ctx, &count, &res_tmp));

    *result = res_tmp;

cleanup:
    return err;
}

/// performs a `ROL` operation on the 2 input operands `a` and `b` and returns an operand
/// containing the result of the operation in `result`.
static err_t binop_rol(
    const insn_ctx_t* ctx, const pis_operand_t* a, const pis_operand_t* b, pis_operand_t* result
) {
    err_t err = SUCCESS;

    CHECK(a->size == b->size);
    pis_operand_size_t operand_size = a->size;

    pis_operand_t count = LIFT_CTX_NEW_TMP(ctx->lift_ctx, operand_size);
    CHECK_RETHROW(mask_shift_count(ctx, b, &count, operand_size));

    // perform the actual rotation
    pis_operand_t left_shifted = LIFT_CTX_NEW_TMP(ctx->lift_ctx, operand_size);
    LIFT_CTX_EMIT(ctx->lift_ctx, PIS_INSN3(PIS_OPCODE_SHIFT_LEFT, left_shifted, *a, count));

    pis_operand_t right_shift_count = LIFT_CTX_NEW_TMP(ctx->lift_ctx, operand_size);
    LIFT_CTX_EMIT(
        ctx->lift_ctx,
        PIS_INSN3(
            PIS_OPCODE_SUB,
            right_shift_count,
            PIS_OPERAND_CONST(pis_operand_size_to_bits(operand_size), operand_size),
            count
        )
    );

    pis_operand_t right_shifted = LIFT_CTX_NEW_TMP(ctx->lift_ctx, operand_size);
    LIFT_CTX_EMIT(
        ctx->lift_ctx,
        PIS_INSN3(PIS_OPCODE_SHIFT_RIGHT, right_shifted, *a, right_shift_count)
    );

    pis_operand_t res_tmp = LIFT_CTX_NEW_TMP(ctx->lift_ctx, operand_size);
    LIFT_CTX_EMIT(ctx->lift_ctx, PIS_INSN3(PIS_OPCODE_OR, res_tmp, right_shifted, left_shifted));

    // calculate the carry flag
    pis_operand_t last_extracted_bit = LIFT_CTX_NEW_TMP(ctx->lift_ctx, operand_size);
    LIFT_CTX_EMIT(
        ctx->lift_ctx,
        PIS_INSN3(PIS_OPCODE_AND, last_extracted_bit, res_tmp, PIS_OPERAND_CONST(1, operand_size))
    );
    LIFT_CTX_EMIT(ctx->lift_ctx, PIS_INSN2(PIS_OPCODE_GET_LOW_BITS, FLAGS_CF, last_extracted_bit));

    // overflow flag is the same as `shl`
    CHECK_RETHROW(shl_calc_overflow_flag(ctx, a, &count, &res_tmp));

    CHECK_RETHROW(shift_calc_parity_zero_sign_flags(ctx, &count, &res_tmp));

    *result = res_tmp;

cleanup:
    return err;
}

/// pushes the current instruction pointer value. this takes into account the effective operand
/// sizes of the instruction.
static err_t push_ip(const insn_ctx_t* ctx) {
    err_t err = SUCCESS;
    u64 cur_insn_end_addr = ctx->lift_ctx->cur_insn_addr + lift_ctx_index(ctx->lift_ctx);
    u64 push_value = rel_jmp_mask_ip_value(ctx, cur_insn_end_addr);
    CHECK_RETHROW(
        push(ctx, &PIS_OPERAND_CONST(push_value, near_branch_operand_default_operand_size(ctx)))
    );
cleanup:
    return err;
}

/// peforms a division operation that operates on the `ax` and `dx` operands and stores its
/// results in the `ax` and `dx` operands.
static err_t do_div_ax_dx(
    const insn_ctx_t* ctx, pis_operand_size_t operand_size, const pis_operand_t* divisor
) {
    err_t err = SUCCESS;

    CHECK(divisor->size == operand_size);

    if (operand_size == PIS_OPERAND_SIZE_8) {
        // divide `rdx:rax`.

        // perform the division
        pis_operand_t quotient = LIFT_CTX_NEW_TMP(ctx->lift_ctx, PIS_OPERAND_SIZE_8);
        LIFT_CTX_EMIT(
            ctx->lift_ctx,
            PIS_INSN4(PIS_OPCODE_UNSIGNED_DIV_16, quotient, RDX, RAX, *divisor)
        );

        // perform the remainder calculation
        pis_operand_t rem = LIFT_CTX_NEW_TMP(ctx->lift_ctx, PIS_OPERAND_SIZE_8);
        LIFT_CTX_EMIT(
            ctx->lift_ctx,
            PIS_INSN4(PIS_OPCODE_UNSIGNED_REM_16, rem, RDX, RAX, *divisor)
        );

        // write the results back to RAX and RDX
        LIFT_CTX_EMIT(ctx->lift_ctx, PIS_INSN2(PIS_OPCODE_MOVE, RAX, quotient));
        LIFT_CTX_EMIT(ctx->lift_ctx, PIS_INSN2(PIS_OPCODE_MOVE, RDX, rem));

    } else {
        // divide `dx:ax` or `edx:eax`.

        // first, combine the 2 registers into a single operand.
        pis_operand_size_t double_operand_size = operand_size * 2;
        pis_operand_t divide_lhs = LIFT_CTX_NEW_TMP(ctx->lift_ctx, double_operand_size);
        LIFT_CTX_EMIT(
            ctx->lift_ctx,
            PIS_INSN2(PIS_OPCODE_ZERO_EXTEND, divide_lhs, operand_resize(&RAX, operand_size))
        );

        // zero extend the dx part and shift it left
        pis_operand_t zero_extended_dx = LIFT_CTX_NEW_TMP(ctx->lift_ctx, double_operand_size);
        LIFT_CTX_EMIT(
            ctx->lift_ctx,
            PIS_INSN2(PIS_OPCODE_ZERO_EXTEND, zero_extended_dx, operand_resize(&RDX, operand_size))
        );
        LIFT_CTX_EMIT(
            ctx->lift_ctx,
            PIS_INSN3(
                PIS_OPCODE_SHIFT_LEFT,
                zero_extended_dx,
                zero_extended_dx,
                PIS_OPERAND_CONST(pis_operand_size_to_bits(operand_size), double_operand_size)
            )
        );

        // or the shifted dx value into the result operand
        LIFT_CTX_EMIT(
            ctx->lift_ctx,
            PIS_INSN3(PIS_OPCODE_OR, divide_lhs, divide_lhs, zero_extended_dx)
        );

        // zero extend the divisor
        pis_operand_t zero_extended_divisor = LIFT_CTX_NEW_TMP(ctx->lift_ctx, double_operand_size);
        LIFT_CTX_EMIT(
            ctx->lift_ctx,
            PIS_INSN2(PIS_OPCODE_ZERO_EXTEND, zero_extended_divisor, *divisor)
        );

        // perform the division
        pis_operand_t div_result = LIFT_CTX_NEW_TMP(ctx->lift_ctx, double_operand_size);
        LIFT_CTX_EMIT(
            ctx->lift_ctx,
            PIS_INSN3(PIS_OPCODE_UNSIGNED_DIV, div_result, divide_lhs, zero_extended_divisor)
        );

        // store the division result in ax
        LIFT_CTX_EMIT(
            ctx->lift_ctx,
            PIS_INSN2(PIS_OPCODE_GET_LOW_BITS, operand_resize(&RAX, operand_size), div_result)
        );

        // perform the remainder calculation
        pis_operand_t rem_result = LIFT_CTX_NEW_TMP(ctx->lift_ctx, double_operand_size);
        LIFT_CTX_EMIT(
            ctx->lift_ctx,
            PIS_INSN3(PIS_OPCODE_UNSIGNED_REM, rem_result, divide_lhs, zero_extended_divisor)
        );

        // store the division result in dx
        LIFT_CTX_EMIT(
            ctx->lift_ctx,
            PIS_INSN2(PIS_OPCODE_GET_LOW_BITS, operand_resize(&RDX, operand_size), rem_result)
        );
    }
cleanup:
    return err;
}

/// peforms a multiplication operation that operates on the `ax` operand and stores its
/// result in the `ax` and `dx` operands.
static err_t
    do_mul_ax(const insn_ctx_t* ctx, pis_operand_size_t operand_size, const pis_operand_t* factor) {
    err_t err = SUCCESS;

    CHECK(factor->size == operand_size);

    pis_operand_t result_high = LIFT_CTX_NEW_TMP(ctx->lift_ctx, operand_size);
    pis_operand_t result_low = LIFT_CTX_NEW_TMP(ctx->lift_ctx, operand_size);

    // compute the result of the multiplication and split it into 2 parts - high and low.
    if (operand_size == PIS_OPERAND_SIZE_8) {
        // when the operand size is 8 we can't use the regular multiplication opcode, since we want
        // a 16-byte result. so, we use a special opcode for it.
        LIFT_CTX_EMIT(
            ctx->lift_ctx,
            PIS_INSN4(PIS_OPCODE_UNSIGNED_MUL_16, result_high, result_low, RAX, *factor)
        );

        // store the result of the multiplication
        LIFT_CTX_EMIT(ctx->lift_ctx, PIS_INSN2(PIS_OPCODE_MOVE, RDX, result_high));
        LIFT_CTX_EMIT(ctx->lift_ctx, PIS_INSN2(PIS_OPCODE_MOVE, RAX, result_low));
    } else {
        // operand size is less than 8, so we can use the regular multiplication opcode.
        pis_operand_size_t double_operand_size = operand_size * 2;

        pis_operand_t factor_zero_extended = LIFT_CTX_NEW_TMP(ctx->lift_ctx, double_operand_size);
        LIFT_CTX_EMIT(
            ctx->lift_ctx,
            PIS_INSN2(PIS_OPCODE_ZERO_EXTEND, factor_zero_extended, *factor)
        );

        pis_operand_t ax = operand_resize(&RAX, double_operand_size);

        pis_operand_t multiplication_result = LIFT_CTX_NEW_TMP(ctx->lift_ctx, double_operand_size);
        LIFT_CTX_EMIT(
            ctx->lift_ctx,
            PIS_INSN3(PIS_OPCODE_UNSIGNED_MUL, multiplication_result, ax, factor_zero_extended)
        );

        // split the result into the low and high parts
        pis_operand_t result_high = LIFT_CTX_NEW_TMP(ctx->lift_ctx, operand_size);
        pis_operand_t result_low = LIFT_CTX_NEW_TMP(ctx->lift_ctx, operand_size);
        LIFT_CTX_EMIT(
            ctx->lift_ctx,
            PIS_INSN2(PIS_OPCODE_GET_LOW_BITS, result_low, multiplication_result)
        );

        pis_operand_t shifted_multiplication_result =
            LIFT_CTX_NEW_TMP(ctx->lift_ctx, double_operand_size);
        LIFT_CTX_EMIT(
            ctx->lift_ctx,
            PIS_INSN3(
                PIS_OPCODE_SHIFT_RIGHT,
                shifted_multiplication_result,
                multiplication_result,
                PIS_OPERAND_CONST(pis_operand_size_to_bits(operand_size), double_operand_size)
            )
        );
        LIFT_CTX_EMIT(
            ctx->lift_ctx,
            PIS_INSN2(PIS_OPCODE_GET_LOW_BITS, result_high, shifted_multiplication_result)
        );

        // store the result of the multiplication
        if (operand_size == PIS_OPERAND_SIZE_1) {
            LIFT_CTX_EMIT(ctx->lift_ctx, PIS_INSN2(PIS_OPCODE_MOVE, AX, multiplication_result));
        } else {
            pis_operand_t dx = operand_resize(&RDX, double_operand_size);
            LIFT_CTX_EMIT(ctx->lift_ctx, PIS_INSN2(PIS_OPCODE_MOVE, dx, result_high));
            LIFT_CTX_EMIT(ctx->lift_ctx, PIS_INSN2(PIS_OPCODE_MOVE, ax, result_low));
        }
    }

    // calculate the carry and overflow flags
    pis_operand_t is_high_zero = LIFT_CTX_NEW_TMP(ctx->lift_ctx, PIS_OPERAND_SIZE_1);
    LIFT_CTX_EMIT(
        ctx->lift_ctx,
        PIS_INSN3(PIS_OPCODE_EQUALS, is_high_zero, result_high, PIS_OPERAND_CONST(0, operand_size))
    );

    LIFT_CTX_EMIT(ctx->lift_ctx, PIS_INSN2(PIS_OPCODE_COND_NEGATE, FLAGS_CF, is_high_zero));
    LIFT_CTX_EMIT(ctx->lift_ctx, PIS_INSN2(PIS_OPCODE_MOVE, FLAGS_OF, FLAGS_CF));
cleanup:
    return err;
}

/// calculates the given binary operation with the `ax` register of appropriate size as its first
/// operand, and an immediate operand of appropriate size as its second operand. returns an operand
/// containing the result in `result`.
static err_t calc_binop_ax_imm(const insn_ctx_t* ctx, binop_fn_t binop, pis_operand_t* result) {
    err_t err = SUCCESS;

    pis_operand_size_t operand_size = ctx->operand_sizes.insn_default_not_64_bit;

    pis_operand_t imm = {};
    CHECK_RETHROW(fetch_imm_of_size_sign_extended(ctx, operand_size, &imm));

    pis_operand_t ax = operand_resize(&RAX, operand_size);

    CHECK_RETHROW(binop(ctx, &ax, &imm, result));

cleanup:
    return err;
}

/// calculates the given binary operation with the `ax` register of appropriate size as its first
/// operand, and an immediate operand of appropriate size as its second operand. stores the result
/// of the operation in the `ax` operand.
static err_t calc_and_store_binop_ax_imm(const insn_ctx_t* ctx, binop_fn_t binop) {
    err_t err = SUCCESS;

    pis_operand_t res = {};
    CHECK_RETHROW(calc_binop_ax_imm(ctx, binop, &res));

    pis_operand_t ax = operand_resize(&RAX, ctx->operand_sizes.insn_default_not_64_bit);
    CHECK_RETHROW(write_gpr(ctx, &ax, &res));

cleanup:
    return err;
}

/// performs a `BT` operation with the first operand being a memory operand.
static err_t do_bt_memory(
    const insn_ctx_t* ctx, const pis_operand_t* bit_base_addr, const pis_operand_t* bit_offset
) {
    err_t err = SUCCESS;

    // resize the bit offset operand to the address size, since we need to add it to the address
    pis_operand_t resized_bit_offset;
    if (ctx->addr_size > bit_offset->size) {
        // sign extend it
        resized_bit_offset = LIFT_CTX_NEW_TMP(ctx->lift_ctx, ctx->addr_size);
        LIFT_CTX_EMIT(
            ctx->lift_ctx,
            PIS_INSN2(PIS_OPCODE_SIGN_EXTEND, resized_bit_offset, *bit_offset)
        );
    } else if (ctx->addr_size < bit_offset->size) {
        // truncate it
        resized_bit_offset = LIFT_CTX_NEW_TMP(ctx->lift_ctx, ctx->addr_size);
        LIFT_CTX_EMIT(
            ctx->lift_ctx,
            PIS_INSN2(PIS_OPCODE_GET_LOW_BITS, resized_bit_offset, *bit_offset)
        );
    } else {
        // same size
        resized_bit_offset = *bit_offset;
    }

    // divide the bit offset by 8 to get the byte offset. this can be done by shifting it right 3
    // times.
    pis_operand_t byte_offset = LIFT_CTX_NEW_TMP(ctx->lift_ctx, ctx->addr_size);
    LIFT_CTX_EMIT(
        ctx->lift_ctx,
        PIS_INSN3(
            PIS_OPCODE_SHIFT_RIGHT_SIGNED,
            byte_offset,
            resized_bit_offset,
            PIS_OPERAND_CONST(3, ctx->addr_size)
        )
    );

    // add the byte offset to the base address to get the byte address
    pis_operand_t byte_addr = LIFT_CTX_NEW_TMP(ctx->lift_ctx, ctx->addr_size);
    LIFT_CTX_EMIT(ctx->lift_ctx, PIS_INSN3(PIS_OPCODE_ADD, byte_addr, *bit_base_addr, byte_offset));

    // load the byte from memory
    pis_operand_t byte = LIFT_CTX_NEW_TMP(ctx->lift_ctx, PIS_OPERAND_SIZE_1);
    LIFT_CTX_EMIT(ctx->lift_ctx, PIS_INSN2(PIS_OPCODE_LOAD, byte, byte_addr));

    // calculate the in-byte bit offset
    pis_operand_t in_byte_bit_offset;
    if (bit_offset->size == PIS_OPERAND_SIZE_1) {
        in_byte_bit_offset = *bit_offset;
    } else {
        in_byte_bit_offset = LIFT_CTX_NEW_TMP(ctx->lift_ctx, PIS_OPERAND_SIZE_1);
        LIFT_CTX_EMIT(
            ctx->lift_ctx,
            PIS_INSN2(PIS_OPCODE_GET_LOW_BITS, in_byte_bit_offset, *bit_offset)
        );
    }
    LIFT_CTX_EMIT(
        ctx->lift_ctx,
        PIS_INSN3(
            PIS_OPCODE_AND,
            in_byte_bit_offset,
            in_byte_bit_offset,
            PIS_OPERAND_CONST(7, PIS_OPERAND_SIZE_1)
        )
    );

    // extract the bit into the carry flag.
    LIFT_CTX_EMIT(
        ctx->lift_ctx,
        PIS_INSN3(PIS_OPCODE_SHIFT_RIGHT, FLAGS_CF, byte, in_byte_bit_offset)
    );

cleanup:
    return err;
}

/// performs a `BT` operation with the first operand being a register operand.
static err_t do_bt_reg(
    const insn_ctx_t* ctx, const pis_operand_t* bit_base_reg, const pis_operand_t* bit_offset
) {
    err_t err = SUCCESS;

    CHECK(bit_base_reg->size == bit_offset->size);

    pis_operand_size_t operand_size = bit_base_reg->size;
    pis_operand_t masked_bit_offset = LIFT_CTX_NEW_TMP(ctx->lift_ctx, operand_size);
    CHECK_RETHROW(mask_shift_count(ctx, bit_offset, &masked_bit_offset, operand_size));

    // extract the bit into the carry flag.
    LIFT_CTX_EMIT(
        ctx->lift_ctx,
        PIS_INSN3(PIS_OPCODE_SHIFT_RIGHT, FLAGS_CF, *bit_base_reg, masked_bit_offset)
    );

cleanup:
    return err;
}

/// performs a `BT` operation with the first operand being an rm operand.
static err_t do_bt_rm(
    const insn_ctx_t* ctx, const modrm_rm_operand_t* bit_base, const pis_operand_t* bit_offset
) {
    err_t err = SUCCESS;

    if (bit_base->is_memory) {
        CHECK_RETHROW(do_bt_memory(ctx, &bit_base->addr_or_reg, bit_offset));
    } else {
        CHECK_RETHROW(do_bt_reg(ctx, &bit_base->addr_or_reg, bit_offset));
    }

cleanup:
    return err;
}

/// lift an instruction according to its second opcode byte
static err_t lift_second_opcode_byte(const insn_ctx_t* ctx, u8 second_opcode_byte) {
    err_t err = SUCCESS;
    modrm_operands_t modrm_operands = {};

    if (opcode_cond_opcode_only(second_opcode_byte) == 0x80) {
        // jcc rel
        pis_operand_t cond = {};
        CHECK_RETHROW(cond_opcode_decode_and_calc(ctx, second_opcode_byte, &cond));

        CHECK_RETHROW(do_cond_rel_jmp(ctx, &cond, near_branch_operand_default_operand_size(ctx)));
    } else if (opcode_cond_opcode_only(second_opcode_byte) == 0x90) {
        // setcc r/m8
        CHECK_RETHROW(modrm_fetch_and_process_with_operand_sizes(
            ctx,
            &modrm_operands,
            PIS_OPERAND_SIZE_1,
            // don't care
            PIS_OPERAND_SIZE_1
        ));

        pis_operand_t cond = {};
        CHECK_RETHROW(cond_opcode_decode_and_calc(ctx, second_opcode_byte, &cond));

        CHECK_RETHROW(modrm_rm_write(ctx, &modrm_operands.rm_operand.rm, &cond));
    } else if (second_opcode_byte == 0xaf) {
        // imul r, r/m
        CHECK_RETHROW(modrm_fetch_and_process(ctx, &modrm_operands));
        CHECK_RETHROW(calc_and_store_binop_modrm(
            ctx,
            binop_imul,
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
    } else if (second_opcode_byte == 0xb6 || second_opcode_byte == 0xbe) {
        // movzx/movsx r, r/m8
        pis_opcode_t opcode =
            second_opcode_byte == 0xb6 ? PIS_OPCODE_ZERO_EXTEND : PIS_OPCODE_SIGN_EXTEND;
        CHECK_RETHROW(do_mov_extend_r_rm(
            ctx,
            opcode,
            ctx->operand_sizes.insn_default_not_64_bit,
            PIS_OPERAND_SIZE_1
        ));
    } else if (second_opcode_byte == 0xb7 || second_opcode_byte == 0xbf) {
        // movzx/movsx r, r/m16
        pis_opcode_t opcode =
            second_opcode_byte == 0xb7 ? PIS_OPCODE_ZERO_EXTEND : PIS_OPCODE_SIGN_EXTEND;
        pis_operand_size_t reg_size;
        if (ctx->prefixes->rex.w) {
            reg_size = PIS_OPERAND_SIZE_8;
        } else {
            reg_size = PIS_OPERAND_SIZE_4;
        }
        CHECK_RETHROW(do_mov_extend_r_rm(ctx, opcode, reg_size, PIS_OPERAND_SIZE_2));
    } else if (opcode_cond_opcode_only(second_opcode_byte) == 0x40) {
        // cmovcc r, r/m
        CHECK_RETHROW(modrm_fetch_and_process(ctx, &modrm_operands));

        pis_operand_t cond = {};
        CHECK_RETHROW(cond_opcode_decode_and_calc(ctx, second_opcode_byte, &cond));

        pis_operand_size_t operand_size = ctx->operand_sizes.insn_default_not_64_bit;
        pis_operand_t rm_value = LIFT_CTX_NEW_TMP(ctx->lift_ctx, operand_size);
        CHECK_RETHROW(modrm_rm_read(ctx, &rm_value, &modrm_operands.rm_operand.rm));

        pis_operand_t final_value = LIFT_CTX_NEW_TMP(ctx->lift_ctx, operand_size);
        CHECK_RETHROW(ternary(ctx, &cond, &rm_value, &modrm_operands.reg_operand.reg, &final_value)
        );

        CHECK_RETHROW(write_gpr(ctx, &modrm_operands.reg_operand.reg, &final_value));
    } else if (second_opcode_byte == 0xa3) {
        // bt r/m, r
        CHECK_RETHROW(modrm_fetch_and_process(ctx, &modrm_operands));

        CHECK_RETHROW(do_bt_rm(ctx, &modrm_operands.rm_operand.rm, &modrm_operands.reg_operand.reg)
        );
    } else if (second_opcode_byte == 0xa4 || second_opcode_byte == 0xa5) {
        // shld r/m, r, imm8/cl
        CHECK_RETHROW(modrm_fetch_and_process(ctx, &modrm_operands));

        pis_operand_size_t operand_size = ctx->operand_sizes.insn_default_not_64_bit;

        // determine the rhs operand according to the opcode
        pis_operand_t shift_count = {};
        switch (second_opcode_byte) {
            case 0xa4: {
                // shld r/m, r, imm8
                u8 imm8 = LIFT_CTX_CUR1_ADVANCE(ctx->lift_ctx);
                shift_count = PIS_OPERAND_CONST(imm8, operand_size);
                break;
            }
            case 0xa5: {
                // shld r/m, r, cl
                pis_operand_t cl_zero_extended = LIFT_CTX_NEW_TMP(ctx->lift_ctx, operand_size);
                LIFT_CTX_EMIT(
                    ctx->lift_ctx,
                    PIS_INSN2(PIS_OPCODE_ZERO_EXTEND, cl_zero_extended, CL)
                );
                shift_count = cl_zero_extended;
                break;
            }
            default:
                UNREACHABLE();
        }

        pis_operand_t rm_value = LIFT_CTX_NEW_TMP(ctx->lift_ctx, operand_size);
        CHECK_RETHROW(modrm_rm_read(ctx, &rm_value, &modrm_operands.rm_operand.rm));

        pis_operand_t result = {};
        CHECK_RETHROW(
            do_shld(ctx, &rm_value, &modrm_operands.reg_operand.reg, &shift_count, &result)
        );

        CHECK_RETHROW(modrm_rm_write(ctx, &modrm_operands.rm_operand.rm, &result));

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

/// lift an instruction according to its first opcode byte
static err_t __attribute__((unused))
old_lift_first_opcode_byte(const insn_ctx_t* ctx, u8 first_opcode_byte) {
    err_t err = SUCCESS;
    modrm_operands_t modrm_operands = {};

    if (opcode_reg_opcode_only(first_opcode_byte) == 0x50) {
        // push <reg>
        u8 reg_encoding = opcode_reg_extract(ctx, first_opcode_byte);

        pis_operand_size_t operand_size = ctx->operand_sizes.insn_default_64_bit;
        pis_operand_t pushed_reg = reg_get_operand(reg_encoding, operand_size, ctx->prefixes);

        CHECK_RETHROW(push(ctx, &pushed_reg));
    } else if (first_opcode_byte == 0x68) {
        // push imm16/imm32
        pis_operand_size_t operand_size = ctx->operand_sizes.insn_default_64_bit;

        pis_operand_t imm = {};
        CHECK_RETHROW(fetch_imm_of_size_sign_extended(ctx, operand_size, &imm));

        CHECK_RETHROW(push(ctx, &imm));
    } else if (first_opcode_byte == 0x6a) {
        // push imm8
        pis_operand_size_t operand_size = ctx->operand_sizes.insn_default_64_bit;

        i8 imm8 = LIFT_CTX_CUR1_ADVANCE(ctx->lift_ctx);
        u64 imm64 = pis_sign_extend_byte(imm8, operand_size);
        pis_operand_t imm_operand = PIS_OPERAND_CONST(imm64, operand_size);

        CHECK_RETHROW(push(ctx, &imm_operand));
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
            PIS_INSN3(PIS_OPCODE_ADD, sp, sp, PIS_OPERAND_CONST(operand_size_bytes, sp.size))
        );

        pis_operand_t reg_operand = reg_get_operand(reg_encoding, operand_size, ctx->prefixes);
        CHECK_RETHROW(write_gpr(ctx, &reg_operand, &tmp));
    } else if (opcode_reg_opcode_only(first_opcode_byte) == 0x40) {
        // inc <reg>
        u8 reg_encoding = opcode_reg_extract(ctx, first_opcode_byte);

        pis_operand_size_t operand_size = ctx->operand_sizes.insn_default_not_64_bit;
        pis_operand_t reg_operand = reg_get_operand(reg_encoding, operand_size, ctx->prefixes);

        pis_operand_t result = {};
        CHECK_RETHROW(unary_op_inc(ctx, &reg_operand, &result));
        CHECK_RETHROW(write_gpr(ctx, &reg_operand, &result));
    } else if (opcode_reg_opcode_only(first_opcode_byte) == 0x90) {
        // xchg [e/r]ax, r
        u8 reg_encoding = opcode_reg_extract(ctx, first_opcode_byte);

        pis_operand_size_t operand_size = ctx->operand_sizes.insn_default_not_64_bit;

        pis_operand_t ax_operand = PIS_OPERAND(RAX.addr, operand_size);
        pis_operand_t reg_operand = reg_get_operand(reg_encoding, operand_size, ctx->prefixes);

        if (pis_operand_equals(&ax_operand, &reg_operand)) {
            // exchange [e/r]ax with itself. this is a nop, so don't emit anything.
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

        pis_operand_t rm_value = LIFT_CTX_NEW_TMP(ctx->lift_ctx, operand_size);
        CHECK_RETHROW(modrm_rm_read(ctx, &rm_value, &modrm_operands.rm_operand.rm));

        if (modrm_operands.modrm.reg == 6) {
            // div r/m
            CHECK_RETHROW(do_div_ax_dx(ctx, operand_size, &rm_value));
        } else if (modrm_operands.modrm.reg == 3) {
            // neg r/m
            pis_operand_t res = {};
            CHECK_RETHROW(unary_op_neg(ctx, &rm_value, &res));
            CHECK_RETHROW(modrm_rm_write(ctx, &modrm_operands.rm_operand.rm, &res));
        } else if (modrm_operands.modrm.reg == 2) {
            // not r/m
            pis_operand_t res = {};
            CHECK_RETHROW(unary_op_not(ctx, &rm_value, &res));
            CHECK_RETHROW(modrm_rm_write(ctx, &modrm_operands.rm_operand.rm, &res));
        } else if (modrm_operands.modrm.reg == 4) {
            // mul r/m
            CHECK_RETHROW(do_mul_ax(ctx, operand_size, &rm_value));
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
        pis_operand_size_t operand_size = ctx->operand_sizes.insn_default_not_64_bit;
        if (operand_size == PIS_OPERAND_SIZE_8) {
            // movsxd r64, r/m32
            CHECK_RETHROW(do_mov_extend_r_rm(
                ctx,
                PIS_OPCODE_SIGN_EXTEND,
                PIS_OPERAND_SIZE_8,
                PIS_OPERAND_SIZE_4
            ));
        } else {
            // regular mov
            CHECK_RETHROW(modrm_fetch_and_process(ctx, &modrm_operands));

            pis_operand_t tmp = LIFT_CTX_NEW_TMP(ctx->lift_ctx, operand_size);
            CHECK_RETHROW(modrm_rm_read(ctx, &tmp, &modrm_operands.rm_operand.rm));
            CHECK_RETHROW(write_gpr(ctx, &modrm_operands.reg_operand.reg, &tmp));
        }
    } else if (first_opcode_byte == 0x01) {
        // add r/m, r
        CHECK_RETHROW(modrm_fetch_and_process(ctx, &modrm_operands));
        CHECK_RETHROW(calc_and_store_binop_modrm(
            ctx,
            binop_add,
            &modrm_operands.rm_operand,
            &modrm_operands.reg_operand
        ));
    } else if (first_opcode_byte == 0x03) {
        // add r, r/m
        CHECK_RETHROW(modrm_fetch_and_process(ctx, &modrm_operands));
        CHECK_RETHROW(calc_and_store_binop_modrm(
            ctx,
            binop_add,
            &modrm_operands.reg_operand,
            &modrm_operands.rm_operand
        ));
    } else if (first_opcode_byte == 0x0b) {
        // or r, r/m
        CHECK_RETHROW(modrm_fetch_and_process(ctx, &modrm_operands));
        CHECK_RETHROW(calc_and_store_binop_modrm(
            ctx,
            binop_or,
            &modrm_operands.reg_operand,
            &modrm_operands.rm_operand
        ));
    } else if (first_opcode_byte == 0x09) {
        // or r/m, r
        CHECK_RETHROW(modrm_fetch_and_process(ctx, &modrm_operands));
        CHECK_RETHROW(calc_and_store_binop_modrm(
            ctx,
            binop_or,
            &modrm_operands.rm_operand,
            &modrm_operands.reg_operand
        ));
    } else if (first_opcode_byte == 0x08) {
        // or r/m8, r8
        CHECK_RETHROW(modrm_fetch_and_process_with_operand_sizes(
            ctx,
            &modrm_operands,
            PIS_OPERAND_SIZE_1,
            PIS_OPERAND_SIZE_1
        ));
        CHECK_RETHROW(calc_and_store_binop_modrm_with_size(
            ctx,
            binop_or,
            PIS_OPERAND_SIZE_1,
            &modrm_operands.rm_operand,
            &modrm_operands.reg_operand
        ));
    } else if (first_opcode_byte == 0x23) {
        // and r, r/m
        CHECK_RETHROW(modrm_fetch_and_process(ctx, &modrm_operands));
        CHECK_RETHROW(calc_and_store_binop_modrm(
            ctx,
            binop_and,
            &modrm_operands.reg_operand,
            &modrm_operands.rm_operand
        ));
    } else if (first_opcode_byte == 0x21) {
        // and r/m, r
        CHECK_RETHROW(modrm_fetch_and_process(ctx, &modrm_operands));
        CHECK_RETHROW(calc_and_store_binop_modrm(
            ctx,
            binop_and,
            &modrm_operands.rm_operand,
            &modrm_operands.reg_operand
        ));
    } else if (first_opcode_byte == 0x20) {
        // and r/m8, r8
        CHECK_RETHROW(modrm_fetch_and_process_with_operand_sizes(
            ctx,
            &modrm_operands,
            PIS_OPERAND_SIZE_1,
            PIS_OPERAND_SIZE_1
        ));
        CHECK_RETHROW(calc_and_store_binop_modrm_with_size(
            ctx,
            binop_and,
            PIS_OPERAND_SIZE_1,
            &modrm_operands.reg_operand,
            &modrm_operands.rm_operand
        ));
    } else if (first_opcode_byte == 0x29) {
        // sub r/m, r
        CHECK_RETHROW(modrm_fetch_and_process(ctx, &modrm_operands));
        CHECK_RETHROW(calc_and_store_binop_modrm(
            ctx,
            binop_sub,
            &modrm_operands.rm_operand,
            &modrm_operands.reg_operand
        ));
    } else if (first_opcode_byte == 0x2b) {
        // sub r, r/m
        CHECK_RETHROW(modrm_fetch_and_process(ctx, &modrm_operands));
        CHECK_RETHROW(calc_and_store_binop_modrm(
            ctx,
            binop_sub,
            &modrm_operands.reg_operand,
            &modrm_operands.rm_operand
        ));
    } else if (first_opcode_byte == 0x31) {
        // xor r/m, r
        CHECK_RETHROW(modrm_fetch_and_process(ctx, &modrm_operands));
        CHECK_RETHROW(calc_and_store_binop_modrm(
            ctx,
            binop_xor,
            &modrm_operands.rm_operand,
            &modrm_operands.reg_operand
        ));
    } else if (first_opcode_byte == 0x33) {
        // xor r, r/m
        CHECK_RETHROW(modrm_fetch_and_process(ctx, &modrm_operands));
        CHECK_RETHROW(calc_and_store_binop_modrm(
            ctx,
            binop_xor,
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
            binop_sub,
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
            binop_sub,
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

        // can't decode modrm operands here since we don't yet know the operand sizes. the operand
        // sizes depend on the `reg` value.
        modrm_t modrm = modrm_decode_byte(LIFT_CTX_CUR1_ADVANCE(ctx->lift_ctx));

        if (modrm.reg == 4) {
            // jmp r/m

            pis_operand_size_t operand_size = near_branch_operand_default_operand_size(ctx);

            modrm_rm_operand_t rm_operand = {};
            CHECK_RETHROW(modrm_decode_rm_operand(ctx, &modrm, operand_size, &rm_operand));

            pis_operand_t rm_tmp = LIFT_CTX_NEW_TMP(ctx->lift_ctx, operand_size);
            CHECK_RETHROW(modrm_rm_read(ctx, &rm_tmp, &rm_operand));

            LIFT_CTX_EMIT(ctx->lift_ctx, PIS_INSN1(PIS_OPCODE_JMP, rm_tmp));
        } else if (modrm.reg == 2) {
            // call r/m

            pis_operand_size_t operand_size = near_branch_operand_default_operand_size(ctx);

            modrm_rm_operand_t rm_operand = {};
            CHECK_RETHROW(modrm_decode_rm_operand(ctx, &modrm, operand_size, &rm_operand));

            pis_operand_t rm_tmp = LIFT_CTX_NEW_TMP(ctx->lift_ctx, operand_size);
            CHECK_RETHROW(modrm_rm_read(ctx, &rm_tmp, &rm_operand));

            CHECK_RETHROW(push_ip(ctx));

            LIFT_CTX_EMIT(ctx->lift_ctx, PIS_INSN1(PIS_OPCODE_JMP, rm_tmp));
        } else if (modrm.reg == 1) {
            // dec r/m

            pis_operand_size_t operand_size = ctx->operand_sizes.insn_default_not_64_bit;

            modrm_rm_operand_t rm_operand = {};
            CHECK_RETHROW(modrm_decode_rm_operand(ctx, &modrm, operand_size, &rm_operand));

            pis_operand_t rm_tmp = LIFT_CTX_NEW_TMP(ctx->lift_ctx, operand_size);
            CHECK_RETHROW(modrm_rm_read(ctx, &rm_tmp, &rm_operand));

            pis_operand_t result = {};
            CHECK_RETHROW(unary_op_dec(ctx, &rm_tmp, &result));

            CHECK_RETHROW(modrm_rm_write(ctx, &rm_operand, &result));
        } else if (modrm.reg == 0) {
            // inc r/m

            pis_operand_size_t operand_size = ctx->operand_sizes.insn_default_not_64_bit;

            modrm_rm_operand_t rm_operand = {};
            CHECK_RETHROW(modrm_decode_rm_operand(ctx, &modrm, operand_size, &rm_operand));

            pis_operand_t rm_tmp = LIFT_CTX_NEW_TMP(ctx->lift_ctx, operand_size);
            CHECK_RETHROW(modrm_rm_read(ctx, &rm_tmp, &rm_operand));

            pis_operand_t result = {};
            CHECK_RETHROW(unary_op_inc(ctx, &rm_tmp, &result));

            CHECK_RETHROW(modrm_rm_write(ctx, &rm_operand, &result));
        } else {
            CHECK_FAIL_CODE(PIS_ERR_UNSUPPORTED_INSN);
        }

    } else if (first_opcode_byte == 0x80 || first_opcode_byte == 0x81 || first_opcode_byte == 0x83) {
        // xxx r/m[8], imm[8]
        pis_operand_size_t operand_size = ctx->operand_sizes.insn_default_not_64_bit;
        if (first_opcode_byte == 0x80) {
            // xxx r/m8, imm8
            operand_size = PIS_OPERAND_SIZE_1;
        }

        CHECK_RETHROW(modrm_fetch_and_process_with_operand_sizes(
            ctx,
            &modrm_operands,
            operand_size,
            operand_size
        ));

        pis_operand_t rm_tmp = LIFT_CTX_NEW_TMP(ctx->lift_ctx, operand_size);
        CHECK_RETHROW(modrm_operand_read(ctx, &rm_tmp, &modrm_operands.rm_operand));

        // calculate the appropriate immediate operand according to the opcode
        pis_operand_t imm_operand = {};
        switch (first_opcode_byte) {
            case 0x80: {
                // xxx r/m8, imm8
                u8 imm = LIFT_CTX_CUR1_ADVANCE(ctx->lift_ctx);
                imm_operand = PIS_OPERAND_CONST(imm, PIS_OPERAND_SIZE_1);
                break;
            }
            case 0x81:
                // xxx r/m, imm
                CHECK_RETHROW(fetch_imm_of_size_sign_extended(ctx, operand_size, &imm_operand));
                break;
            case 0x83: {
                // xxx r/m, imm8
                i8 imm8 = LIFT_CTX_CUR1_ADVANCE(ctx->lift_ctx);
                u64 imm64 = pis_sign_extend_byte(imm8, operand_size);
                imm_operand = PIS_OPERAND_CONST(imm64, operand_size);
                break;
            }
            default:
                UNREACHABLE();
        }

        // determine the kind of binary operation according to the modrm `reg` value.
        binop_fn_t binop = NULL;
        bool should_store_result = false;
        if (modrm_operands.modrm.reg == 5) {
            // sub
            binop = binop_sub;
            should_store_result = true;
        } else if (modrm_operands.modrm.reg == 0) {
            // add
            binop = binop_add;
            should_store_result = true;
        } else if (modrm_operands.modrm.reg == 1) {
            // or
            binop = binop_or;
            should_store_result = true;
        } else if (modrm_operands.modrm.reg == 2) {
            // adc
            binop = binop_adc;
            should_store_result = true;
        } else if (modrm_operands.modrm.reg == 6) {
            // xor
            binop = binop_xor;
            should_store_result = true;
        } else if (modrm_operands.modrm.reg == 4) {
            // and
            binop = binop_and;
            should_store_result = true;
        } else if (modrm_operands.modrm.reg == 7) {
            // cmp
            binop = binop_sub;
            should_store_result = false;
        } else {
            CHECK_FAIL_CODE(PIS_ERR_UNSUPPORTED_INSN);
        }

        // calculate the binary operation and optionally store its result
        CHECK(binop != NULL);
        CHECK_RETHROW(calc_and_maybe_store_binop_modrm_imm_with_size(
            ctx,
            binop,
            operand_size,
            should_store_result,
            &modrm_operands.rm_operand,
            &imm_operand
        ));
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
            pis_operand_t res_tmp = {};
            CHECK_RETHROW(calc_binop_modrm_imm_with_size(
                ctx,
                binop_and,
                PIS_OPERAND_SIZE_1,
                &modrm_operands.rm_operand,
                &imm_operand,
                &res_tmp
            ));
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
    } else if (first_opcode_byte == 0xe9) {
        // jmp rel
        pis_operand_t target = {};
        CHECK_RETHROW(rel_jmp_fetch_disp_and_calc_target(
            ctx,
            near_branch_operand_default_operand_size(ctx),
            &target
        ));

        LIFT_CTX_EMIT(ctx->lift_ctx, PIS_INSN1(PIS_OPCODE_JMP, target));
    } else if (first_opcode_byte == 0xeb) {
        // jmp rel8
        pis_operand_t target = {};
        CHECK_RETHROW(rel_jmp_fetch_disp_and_calc_target(ctx, PIS_OPERAND_SIZE_1, &target));

        LIFT_CTX_EMIT(ctx->lift_ctx, PIS_INSN1(PIS_OPCODE_JMP, target));
    } else if (opcode_cond_opcode_only(first_opcode_byte) == 0x70) {
        // jcc rel8
        pis_operand_t cond = {};
        CHECK_RETHROW(cond_opcode_decode_and_calc(ctx, first_opcode_byte, &cond));

        CHECK_RETHROW(do_cond_rel_jmp(ctx, &cond, PIS_OPERAND_SIZE_1));
    } else if (first_opcode_byte == 0xe8) {
        // call rel
        pis_operand_t target = {};
        CHECK_RETHROW(rel_jmp_fetch_disp_and_calc_target(
            ctx,
            near_branch_operand_default_operand_size(ctx),
            &target
        ));

        CHECK_RETHROW(push_ip(ctx));

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
            PIS_INSN3(PIS_OPCODE_ADD, sp, sp, PIS_OPERAND_CONST(operand_size_bytes, sp.size))
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
        CHECK_RETHROW(calc_binop_modrm_with_size(
            ctx,
            binop_and,
            PIS_OPERAND_SIZE_1,
            &modrm_operands.rm_operand,
            &modrm_operands.reg_operand,
            &res
        ));
    } else if (first_opcode_byte == 0x30) {
        // xor r/m8, r8
        CHECK_RETHROW(modrm_fetch_and_process_with_operand_sizes(
            ctx,
            &modrm_operands,
            PIS_OPERAND_SIZE_1,
            PIS_OPERAND_SIZE_1
        ));

        CHECK_RETHROW(calc_and_store_binop_modrm_with_size(
            ctx,
            binop_xor,
            PIS_OPERAND_SIZE_1,
            &modrm_operands.rm_operand,
            &modrm_operands.reg_operand
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
    } else if (first_opcode_byte == 0x3c) {
        // cmp al, imm8
        u8 imm = LIFT_CTX_CUR1_ADVANCE(ctx->lift_ctx);
        pis_operand_t imm_operand = PIS_OPERAND_CONST(imm, PIS_OPERAND_SIZE_1);

        pis_operand_t res = {};
        CHECK_RETHROW(binop_sub(ctx, &AL, &imm_operand, &res));
    } else if (first_opcode_byte == 0x04) {
        // add al, imm8
        u8 imm = LIFT_CTX_CUR1_ADVANCE(ctx->lift_ctx);
        pis_operand_t imm_operand = PIS_OPERAND_CONST(imm, PIS_OPERAND_SIZE_1);

        pis_operand_t res = {};
        CHECK_RETHROW(binop_add(ctx, &AL, &imm_operand, &res));
        CHECK_RETHROW(write_gpr(ctx, &AL, &res));
    } else if (first_opcode_byte == 0x34) {
        // xor al, imm8
        u8 imm = LIFT_CTX_CUR1_ADVANCE(ctx->lift_ctx);

        pis_operand_t res = {};
        CHECK_RETHROW(binop_xor(ctx, &AL, &PIS_OPERAND_CONST(imm, PIS_OPERAND_SIZE_1), &res));
        CHECK_RETHROW(write_gpr(ctx, &AL, &res));
    } else if (opcode_reg_opcode_only(first_opcode_byte) == 0xb8) {
        // mov <reg>, imm
        u8 reg_encoding = opcode_reg_extract(ctx, first_opcode_byte);
        pis_operand_size_t operand_size = ctx->operand_sizes.insn_default_not_64_bit;
        pis_operand_t dst_reg = reg_get_operand(reg_encoding, operand_size, ctx->prefixes);

        pis_operand_t imm = {};
        CHECK_RETHROW(fetch_imm_operand_of_size(ctx, operand_size, &imm));

        CHECK_RETHROW(write_gpr(ctx, &dst_reg, &imm));
    } else if (first_opcode_byte == 0xc7) {
        // xxx r/m, imm
        CHECK_RETHROW(modrm_fetch_and_process(ctx, &modrm_operands));

        pis_operand_t imm = {};
        CHECK_RETHROW(
            fetch_imm_of_size_sign_extended(ctx, ctx->operand_sizes.insn_default_not_64_bit, &imm)
        );

        if (modrm_operands.modrm.reg == 0) {
            // mov r/m, imm
            CHECK_RETHROW(modrm_rm_write(ctx, &modrm_operands.rm_operand.rm, &imm));
        } else {
            CHECK_FAIL_CODE(PIS_ERR_UNSUPPORTED_INSN);
        }
    } else if (first_opcode_byte == 0x25) {
        // and [R/E]AX, imm
        CHECK_RETHROW(calc_and_store_binop_ax_imm(ctx, binop_and));
    } else if (first_opcode_byte == 0x2d) {
        // sub [R/E]AX, imm
        CHECK_RETHROW(calc_and_store_binop_ax_imm(ctx, binop_sub));
    } else if (first_opcode_byte == 0x05) {
        // add [R/E]AX, imm
        CHECK_RETHROW(calc_and_store_binop_ax_imm(ctx, binop_add));
    } else if (first_opcode_byte == 0x3d) {
        // cmp [R/E]AX, imm
        pis_operand_t res = {};
        CHECK_RETHROW(calc_binop_ax_imm(ctx, binop_sub, &res));
    } else if (first_opcode_byte == 0xa8) {
        // test al, imm8
        u8 imm = LIFT_CTX_CUR1_ADVANCE(ctx->lift_ctx);

        pis_operand_t res = {};
        CHECK_RETHROW(binop_and(ctx, &AL, &PIS_OPERAND_CONST(imm, PIS_OPERAND_SIZE_1), &res));
    } else if (first_opcode_byte == 0x85) {
        // test r/m, r
        CHECK_RETHROW(modrm_fetch_and_process(ctx, &modrm_operands));

        pis_operand_t res = {};
        CHECK_RETHROW(calc_binop_modrm(
            ctx,
            binop_add,
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
        CHECK_RETHROW(binop_imul(ctx, &rm_value, &imm_operand, &res));

        CHECK_RETHROW(write_gpr(ctx, &modrm_operands.reg_operand.reg, &res));
    } else if (first_opcode_byte == 0x98) {
        // cbw/cwde/cdqe
        pis_operand_size_t operand_size = ctx->operand_sizes.insn_default_not_64_bit;
        pis_operand_size_t half_operand_size = operand_size / 2;

        pis_operand_t tmp = LIFT_CTX_NEW_TMP(ctx->lift_ctx, operand_size);
        LIFT_CTX_EMIT(
            ctx->lift_ctx,
            PIS_INSN2(PIS_OPCODE_SIGN_EXTEND, tmp, operand_resize(&RAX, half_operand_size))
        );

        pis_operand_t dst = operand_resize(&RAX, operand_size);
        CHECK_RETHROW(write_gpr(ctx, &dst, &tmp));
    } else if (first_opcode_byte == 0xc1 || first_opcode_byte == 0xc0 || first_opcode_byte == 0xd0 || first_opcode_byte == 0xd1 || first_opcode_byte == 0xd3) {
        // shift r/m, imm/cl

        // `0xd0` is `shift r/m8, 1` and `0xc0` is `shift r/m8, imm8`. so, set the operand size to 1
        // in those cases.
        pis_operand_size_t operand_size = (first_opcode_byte == 0xd0 || first_opcode_byte == 0xc0)
                                              ? PIS_OPERAND_SIZE_1
                                              : ctx->operand_sizes.insn_default_not_64_bit;

        CHECK_RETHROW(modrm_fetch_and_process_with_operand_sizes(
            ctx,
            &modrm_operands,
            operand_size,
            // don't care
            PIS_OPERAND_SIZE_1
        ));

        // determine the rhs operand according to the opcode
        pis_operand_t rhs_operand = {};
        switch (first_opcode_byte) {
            case 0xc0:
            case 0xc1: {
                // shift r/m[8], imm8
                u8 imm8 = LIFT_CTX_CUR1_ADVANCE(ctx->lift_ctx);
                rhs_operand = PIS_OPERAND_CONST(imm8, operand_size);
                break;
            }
            case 0xd0:
            case 0xd1:
                // shift r/m[8], 1
                rhs_operand = PIS_OPERAND_CONST(1, operand_size);
                break;
            case 0xd3: {
                // shift r/m, cl
                pis_operand_t cl_zero_extended = LIFT_CTX_NEW_TMP(ctx->lift_ctx, operand_size);
                LIFT_CTX_EMIT(
                    ctx->lift_ctx,
                    PIS_INSN2(PIS_OPCODE_ZERO_EXTEND, cl_zero_extended, CL)
                );
                rhs_operand = cl_zero_extended;
                break;
            }
            default:
                UNREACHABLE();
        }

        // determine the kind of binary operation according to the modrm `reg` value.
        binop_fn_t binop = NULL;
        if (modrm_operands.modrm.reg == 4) {
            // shl/sal
            binop = binop_shl;
        } else if (modrm_operands.modrm.reg == 5) {
            // shr
            binop = binop_shr;
        } else if (modrm_operands.modrm.reg == 7) {
            // sar
            binop = binop_sar;
        } else if (modrm_operands.modrm.reg == 0) {
            // rol
            binop = binop_rol;
        } else {
            CHECK_FAIL_CODE(PIS_ERR_UNSUPPORTED_INSN);
        }

        // calculate the binary operation and store its result
        CHECK(binop != NULL);
        CHECK_RETHROW(calc_and_store_binop_modrm_imm_with_size(
            ctx,
            binop,
            operand_size,
            &modrm_operands.rm_operand,
            &rhs_operand
        ));
    } else if (first_opcode_byte == 0xf4) {
        // hlt
        LIFT_CTX_EMIT(ctx->lift_ctx, PIS_INSN0(PIS_OPCODE_HALT));
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

/// returns the group 1 prefix of the current instruction.
static legacy_prefix_t group1_prefix(const insn_ctx_t* ctx) {
    return ctx->prefixes->legacy.by_group[LEGACY_PREFIX_GROUP_1];
}

/// lift an instruction with a REP or a BND prefix according to its second opcode byte
static err_t rep_or_bnd_lift_second_opcode_byte(const insn_ctx_t* ctx, u8 second_opcode_byte) {
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
            "unsupported second opcode byte with rep or bnd prefix: 0x%x",
            second_opcode_byte
        );
    }
cleanup:
    return err;
}

/// the context used to implement a REP prefix.
typedef struct {
    size_t insn_index_at_loop_start;
    pis_insn_t* jmp_end_insn;
} rep_ctx_t;

/// begin implementing a rep loop. this emits the first half of the rep loop which is at the start
/// of the lifted instruction. after calling this, you should emit your logic for a single iteration
/// of the loop, and then call the rep end function to emit the second half of the rep loop.
static err_t rep_begin(const insn_ctx_t* ctx, rep_ctx_t* rep_ctx) {
    err_t err = SUCCESS;

    // save the instruction index at the start of the loop so that we can jump to it later.
    rep_ctx->insn_index_at_loop_start = lift_ctx_index(ctx->lift_ctx);

    // first check if `cx` if zero
    pis_operand_t cx = operand_resize(&RCX, ctx->addr_size);
    pis_operand_t cx_equals_zero = LIFT_CTX_NEW_TMP(ctx->lift_ctx, PIS_OPERAND_SIZE_1);
    LIFT_CTX_EMIT(
        ctx->lift_ctx,
        PIS_INSN3(PIS_OPCODE_EQUALS, cx_equals_zero, cx, PIS_OPERAND_CONST(0, ctx->addr_size))
    );

    // emit a jump which should skip over the entire code. the offset is currently 0 since we
    // don't know the size of the code, but it will be filled with the correct value later on.
    LIFT_CTX_EMIT(
        ctx->lift_ctx,
        PIS_INSN2(PIS_OPCODE_JMP_COND, cx_equals_zero, PIS_OPERAND_CONST(0, PIS_OPERAND_SIZE_1))
    );
    CHECK_RETHROW(
        pis_lift_result_get_last_emitted_insn(ctx->lift_ctx->result, &rep_ctx->jmp_end_insn)
    );

    // now that we know that `cx` is not zero, decrement it.
    LIFT_CTX_EMIT(
        ctx->lift_ctx,
        PIS_INSN3(PIS_OPCODE_SUB, cx, cx, PIS_OPERAND_CONST(1, ctx->addr_size))
    );

cleanup:
    return err;
}

/// emits the second half of the rep loop, at the end of the instruction. this should be called
/// after calling the rep begin function and after emitting your code for a single iteration of the
/// rep loop.
static err_t rep_end(const insn_ctx_t* ctx, const rep_ctx_t* rep_ctx) {
    err_t err = SUCCESS;


    // now jump back to the start of the loop, for the next iteration of the loop.
    LIFT_CTX_EMIT(
        ctx->lift_ctx,
        PIS_INSN1(
            PIS_OPCODE_JMP,
            PIS_OPERAND_CONST(rep_ctx->insn_index_at_loop_start, PIS_OPERAND_SIZE_1)
        )
    );

    // now that we finished emitting the code, update the offset of the jmp instruction at the start
    // of the loop which should jump to the end of the instruction.
    rep_ctx->jmp_end_insn->operands[1] =
        PIS_OPERAND_CONST(lift_ctx_index(ctx->lift_ctx), PIS_OPERAND_SIZE_1);

cleanup:
    return err;
}

static err_t do_movs(const insn_ctx_t* ctx, pis_operand_size_t operand_size) {
    err_t err = SUCCESS;

    // movs can only be used with a REP prefix, not a REPNE prefix.
    CHECK(group1_prefix(ctx) == LEGACY_PREFIX_REPZ_OR_REP);

    rep_ctx_t rep_ctx = {};
    CHECK_RETHROW(rep_begin(ctx, &rep_ctx));

    pis_operand_t si = operand_resize(&RSI, ctx->addr_size);
    pis_operand_t di = operand_resize(&RDI, ctx->addr_size);

    // copy one chunk from [si] to [di].
    pis_operand_t byte_tmp = LIFT_CTX_NEW_TMP(ctx->lift_ctx, operand_size);
    LIFT_CTX_EMIT(ctx->lift_ctx, PIS_INSN2(PIS_OPCODE_LOAD, byte_tmp, si));
    LIFT_CTX_EMIT(ctx->lift_ctx, PIS_INSN2(PIS_OPCODE_STORE, di, byte_tmp));

    // increment si and di
    pis_operand_t increment =
        PIS_OPERAND_CONST(pis_operand_size_to_bytes(operand_size), ctx->addr_size);
    LIFT_CTX_EMIT(ctx->lift_ctx, PIS_INSN3(PIS_OPCODE_ADD, si, si, increment));
    LIFT_CTX_EMIT(ctx->lift_ctx, PIS_INSN3(PIS_OPCODE_ADD, di, di, increment));

    CHECK_RETHROW(rep_end(ctx, &rep_ctx));
cleanup:
    return err;
}

/// lift an instruction with a REP or a BND prefix according to its first opcode byte
static err_t __attribute__((unused))
rep_or_bnd_lift_first_opcode_byte(const insn_ctx_t* ctx, u8 first_opcode_byte) {
    err_t err = SUCCESS;

    if (first_opcode_byte == 0x0f) {
        // opcode is longer than 1 byte
        u8 second_opcode_byte = LIFT_CTX_CUR1_ADVANCE(ctx->lift_ctx);

        CHECK_RETHROW(rep_or_bnd_lift_second_opcode_byte(ctx, second_opcode_byte));
    } else if (first_opcode_byte == 0xa4) {
        // movsb
        CHECK_RETHROW(do_movs(ctx, PIS_OPERAND_SIZE_1));
    } else if (first_opcode_byte == 0xa5) {
        // movs[w/d/q]
        CHECK_RETHROW(do_movs(ctx, ctx->operand_sizes.insn_default_not_64_bit));
    } else {
        CHECK_FAIL_TRACE_CODE(
            PIS_ERR_UNSUPPORTED_INSN,
            "unsupported first opcode byte with rep or bnd prefix: 0x%x",
            first_opcode_byte
        );
    }
cleanup:
    return err;
}

op_size_t calc_size(const insn_ctx_t* ctx, size_t size_info_index) {
    const op_size_info_t* size_info = &op_size_infos_table[size_info_index];
    if (ctx->prefixes->rex.w) {
        return size_info->mode_64_with_rex_w;
    } else if (prefixes_contain_legacy_prefix(ctx->prefixes, LEGACY_PREFIX_OPERAND_SIZE_OVERRIDE)) {
        return size_info->with_operand_size_override;
    } else {
        switch (ctx->lift_ctx->pis_x86_ctx->cpumode) {
            case PIS_X86_CPUMODE_32_BIT:
                return size_info->mode_32;
            case PIS_X86_CPUMODE_64_BIT:
                return size_info->mode_64;
            default:
                // unreachable
                return OP_SIZE_8;
        }
    }
}

static u32 op_size_to_bits(op_size_t op_size) {
    return (u32) 1 << ((u32) op_size + 3);
}

static pis_operand_size_t op_size_to_pis_operand_size(op_size_t op_size) {
    return (u32) 1 << (u32) op_size;
}

static u64 op_size_max_unsigned_value(op_size_t op_size) {
    if (op_size == OP_SIZE_64) {
        return UINT64_MAX;
    } else {
        return ((u64) 1 << op_size_to_bits(op_size)) - 1;
    }
}

static err_t get_or_fetch_modrm(insn_ctx_t* ctx, modrm_t* modrm) {
    err_t err = SUCCESS;
    if (!ctx->has_modrm) {
        ctx->modrm_byte = LIFT_CTX_CUR1_ADVANCE(ctx->lift_ctx);
        ctx->has_modrm = true;
    }
    *modrm = modrm_decode_byte(ctx->modrm_byte);
cleanup:
    return err;
}

static pis_operand_t decode_specific_reg(specific_reg_t reg, op_size_t size) {
    u8 reg_encoding;
    switch (reg) {
        case SPECIFIC_REG_RAX:
            reg_encoding = 0;
            break;
        case SPECIFIC_REG_RCX:
            reg_encoding = 1;
            break;
        case SPECIFIC_REG_RDX:
            reg_encoding = 2;
            break;
        default:
            // unreachable
            reg_encoding = 0;
            break;
    }

    return PIS_OPERAND_REG(reg_encoding * 8, op_size_to_pis_operand_size(size));
}

static err_t lift_op(
    insn_ctx_t* ctx, u8 opcode_byte, const op_info_t* op_info, lifted_op_t* lifted_operand
) {
    err_t err = SUCCESS;
    switch (op_info->kind) {
        case OP_KIND_IMM: {
            op_size_t encoded_size = calc_size(ctx, op_info->imm.encoded_size_info_index);
            op_size_t extended_size = calc_size(ctx, op_info->imm.extended_size_info_index);

            u64 imm = 0;
            switch (op_info->imm.extend_kind) {
                case IMM_EXT_SIGN_EXTEND:
                    CHECK_RETHROW(fetch_imm_of_op_size_sext(ctx, encoded_size, &imm));
                    break;
                case IMM_EXT_ZERO_EXTEND:
                    CHECK_RETHROW(fetch_imm_of_op_size_zext(ctx, encoded_size, &imm));
                    break;
            }

            CHECK(extended_size >= encoded_size);

            imm &= op_size_max_unsigned_value(extended_size);

            *lifted_operand = (lifted_op_t) {
                .kind = LIFTED_OP_KIND_VALUE,
                .value = PIS_OPERAND_CONST(imm, op_size_to_pis_operand_size(extended_size)),
            };

            break;
        }
        case OP_KIND_SPECIFIC_IMM: {
            u64 imm;

            switch (op_info->specific_imm.value) {
                case SPECIFIC_IMM_ZERO:
                    imm = 0;
                    break;
                case SPECIFIC_IMM_ONE:
                    imm = 1;
                    break;
            }

            op_size_t size = calc_size(ctx, op_info->specific_imm.operand_size_info_index);
            *lifted_operand = (lifted_op_t) {
                .kind = LIFTED_OP_KIND_VALUE,
                .value = PIS_OPERAND_CONST(imm, op_size_to_pis_operand_size(size)),
            };

            break;
        }
        case OP_KIND_REG: {
            u8 reg_encoding;
            switch (op_info->reg.encoding) {
                case REG_ENC_MODRM: {
                    modrm_t modrm = {};
                    CHECK_RETHROW(get_or_fetch_modrm(ctx, &modrm));
                    reg_encoding = apply_rex_bit_to_reg_encoding(modrm.reg, ctx->prefixes->rex.r);
                    break;
                }
                case REG_ENC_OPCODE:
                    reg_encoding = opcode_reg_extract(ctx, opcode_byte);
                    break;
            }

            op_size_t size = calc_size(ctx, op_info->reg.size_info_index);

            *lifted_operand = (lifted_op_t) {
                .kind = LIFTED_OP_KIND_WRITABLE_VALUE,
                .value =
                    reg_get_operand(reg_encoding, op_size_to_pis_operand_size(size), ctx->prefixes),
            };

            break;
        }
        case OP_KIND_RM: {
            modrm_t modrm = {};
            CHECK_RETHROW(get_or_fetch_modrm(ctx, &modrm));

            op_size_t size = calc_size(ctx, op_info->rm.size_info_index);
            pis_operand_size_t pis_operand_size = op_size_to_pis_operand_size(size);

            modrm_rm_operand_t rm_operand = {};
            CHECK_RETHROW(modrm_decode_rm_operand(ctx, &modrm, pis_operand_size, &rm_operand));

            if (rm_operand.is_memory) {
                *lifted_operand = (lifted_op_t) {
                    .kind = LIFTED_OP_KIND_MEM,
                    .mem =
                        (lifted_op_mem_t) {
                            .addr = rm_operand.addr_or_reg,
                            .size = pis_operand_size,
                        },
                };
            } else {
                *lifted_operand = (lifted_op_t) {
                    .kind = LIFTED_OP_KIND_WRITABLE_VALUE,
                    .value = rm_operand.addr_or_reg,
                };
            }
            break;
        }
        case OP_KIND_SPECIFIC_REG: {
            op_size_t size = calc_size(ctx, op_info->specific_reg.size_info_index);

            *lifted_operand = (lifted_op_t) {
                .kind = LIFTED_OP_KIND_WRITABLE_VALUE,
                .value = decode_specific_reg(op_info->specific_reg.reg, size),
            };
            break;
        }
        case OP_KIND_ZEXT_SPECIFIC_REG: {
            op_size_t size = calc_size(ctx, op_info->zext_specific_reg.size_info_index);
            op_size_t extended_size =
                calc_size(ctx, op_info->zext_specific_reg.extended_size_info_index);

            pis_operand_t reg_operand = decode_specific_reg(op_info->zext_specific_reg.reg, size);

            if (extended_size > size) {
                pis_operand_t extended_reg =
                    LIFT_CTX_NEW_TMP(ctx->lift_ctx, op_size_to_pis_operand_size(extended_size));
                LIFT_CTX_EMIT(
                    ctx->lift_ctx,
                    PIS_INSN2(PIS_OPCODE_ZERO_EXTEND, extended_reg, reg_operand)
                );
                *lifted_operand = (lifted_op_t) {
                    .kind = LIFTED_OP_KIND_VALUE,
                    .value = extended_reg,
                };
            } else {
                *lifted_operand = (lifted_op_t) {
                    .kind = LIFTED_OP_KIND_VALUE,
                    .value = reg_operand,
                };
            }

            break;
        }
        case OP_KIND_REL: {
            // the behvaiour of relative operands with address/operand size override is weird
            // (masking of the ip value), so don't allow it.
            CHECK(
                !prefixes_contain_legacy_prefix(ctx->prefixes, LEGACY_PREFIX_OPERAND_SIZE_OVERRIDE)
            );
            CHECK(
                !prefixes_contain_legacy_prefix(ctx->prefixes, LEGACY_PREFIX_ADDRESS_SIZE_OVERRIDE)
            );

            op_size_t size = calc_size(ctx, op_info->rel.size_info_index);

            u64 rel_offset = 0;
            CHECK_RETHROW(fetch_imm_of_op_size_sext(ctx, size, &rel_offset));

            u64 cur_insn_end_addr = ctx->lift_ctx->cur_insn_addr + lift_ctx_index(ctx->lift_ctx);
            u64 target_addr = rel_jmp_mask_ip_value(ctx, cur_insn_end_addr + rel_offset);

            *lifted_operand = (lifted_op_t) {
                .kind = LIFTED_OP_KIND_VALUE,
                .value = PIS_OPERAND_RAM(target_addr, PIS_OPERAND_SIZE_1),
            };

            break;
        }
        case OP_KIND_MEM_OFFSET: {
            u64 addr = 0;
            CHECK_RETHROW(fetch_imm_of_pis_size_zext(ctx, ctx->addr_size, &addr));

            *lifted_operand = (lifted_op_t) {
                .kind = LIFTED_OP_KIND_MEM,
                .value = PIS_OPERAND_CONST(addr, ctx->addr_size),
            };

            break;
        }
        case OP_KIND_IMPLICIT: {
            op_size_t size = calc_size(ctx, op_info->implicit.size_info_index);

            // implicit operands are only used to determine the operand size.
            *lifted_operand = (lifted_op_t) {
                .kind = LIFTED_OP_KIND_IMPLICIT,
                .implicit =
                    {
                        .size = op_size_to_pis_operand_size(size),
                    },
            };
            break;
        }
        case OP_KIND_COND: {
            pis_operand_t cond = {};
            CHECK_RETHROW(cond_opcode_decode_and_calc(ctx, opcode_byte, &cond));

            *lifted_operand = (lifted_op_t) {
                .kind = LIFTED_OP_KIND_VALUE,
                .value = cond,
            };

            break;
        }
    }
cleanup:
    return err;
}

static pis_operand_size_t lifted_op_size(const lifted_op_t* op) {
    switch (op->kind) {
        case LIFTED_OP_KIND_MEM:
            return op->mem.size;
        case LIFTED_OP_KIND_VALUE:
        case LIFTED_OP_KIND_WRITABLE_VALUE:
            return op->value.size;
        default:
            // unreachable
            return PIS_OPERAND_SIZE_1;
    }
}

static err_t lifted_op_read(const insn_ctx_t* ctx, const lifted_op_t* op, pis_operand_t* value) {
    err_t err = SUCCESS;
    switch (op->kind) {
        case LIFTED_OP_KIND_MEM: {
            pis_operand_t tmp = LIFT_CTX_NEW_TMP(ctx->lift_ctx, op->mem.size);
            LIFT_CTX_EMIT(ctx->lift_ctx, PIS_INSN2(PIS_OPCODE_LOAD, tmp, op->mem.addr));
            *value = tmp;
            break;
        }
        case LIFTED_OP_KIND_VALUE:
        case LIFTED_OP_KIND_WRITABLE_VALUE:
            *value = op->value;
            break;
        case LIFTED_OP_KIND_IMPLICIT:
            // can't read implicit operands
            UNREACHABLE();
    }
cleanup:
    return err;
}

static err_t
    lifted_op_write(const insn_ctx_t* ctx, const lifted_op_t* op, const pis_operand_t* value) {
    err_t err = SUCCESS;
    switch (op->kind) {
        case LIFTED_OP_KIND_MEM: {
            LIFT_CTX_EMIT(ctx->lift_ctx, PIS_INSN2(PIS_OPCODE_STORE, op->mem.addr, *value));
            break;
        }
        case LIFTED_OP_KIND_VALUE:
        case LIFTED_OP_KIND_WRITABLE_VALUE:
            LIFT_CTX_EMIT(ctx->lift_ctx, PIS_INSN2(PIS_OPCODE_MOVE, op->value, *value));
            break;
        case LIFTED_OP_KIND_IMPLICIT:
            // can't write to implicit operands
            UNREACHABLE();
    }
cleanup:
    return err;
}

static err_t handle_mnemonic_binop(
    const insn_ctx_t* ctx, const lifted_op_t* ops, size_t ops_amount, binop_fn_t binop, bool store
) {
    err_t err = SUCCESS;
    CHECK(ops_amount == 2);

    pis_operand_t lhs = {};
    CHECK_RETHROW(lifted_op_read(ctx, &ops[0], &lhs));

    pis_operand_t rhs = {};
    CHECK_RETHROW(lifted_op_read(ctx, &ops[1], &rhs));

    pis_operand_t res = {};
    CHECK_RETHROW(binop(ctx, &lhs, &rhs, &res));

    if (store) {
        CHECK_RETHROW(lifted_op_write(ctx, &ops[0], &res));
    }
cleanup:
    return err;
}

static err_t handle_mnemonic_unary_op(
    const insn_ctx_t* ctx, const lifted_op_t* ops, size_t ops_amount, unary_op_fn_t unary_op
) {
    err_t err = SUCCESS;
    CHECK(ops_amount == 1);

    pis_operand_t op = {};
    CHECK_RETHROW(lifted_op_read(ctx, &ops[0], &op));

    pis_operand_t res = {};
    CHECK_RETHROW(unary_op(ctx, &op, &res));

    CHECK_RETHROW(lifted_op_write(ctx, &ops[0], &res));
cleanup:
    return err;
}

#define DEFINE_BINOP_MNEMONIC_HANDLER(NAME)                                                        \
    static err_t handle_mnemonic_##NAME(                                                           \
        const insn_ctx_t* ctx,                                                                     \
        const lifted_op_t* ops,                                                                    \
        size_t ops_amount                                                                          \
    ) {                                                                                            \
        err_t err = SUCCESS;                                                                       \
        CHECK_RETHROW(handle_mnemonic_binop(ctx, ops, ops_amount, binop_##NAME, true));            \
    cleanup:                                                                                       \
        return err;                                                                                \
    }

#define DEFINE_COMPARISON_BINOP_MNEMONIC_HANDLER(NAME, BINOP_NAME)                                 \
    static err_t handle_mnemonic_##NAME(                                                           \
        const insn_ctx_t* ctx,                                                                     \
        const lifted_op_t* ops,                                                                    \
        size_t ops_amount                                                                          \
    ) {                                                                                            \
        err_t err = SUCCESS;                                                                       \
        CHECK_RETHROW(handle_mnemonic_binop(ctx, ops, ops_amount, binop_##BINOP_NAME, false));     \
    cleanup:                                                                                       \
        return err;                                                                                \
    }

#define DEFINE_UNARY_OP_MNEMONIC_HANDLER(NAME)                                                     \
    static err_t handle_mnemonic_##NAME(                                                           \
        const insn_ctx_t* ctx,                                                                     \
        const lifted_op_t* ops,                                                                    \
        size_t ops_amount                                                                          \
    ) {                                                                                            \
        err_t err = SUCCESS;                                                                       \
        CHECK_RETHROW(handle_mnemonic_unary_op(ctx, ops, ops_amount, unary_op_##NAME));            \
    cleanup:                                                                                       \
        return err;                                                                                \
    }

DEFINE_BINOP_MNEMONIC_HANDLER(add);
DEFINE_BINOP_MNEMONIC_HANDLER(and);
DEFINE_BINOP_MNEMONIC_HANDLER(sub);
DEFINE_BINOP_MNEMONIC_HANDLER(shr);
DEFINE_BINOP_MNEMONIC_HANDLER(xor);
DEFINE_BINOP_MNEMONIC_HANDLER(or);

DEFINE_COMPARISON_BINOP_MNEMONIC_HANDLER(cmp, sub);
DEFINE_COMPARISON_BINOP_MNEMONIC_HANDLER(test, and);

DEFINE_UNARY_OP_MNEMONIC_HANDLER(dec);

static err_t handle_mnemonic_mov(const insn_ctx_t* ctx, const lifted_op_t* ops, size_t ops_amount) {
    err_t err = SUCCESS;
    CHECK(ops_amount == 2);

    pis_operand_t rhs = {};
    CHECK_RETHROW(lifted_op_read(ctx, &ops[1], &rhs));

    CHECK_RETHROW(lifted_op_write(ctx, &ops[0], &rhs));
cleanup:
    return err;
}

static err_t handle_mnemonic_jcc(const insn_ctx_t* ctx, const lifted_op_t* ops, size_t ops_amount) {
    err_t err = SUCCESS;
    CHECK(ops_amount == 2);

    pis_operand_t cond = {};
    CHECK_RETHROW(lifted_op_read(ctx, &ops[0], &cond));

    pis_operand_t target = {};
    CHECK_RETHROW(lifted_op_read(ctx, &ops[1], &target));

    LIFT_CTX_EMIT(ctx->lift_ctx, PIS_INSN2(PIS_OPCODE_JMP_COND, cond, target));

cleanup:
    return err;
}

static err_t
    handle_mnemonic_call(const insn_ctx_t* ctx, const lifted_op_t* ops, size_t ops_amount) {
    err_t err = SUCCESS;
    CHECK(ops_amount == 1);

    pis_operand_t target = {};
    CHECK_RETHROW(lifted_op_read(ctx, &ops[0], &target));

    CHECK_RETHROW(push_ip(ctx));

    LIFT_CTX_EMIT(ctx->lift_ctx, PIS_INSN1(PIS_OPCODE_JMP, target));

cleanup:
    return err;
}

static err_t handle_mnemonic_jmp(const insn_ctx_t* ctx, const lifted_op_t* ops, size_t ops_amount) {
    err_t err = SUCCESS;
    CHECK(ops_amount == 1);

    pis_operand_t target = {};
    CHECK_RETHROW(lifted_op_read(ctx, &ops[0], &target));

    LIFT_CTX_EMIT(ctx->lift_ctx, PIS_INSN1(PIS_OPCODE_JMP, target));

cleanup:
    return err;
}

static err_t handle_mnemonic_lea(const insn_ctx_t* ctx, const lifted_op_t* ops, size_t ops_amount) {
    err_t err = SUCCESS;
    CHECK(ops_amount == 2);

    CHECK(ops[1].kind == LIFTED_OP_KIND_MEM);

    CHECK_RETHROW(lifted_op_write(ctx, &ops[0], &ops[1].mem.addr));
cleanup:
    return err;
}

static err_t
    handle_mnemonic_endbr(const insn_ctx_t* ctx, const lifted_op_t* ops, size_t ops_amount) {
    // endbr is a nop
    UNUSED(ctx);
    UNUSED(ops);
    UNUSED(ops_amount);
    return SUCCESS;
}

static err_t handle_mnemonic_pop(const insn_ctx_t* ctx, const lifted_op_t* ops, size_t ops_amount) {
    err_t err = SUCCESS;
    CHECK(ops_amount == 1);

    pis_operand_size_t operand_size = lifted_op_size(&ops[0]);
    pis_operand_t sp = ctx->lift_ctx->sp;
    u64 operand_size_bytes = pis_operand_size_to_bytes(operand_size);

    pis_operand_t tmp = LIFT_CTX_NEW_TMP(ctx->lift_ctx, operand_size);

    LIFT_CTX_EMIT(ctx->lift_ctx, PIS_INSN2(PIS_OPCODE_LOAD, tmp, sp));

    LIFT_CTX_EMIT(
        ctx->lift_ctx,
        PIS_INSN3(PIS_OPCODE_ADD, sp, sp, PIS_OPERAND_CONST(operand_size_bytes, sp.size))
    );

    CHECK_RETHROW(lifted_op_write(ctx, &ops[0], &tmp));
cleanup:
    return err;
}

static err_t
    handle_mnemonic_push(const insn_ctx_t* ctx, const lifted_op_t* ops, size_t ops_amount) {
    err_t err = SUCCESS;
    CHECK(ops_amount == 1);

    pis_operand_t to_push = {};
    CHECK_RETHROW(lifted_op_read(ctx, &ops[0], &to_push));
    CHECK_RETHROW(push(ctx, &to_push));
cleanup:
    return err;
}

static err_t
    handle_mnemonic_stos(const insn_ctx_t* ctx, const lifted_op_t* ops, size_t ops_amount) {
    err_t err = SUCCESS;

    // we expect 1 implicit operand
    CHECK(ops_amount == 1);
    CHECK(ops[0].kind == LIFTED_OP_KIND_IMPLICIT);

    // `stos` must be used with a `rep` prefix
    CHECK(group1_prefix(ctx) == LEGACY_PREFIX_REPZ_OR_REP);

    rep_ctx_t rep_ctx = {};
    CHECK_RETHROW(rep_begin(ctx, &rep_ctx));

    pis_operand_size_t operand_size = ops[0].implicit.size;

    pis_operand_t ax = operand_resize(&RAX, operand_size);
    pis_operand_t di = operand_resize(&RDI, ctx->addr_size);

    // copy one chunk from ax to [di].
    LIFT_CTX_EMIT(ctx->lift_ctx, PIS_INSN2(PIS_OPCODE_STORE, di, ax));

    // increment di
    pis_operand_t increment =
        PIS_OPERAND_CONST(pis_operand_size_to_bytes(operand_size), ctx->addr_size);
    LIFT_CTX_EMIT(ctx->lift_ctx, PIS_INSN3(PIS_OPCODE_ADD, di, di, increment));

    CHECK_RETHROW(rep_end(ctx, &rep_ctx));
cleanup:
    return err;
}

static const mnemonic_handler_t mnemonic_handler_table[MNEMONIC_MAX + 1] = {
    [MNEMONIC_SHR] = handle_mnemonic_shr,
    [MNEMONIC_XOR] = handle_mnemonic_xor,
    [MNEMONIC_ADD] = handle_mnemonic_add,
    [MNEMONIC_AND] = handle_mnemonic_and,
    [MNEMONIC_SUB] = handle_mnemonic_sub,
    [MNEMONIC_OR] = handle_mnemonic_or,
    [MNEMONIC_MOV] = handle_mnemonic_mov,
    [MNEMONIC_ENDBR] = handle_mnemonic_endbr,
    [MNEMONIC_POP] = handle_mnemonic_pop,
    [MNEMONIC_PUSH] = handle_mnemonic_push,
    [MNEMONIC_LEA] = handle_mnemonic_lea,
    [MNEMONIC_STOS] = handle_mnemonic_stos,
    [MNEMONIC_CMP] = handle_mnemonic_cmp,
    [MNEMONIC_JCC] = handle_mnemonic_jcc,
    [MNEMONIC_CALL] = handle_mnemonic_call,
    [MNEMONIC_JMP] = handle_mnemonic_jmp,
    [MNEMONIC_TEST] = handle_mnemonic_test,
    [MNEMONIC_DEC] = handle_mnemonic_dec,
};

static err_t lift_regular_insn_info(
    insn_ctx_t* ctx, uint8_t opcode_byte, const regular_insn_info_t* insn_info
) {
    err_t err = SUCCESS;
    lifted_op_t lifted_ops[X86_TABLES_INSN_MAX_OPS] = {};
    const uint8_t* op_info_indexes = &laid_out_ops_infos_table[insn_info->first_op_index];
    u8 ops_amount = insn_info->ops_amount;
    u8 mnemonic = insn_info->mnemonic;
    for (size_t i = 0; i < ops_amount; i++) {
        uint8_t op_info_index = op_info_indexes[i];
        const op_info_t* op_info = &op_infos_table[op_info_index];
        CHECK_RETHROW(lift_op(ctx, opcode_byte, op_info, &lifted_ops[i]));
    }
    mnemonic_handler_t mnemonic_handler = mnemonic_handler_table[mnemonic];
    CHECK_TRACE_CODE(
        mnemonic_handler != NULL,
        PIS_ERR_UNSUPPORTED_INSN,
        "unsupported mnemonic %d",
        mnemonic
    );
    CHECK_RETHROW(mnemonic_handler(ctx, lifted_ops, ops_amount));
cleanup:
    return err;
}

static err_t lift_modrm_reg_opcode_ext_insn_info(
    insn_ctx_t* ctx, u8 opcode_byte, const modrm_reg_opcode_ext_table_t* table
) {
    err_t err = SUCCESS;

    modrm_t modrm = {};
    CHECK_RETHROW(get_or_fetch_modrm(ctx, &modrm));

    CHECK_RETHROW(lift_regular_insn_info(ctx, opcode_byte, &table->by_reg_value[modrm.reg]));

cleanup:
    return err;
}

static err_t
    lift_opcode_byte(insn_ctx_t* ctx, u8 opcode_byte, const insn_info_t* opcode_byte_table) {
    err_t err = SUCCESS;
    const insn_info_t* insn_info = &opcode_byte_table[opcode_byte];
    if (insn_info->mnemonic == MNEMONIC_UNSUPPORTED) {
        CHECK_FAIL_TRACE_CODE(
            PIS_ERR_UNSUPPORTED_INSN,
            "unsupported opcode byte 0x%x",
            opcode_byte
        );
    } else if (insn_info->mnemonic == MNEMONIC_MODRM_REG_OPCODE_EXT) {
        // modrm reg opcode ext
        CHECK_RETHROW(lift_modrm_reg_opcode_ext_insn_info(
            ctx,
            opcode_byte,
            &modrm_reg_opcode_ext_tables[insn_info->modrm_reg_opcode_ext.modrm_reg_table_index]
        ));
    } else {
        CHECK_RETHROW(lift_regular_insn_info(ctx, opcode_byte, &insn_info->regular));
    }
cleanup:
    return err;
}

/// lift the next instruction after processing its prefixes.
static err_t post_prefixes_lift(insn_ctx_t* ctx) {
    err_t err = SUCCESS;

    u8 first_opcode_byte = LIFT_CTX_CUR1_ADVANCE(ctx->lift_ctx);
    if (first_opcode_byte == 0x0f) {
        // 2 or 3 byte opcode
        u8 second_opcode_byte = LIFT_CTX_CUR1_ADVANCE(ctx->lift_ctx);
        if (second_opcode_byte == 0x38 || second_opcode_byte == 0x3a) {
            // 3 byte opcode
            CHECK_FAIL_TRACE_CODE(
                PIS_ERR_UNSUPPORTED_INSN,
                "3 byte opcodes are currently not supported"
            );
        } else {
            // 2 byte opcode
            CHECK_RETHROW(lift_opcode_byte(ctx, second_opcode_byte, second_opcode_byte_table));
        }
    } else {
        // 1 byte opcode
        CHECK_RETHROW(lift_opcode_byte(ctx, first_opcode_byte, first_opcode_byte_table));
    }

cleanup:
    return err;
}

/// lift the next instruction using the given ctx.
static err_t lift(lift_ctx_t* ctx) {
    err_t err = SUCCESS;
    prefixes_t prefixes = {};

    CHECK_RETHROW(parse_prefixes(ctx, &prefixes));

    insn_ctx_t insn_ctx = {
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
    CHECK_RETHROW(post_prefixes_lift(&insn_ctx));

cleanup:
    return err;
}

/// lift the next instruction.
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
        .sp = operand_resize(&RSP, get_effective_stack_addr_size(ctx->cpumode)),
    };
    CHECK_RETHROW(lift(&lift_ctx));

    result->machine_insn_len = lift_ctx_index(&lift_ctx);

cleanup:
    return err;
}
