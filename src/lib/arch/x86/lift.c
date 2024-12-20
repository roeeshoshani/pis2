#include "lift.h"
#include "../../errors.h"
#include "../../except.h"
#include "../../pis.h"
#include "ctx.h"
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
    LIFTED_OP_KIND_REG,
    LIFTED_OP_KIND_MEM,
    LIFTED_OP_KIND_IMPLICIT,
} lifted_op_kind_t;

typedef struct {
    pis_op_t addr;
    pis_size_t size;
} lifted_op_mem_t;

typedef struct {
    lifted_op_kind_t kind;
    union {
        pis_op_t value;
        pis_op_t reg;
        lifted_op_mem_t mem;
        struct {
            pis_size_t size;
        } implicit;
    };
} lifted_op_t;

typedef err_t (*mnemonic_handler_t)(ctx_t* ctx, const lifted_op_t* ops, size_t ops_amount);

/// the prototype for a binary operation function - that is an operation which takes 2 input
/// operands and produces a single result, for example an `ADD` operation.
typedef err_t (*binop_fn_t)(ctx_t* ctx, const pis_op_t* a, const pis_op_t* b, pis_op_t* result);

/// the prototype for a unary operation function - that is an operation which takes 1 operand and
/// applies some operation to it, for example a `NOT` operation.
typedef err_t (*unary_op_fn_t)(ctx_t* ctx, const pis_op_t* operand, pis_op_t* result);

/// the prototype for a flag calculation of a binary operation. the functions takes the 2 input
/// operands and writes out the result flag value.
typedef err_t (*binop_calc_flag_fn_t
)(ctx_t* ctx, const pis_op_t* a, const pis_op_t* b, const pis_op_t* result);

/// extracts the condition encoding of an opcode which has a condition encoded in its value.
static u8 opcode_cond_extract(u8 opcode_byte) {
    return opcode_byte & 0b1111;
}

/// reads and resizes an operand to the desired size. if the new size is larger than the original,
/// zero extension is used.
static err_t
    read_resize_zext(ctx_t* ctx, const pis_op_t* value, pis_size_t new_size, pis_op_t* resized) {
    err_t err = SUCCESS;

    pis_op_t tmp = TMP_ALLOC(&ctx->tmp_allocator, new_size);

    pis_opcode_t opcode;
    if (new_size == value->size) {
        // same size
        opcode = PIS_OPCODE_MOVE;
    } else if (new_size > value->size) {
        // increase size
        opcode = PIS_OPCODE_ZERO_EXTEND;
    } else {
        // truncate
        opcode = PIS_OPCODE_GET_LOW_BITS;
    }

    PIS_EMIT(&ctx->args->result, PIS_INSN2(opcode, tmp, *value));

    *resized = tmp;
cleanup:
    return err;
}

/// resizes the input operand to the desired size and writes it to the target operand. if the new
/// size is larger than the original, zero extension is used.
static err_t write_resize_zext(ctx_t* ctx, const pis_op_t* write_to, const pis_op_t* input) {
    err_t err = SUCCESS;

    pis_opcode_t opcode;
    if (write_to->size == input->size) {
        // same size
        opcode = PIS_OPCODE_MOVE;
    } else if (write_to->size > input->size) {
        // increase size
        opcode = PIS_OPCODE_ZERO_EXTEND;
    } else {
        // truncate
        opcode = PIS_OPCODE_GET_LOW_BITS;
    }

    PIS_EMIT(&ctx->args->result, PIS_INSN2(opcode, *write_to, *input));
cleanup:
    return err;
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
static err_t calc_cond(ctx_t* ctx, const x86_cond_t cond, pis_op_t* result) {
    err_t err = SUCCESS;

    pis_op_t tmp = TMP_ALLOC(&ctx->tmp_allocator, PIS_SIZE_1);

    switch (cond.kind) {
        case X86_COND_CLASS_OVERFLOW:
            PIS_EMIT(
                &ctx->args->result,
                PIS_INSN2(PIS_OPCODE_MOVE, tmp, pis_reg_to_op(X86_FLAGS_OF))
            );
            break;
        case X86_COND_CLASS_BELOW:
            PIS_EMIT(
                &ctx->args->result,
                PIS_INSN2(PIS_OPCODE_MOVE, tmp, pis_reg_to_op(X86_FLAGS_CF))
            );
            break;
        case X86_COND_CLASS_EQUALS:
            PIS_EMIT(
                &ctx->args->result,
                PIS_INSN2(PIS_OPCODE_MOVE, tmp, pis_reg_to_op(X86_FLAGS_ZF))
            );
            break;
        case X86_COND_CLASS_BELOW_EQUAL:
            PIS_EMIT(
                &ctx->args->result,
                PIS_INSN3(
                    PIS_OPCODE_OR,
                    tmp,
                    pis_reg_to_op(X86_FLAGS_ZF),
                    pis_reg_to_op(X86_FLAGS_CF)
                )
            );
            break;
        case X86_COND_CLASS_SIGN:
            PIS_EMIT(
                &ctx->args->result,
                PIS_INSN2(PIS_OPCODE_MOVE, tmp, pis_reg_to_op(X86_FLAGS_SF))
            );
            break;
        case X86_COND_CLASS_PARITY:
            PIS_EMIT(
                &ctx->args->result,
                PIS_INSN2(PIS_OPCODE_MOVE, tmp, pis_reg_to_op(X86_FLAGS_PF))
            );
            break;
        case X86_COND_CLASS_LOWER:
            PIS_EMIT(
                &ctx->args->result,
                PIS_INSN3(
                    PIS_OPCODE_XOR,
                    tmp,
                    pis_reg_to_op(X86_FLAGS_SF),
                    pis_reg_to_op(X86_FLAGS_OF)
                )
            );
            break;
        case X86_COND_CLASS_LOWER_EQUAL: {
            pis_op_t inner_tmp = TMP_ALLOC(&ctx->tmp_allocator, PIS_SIZE_1);
            PIS_EMIT(
                &ctx->args->result,
                PIS_INSN3(
                    PIS_OPCODE_XOR,
                    inner_tmp,
                    pis_reg_to_op(X86_FLAGS_SF),
                    pis_reg_to_op(X86_FLAGS_OF)
                )
            );
            PIS_EMIT(
                &ctx->args->result,
                PIS_INSN3(PIS_OPCODE_OR, tmp, inner_tmp, pis_reg_to_op(X86_FLAGS_ZF))
            );
            break;
        }
        default:
            UNREACHABLE();
    }

    if (cond.is_negative) {
        PIS_EMIT(&ctx->args->result, PIS_INSN2(PIS_OPCODE_COND_NEGATE, tmp, tmp));
    }
    *result = tmp;

cleanup:
    return err;
}

/// decodes an x86 condition encoding from the given opcode and calculates its value into the given
/// result operand.
static err_t cond_opcode_decode_and_calc(ctx_t* ctx, u8 opcode_byte, pis_op_t* result) {
    err_t err = SUCCESS;

    x86_cond_t cond = {};
    CHECK_RETHROW(cond_decode(opcode_cond_extract(opcode_byte), &cond));

    CHECK_RETHROW(calc_cond(ctx, cond, result));

cleanup:
    return err;
}

/// returns the effective stack address size. this is the size of the `sp` register to be used in
/// stack-addressing operations.
static pis_size_t get_effective_stack_addr_size(pis_x86_cpumode_t cpumode) {
    return pis_x86_cpumode_get_operand_size(cpumode);
}

/// converts the given register to an operand and resizes it to the given new size.
static pis_op_t reg_to_op_resize(pis_reg_t reg, pis_size_t size) {
    return PIS_OPERAND_REG(reg.region.offset, size);
}

/// calculates the effective operand size for the instruction.
static pis_size_t get_effective_operand_size(
    pis_x86_cpumode_t cpumode, const prefixes_t* prefixes, bool default_to_64_bit
) {
    bool has_size_override =
        prefixes_contain_legacy_prefix(prefixes, LEGACY_PREFIX_OPERAND_SIZE_OVERRIDE);

    switch (cpumode) {
        case PIS_X86_CPUMODE_32_BIT:
            return has_size_override ? PIS_SIZE_2 : PIS_SIZE_4;
        case PIS_X86_CPUMODE_64_BIT:
            if (prefixes->rex.w) {
                return PIS_SIZE_8;
            } else {
                if (default_to_64_bit) {
                    return has_size_override ? PIS_SIZE_2 : PIS_SIZE_8;
                } else {
                    return has_size_override ? PIS_SIZE_2 : PIS_SIZE_4;
                }
            }
        default:
            // unreachable
            return PIS_SIZE_1;
    }
}

/// calculates the effective address size of an instruction.
static pis_size_t get_effective_addr_size(pis_x86_cpumode_t cpumode, const prefixes_t* prefixes) {
    bool has_size_override =
        prefixes_contain_legacy_prefix(prefixes, LEGACY_PREFIX_ADDRESS_SIZE_OVERRIDE);

    switch (cpumode) {
        case PIS_X86_CPUMODE_32_BIT:
            return has_size_override ? PIS_SIZE_2 : PIS_SIZE_4;
        case PIS_X86_CPUMODE_64_BIT:
            return has_size_override ? PIS_SIZE_4 : PIS_SIZE_8;
        default:
            // unreachable
            return PIS_SIZE_1;
    }
}

/// calculates the parity flag of the given value into the given result operand.
static err_t calc_parity_flag_into(ctx_t* ctx, const pis_op_t* value, const pis_op_t* result) {
    err_t err = SUCCESS;

    pis_op_t low_byte = {};
    CHECK_RETHROW(read_resize_zext(ctx, value, PIS_SIZE_1, &low_byte));

    PIS_EMIT(&ctx->args->result, PIS_INSN2(PIS_OPCODE_PARITY, *result, low_byte));

cleanup:
    return err;
}

/// calculates the parity flag of the given calculation result into the parity flag register.
static err_t calc_parity_flag(ctx_t* ctx, const pis_op_t* calculation_result) {
    err_t err = SUCCESS;

    pis_op_t pf = pis_reg_to_op(X86_FLAGS_PF);
    CHECK_RETHROW(calc_parity_flag_into(ctx, calculation_result, &pf));

cleanup:
    return err;
}

/// calculates the zero flag of the given value into the given result operand.
static err_t calc_zero_flag_into(ctx_t* ctx, const pis_op_t* value, const pis_op_t* result) {
    err_t err = SUCCESS;

    PIS_EMIT(
        &ctx->args->result,
        PIS_INSN3(PIS_OPCODE_EQUALS, *result, *value, PIS_OPERAND_IMM(0, value->size))
    );

cleanup:
    return err;
}

/// calculates the zero flag of the given calculation result into the zero flag register.
static err_t calc_zero_flag(ctx_t* ctx, const pis_op_t* calculation_result) {
    err_t err = SUCCESS;

    pis_op_t zf = pis_reg_to_op(X86_FLAGS_ZF);
    CHECK_RETHROW(calc_zero_flag_into(ctx, calculation_result, &zf));

cleanup:
    return err;
}

/// extracts the most significant bit of the given value into the given result operand.
/// the output is a 1 byte conditional expression which indicates whether the sign bit of the given
/// value is enabled.
static err_t
    extract_most_significant_bit(ctx_t* ctx, const pis_op_t* value, const pis_op_t* result) {
    err_t err = SUCCESS;

    // make sure that the output operand is a 1 byte conditional expression
    CHECK(result->size == PIS_SIZE_1);

    u64 shift_amount = pis_size_to_bits(value->size) - 1;

    pis_op_t tmp = TMP_ALLOC(&ctx->tmp_allocator, value->size);
    PIS_EMIT(
        &ctx->args->result,
        PIS_INSN3(PIS_OPCODE_SHIFT_RIGHT, tmp, *value, PIS_OPERAND_IMM(shift_amount, value->size))
    );

    // resize and write the result into the result operand
    CHECK_RETHROW(write_resize_zext(ctx, result, &tmp));

cleanup:
    return err;
}

/// extracts the least significant bit of the given value into the given result operand.
/// the output is a 1 byte conditional expression which indicates whether the least significant bit
/// of the given value is enabled.
static err_t
    extract_least_significant_bit(ctx_t* ctx, const pis_op_t* value, const pis_op_t* result) {
    err_t err = SUCCESS;

    // make sure that the output operand is a 1 byte conditional expression
    CHECK(result->size == PIS_SIZE_1);

    pis_op_t least_significant_byte = {};
    CHECK_RETHROW(read_resize_zext(ctx, value, PIS_SIZE_1, &least_significant_byte));

    PIS_EMIT(
        &ctx->args->result,
        PIS_INSN3(PIS_OPCODE_AND, *result, least_significant_byte, PIS_OPERAND_IMM(1, PIS_SIZE_1))
    );

cleanup:
    return err;
}

/// calculates the sign flag of the given calculation result into the sign flag register.
static err_t calc_sign_flag(ctx_t* ctx, const pis_op_t* calculation_result) {
    err_t err = SUCCESS;

    pis_op_t sf = pis_reg_to_op(X86_FLAGS_SF);
    CHECK_RETHROW(extract_most_significant_bit(ctx, calculation_result, &sf));

cleanup:
    return err;
}

/// calculates the parity, zero and sign flags according to the given calculation results and stores
/// the flag values into their appropriate flag registers.
static err_t calc_parity_zero_sign_flags(ctx_t* ctx, const pis_op_t* calculation_result) {
    err_t err = SUCCESS;

    CHECK_RETHROW(calc_parity_flag(ctx, calculation_result));
    CHECK_RETHROW(calc_zero_flag(ctx, calculation_result));
    CHECK_RETHROW(calc_sign_flag(ctx, calculation_result));

cleanup:
    return err;
}

static err_t calc_add_carry_flag_value(
    ctx_t* ctx, const pis_op_t* a, const pis_op_t* b, const pis_op_t* result
) {
    err_t err = SUCCESS;
    PIS_EMIT(&ctx->args->result, PIS_INSN3(PIS_OPCODE_UNSIGNED_CARRY, *result, *a, *b));
cleanup:
    return err;
}

static err_t calc_add_overflow_flag_value(
    ctx_t* ctx, const pis_op_t* a, const pis_op_t* b, const pis_op_t* result
) {
    err_t err = SUCCESS;
    PIS_EMIT(&ctx->args->result, PIS_INSN3(PIS_OPCODE_SIGNED_CARRY, *result, *a, *b));
cleanup:
    return err;
}

/// performs an `ADD` operation on the 2 input operands `a` and `b` and returns an operand
/// containing the result of the operation in `result`.
static err_t binop_add(ctx_t* ctx, const pis_op_t* a, const pis_op_t* b, pis_op_t* result) {
    err_t err = SUCCESS;

    CHECK(a->size == b->size);
    pis_size_t operand_size = a->size;

    pis_op_t res_tmp = TMP_ALLOC(&ctx->tmp_allocator, operand_size);

    // carry flag
    pis_op_t cf = pis_reg_to_op(X86_FLAGS_CF);
    CHECK_RETHROW(calc_add_carry_flag_value(ctx, a, b, &cf));

    // overflow flag
    pis_op_t of = pis_reg_to_op(X86_FLAGS_OF);
    CHECK_RETHROW(calc_add_overflow_flag_value(ctx, a, b, &of));

    // perform the actual addition
    PIS_EMIT(&ctx->args->result, PIS_INSN3(PIS_OPCODE_ADD, res_tmp, *a, *b));

    CHECK_RETHROW(calc_parity_zero_sign_flags(ctx, &res_tmp));

    *result = res_tmp;

cleanup:
    return err;
}

/// a generic implementation of a binary operator which also uses the carry flag. can be used to
/// implement both `ADC` and `SBB`
static err_t impl_binop_with_carry(
    ctx_t* ctx,
    const pis_op_t* a,
    const pis_op_t* b,
    pis_op_t* result,
    pis_opcode_t binop_opcode,
    binop_calc_flag_fn_t calc_carry_fn,
    binop_calc_flag_fn_t calc_overflow_fn
) {
    err_t err = SUCCESS;

    CHECK(a->size == b->size);
    pis_size_t operand_size = a->size;

    pis_op_t orig_cf_zext = {};
    pis_op_t cf = pis_reg_to_op(X86_FLAGS_CF);
    CHECK_RETHROW(read_resize_zext(ctx, &cf, operand_size, &orig_cf_zext));

    pis_op_t a_and_b = TMP_ALLOC(&ctx->tmp_allocator, operand_size);
    PIS_EMIT(&ctx->args->result, PIS_INSN3(binop_opcode, a_and_b, *a, *b));

    // carry flag
    pis_op_t carry_first_cond = TMP_ALLOC(&ctx->tmp_allocator, PIS_SIZE_1);
    CHECK_RETHROW(calc_carry_fn(ctx, a, b, &carry_first_cond));

    pis_op_t carry_second_cond = TMP_ALLOC(&ctx->tmp_allocator, PIS_SIZE_1);
    CHECK_RETHROW(calc_carry_fn(ctx, &a_and_b, &orig_cf_zext, &carry_second_cond));

    PIS_EMIT(
        &ctx->args->result,
        PIS_INSN3(PIS_OPCODE_OR, pis_reg_to_op(X86_FLAGS_CF), carry_first_cond, carry_second_cond)
    );

    // overflow flag
    pis_op_t overflow_first_cond = TMP_ALLOC(&ctx->tmp_allocator, PIS_SIZE_1);
    CHECK_RETHROW(calc_overflow_fn(ctx, a, b, &overflow_first_cond));

    pis_op_t overflow_second_cond = TMP_ALLOC(&ctx->tmp_allocator, PIS_SIZE_1);
    CHECK_RETHROW(calc_overflow_fn(ctx, &a_and_b, &orig_cf_zext, &overflow_second_cond));

    PIS_EMIT(
        &ctx->args->result,
        PIS_INSN3(
            PIS_OPCODE_OR,
            pis_reg_to_op(X86_FLAGS_OF),
            overflow_first_cond,
            overflow_second_cond
        )
    );

    // perform the actual binop
    pis_op_t res_tmp = TMP_ALLOC(&ctx->tmp_allocator, operand_size);
    PIS_EMIT(&ctx->args->result, PIS_INSN3(binop_opcode, res_tmp, a_and_b, orig_cf_zext));

    CHECK_RETHROW(calc_parity_zero_sign_flags(ctx, &res_tmp));

    *result = res_tmp;

cleanup:
    return err;
}

/// performs an `ADC` operation on the 2 input operands `a` and `b` and returns an operand
/// containing the result of the operation in `result`.
static err_t binop_adc(ctx_t* ctx, const pis_op_t* a, const pis_op_t* b, pis_op_t* result) {
    err_t err = SUCCESS;

    CHECK_RETHROW(impl_binop_with_carry(
        ctx,
        a,
        b,
        result,
        PIS_OPCODE_ADD,
        calc_add_carry_flag_value,
        calc_add_overflow_flag_value
    ));

cleanup:
    return err;
}

static err_t calc_sub_carry_flag_value(
    ctx_t* ctx, const pis_op_t* a, const pis_op_t* b, const pis_op_t* result
) {
    err_t err = SUCCESS;
    PIS_EMIT(&ctx->args->result, PIS_INSN3(PIS_OPCODE_UNSIGNED_LESS_THAN, *result, *a, *b));
cleanup:
    return err;
}

/// calculates the value of the overflow flag for a subtraction operation `a - b`.
static err_t calc_sub_overflow_flag_value(
    ctx_t* ctx, const pis_op_t* a, const pis_op_t* b, const pis_op_t* result
) {
    err_t err = SUCCESS;

    CHECK(a->size == b->size);

    // first calculate the subtraction result
    pis_op_t res_tmp = TMP_ALLOC(&ctx->tmp_allocator, a->size);
    PIS_EMIT(&ctx->args->result, PIS_INSN3(PIS_OPCODE_SUB, res_tmp, *a, *b));

    // calculate the sign bit of the subtraction result
    pis_op_t res_sign_bit = TMP_ALLOC(&ctx->tmp_allocator, PIS_SIZE_1);
    CHECK_RETHROW(extract_most_significant_bit(ctx, &res_tmp, &res_sign_bit));

    // check if `a` is less than `b`
    pis_op_t signed_less_than = TMP_ALLOC(&ctx->tmp_allocator, PIS_SIZE_1);
    PIS_EMIT(&ctx->args->result, PIS_INSN3(PIS_OPCODE_SIGNED_LESS_THAN, signed_less_than, *a, *b));

    // the overflow can be calculated by xoring the less than condition with the sign bit.
    //
    // this is because, if the less than condition is 1, it means that `a < b`, in which case we
    // expect the result to be negative, and if it is not then it is an overflow. so, if less than
    // is 1 and sign is 0, it is an overflow.
    //
    // additionally, if the less than condition is 0, it means that `a >= b`, in which case we
    // expect the result to be positive, and if it is not then it is an overflow. so, if less than
    // is 0 and sign is 1, it is an overflow.
    //
    // both of those cases can be detected by just xoring these values together.
    PIS_EMIT(
        &ctx->args->result,
        PIS_INSN3(PIS_OPCODE_XOR, *result, signed_less_than, res_sign_bit)
    );
cleanup:
    return err;
}

/// performs an `SBB` operation on the 2 input operands `a` and `b` and returns an operand
/// containing the result of the operation in `result`.
static err_t binop_sbb(ctx_t* ctx, const pis_op_t* a, const pis_op_t* b, pis_op_t* result) {
    err_t err = SUCCESS;

    CHECK_RETHROW(impl_binop_with_carry(
        ctx,
        a,
        b,
        result,
        PIS_OPCODE_SUB,
        calc_sub_carry_flag_value,
        calc_add_overflow_flag_value
    ));

cleanup:
    return err;
}

/// performs an `SUB` operation on the 2 input operands `a` and `b` and returns an operand
/// containing the result of the operation in `result`.
static err_t binop_sub(ctx_t* ctx, const pis_op_t* a, const pis_op_t* b, pis_op_t* result) {
    err_t err = SUCCESS;

    CHECK(a->size == b->size);
    pis_size_t operand_size = a->size;

    pis_op_t res_tmp = TMP_ALLOC(&ctx->tmp_allocator, operand_size);

    // carry flag
    pis_op_t cf = pis_reg_to_op(X86_FLAGS_CF);
    CHECK_RETHROW(calc_sub_carry_flag_value(ctx, a, b, &cf));

    // overflow flag
    pis_op_t of = pis_reg_to_op(X86_FLAGS_OF);
    CHECK_RETHROW(calc_sub_overflow_flag_value(ctx, a, b, &of));

    // perform the actual subtraction
    PIS_EMIT(&ctx->args->result, PIS_INSN3(PIS_OPCODE_SUB, res_tmp, *a, *b));

    CHECK_RETHROW(calc_parity_zero_sign_flags(ctx, &res_tmp));

    *result = res_tmp;

cleanup:
    return err;
}

/// performs a `DEC` operation on the input operand and returns an operand
/// containing the result of the operation in `result`.
static err_t unary_op_dec(ctx_t* ctx, const pis_op_t* operand, pis_op_t* result) {
    err_t err = SUCCESS;

    pis_size_t operand_size = operand->size;

    pis_op_t one = PIS_OPERAND_IMM(1, operand_size);

    // overflow flag
    pis_op_t of = pis_reg_to_op(X86_FLAGS_OF);
    CHECK_RETHROW(calc_sub_overflow_flag_value(ctx, operand, &one, &of));

    // perform the actual subtraction
    pis_op_t res_tmp = TMP_ALLOC(&ctx->tmp_allocator, operand_size);
    PIS_EMIT(&ctx->args->result, PIS_INSN3(PIS_OPCODE_SUB, res_tmp, *operand, one));

    CHECK_RETHROW(calc_parity_zero_sign_flags(ctx, &res_tmp));

    *result = res_tmp;

cleanup:
    return err;
}

/// performs an `INC` operation on the input operand and returns an operand
/// containing the result of the operation in `result`.
static err_t unary_op_inc(ctx_t* ctx, const pis_op_t* operand, pis_op_t* result) {
    err_t err = SUCCESS;

    pis_size_t operand_size = operand->size;

    pis_op_t one = PIS_OPERAND_IMM(1, operand_size);

    // overflow flag
    PIS_EMIT(
        &ctx->args->result,
        PIS_INSN3(PIS_OPCODE_SIGNED_CARRY, pis_reg_to_op(X86_FLAGS_OF), *operand, one)
    );

    // perform the actual subtraction
    pis_op_t res_tmp = TMP_ALLOC(&ctx->tmp_allocator, operand_size);
    PIS_EMIT(&ctx->args->result, PIS_INSN3(PIS_OPCODE_ADD, res_tmp, *operand, one));

    CHECK_RETHROW(calc_parity_zero_sign_flags(ctx, &res_tmp));

    *result = res_tmp;

cleanup:
    return err;
}

/// performs a `NEG` operation on the input operand and returns an operand
/// containing the result of the operation in `result`.
static err_t unary_op_neg(ctx_t* ctx, const pis_op_t* operand, pis_op_t* result) {
    err_t err = SUCCESS;

    pis_size_t operand_size = operand->size;

    pis_op_t zero = PIS_OPERAND_IMM(0, operand_size);

    // carry flag
    pis_op_t equals_zero = TMP_ALLOC(&ctx->tmp_allocator, PIS_SIZE_1);
    PIS_EMIT(&ctx->args->result, PIS_INSN3(PIS_OPCODE_EQUALS, equals_zero, *operand, zero));
    PIS_EMIT(
        &ctx->args->result,
        PIS_INSN2(PIS_OPCODE_COND_NEGATE, pis_reg_to_op(X86_FLAGS_CF), equals_zero)
    );

    // perform the actual negation
    pis_op_t res_tmp = TMP_ALLOC(&ctx->tmp_allocator, operand_size);
    PIS_EMIT(&ctx->args->result, PIS_INSN2(PIS_OPCODE_NEG, res_tmp, *operand));

    CHECK_RETHROW(calc_parity_zero_sign_flags(ctx, &res_tmp));

    *result = res_tmp;

cleanup:
    return err;
}

/// performs a `NOT` operation on the input operand and returns an operand
/// containing the result of the operation in `result`.
static err_t unary_op_not(ctx_t* ctx, const pis_op_t* operand, pis_op_t* result) {
    err_t err = SUCCESS;

    pis_size_t operand_size = operand->size;

    // perform the actual not operation
    pis_op_t res_tmp = TMP_ALLOC(&ctx->tmp_allocator, operand_size);
    PIS_EMIT(&ctx->args->result, PIS_INSN2(PIS_OPCODE_NOT, res_tmp, *operand));

    *result = res_tmp;

cleanup:
    return err;
}

/// performs an `AND` operation on the 2 input operands `a` and `b` and returns an operand
/// containing the result of the operation in `result`.
static err_t binop_and(ctx_t* ctx, const pis_op_t* a, const pis_op_t* b, pis_op_t* result) {
    err_t err = SUCCESS;

    CHECK(a->size == b->size);
    pis_size_t operand_size = a->size;

    pis_op_t res_tmp = TMP_ALLOC(&ctx->tmp_allocator, operand_size);

    // set CF and OF to zero
    PIS_EMIT(
        &ctx->args->result,
        PIS_INSN2(PIS_OPCODE_MOVE, pis_reg_to_op(X86_FLAGS_CF), PIS_OPERAND_IMM(0, PIS_SIZE_1))
    );
    PIS_EMIT(
        &ctx->args->result,
        PIS_INSN2(PIS_OPCODE_MOVE, pis_reg_to_op(X86_FLAGS_OF), PIS_OPERAND_IMM(0, PIS_SIZE_1))
    );

    // perform the actual bitwide and operation
    PIS_EMIT(&ctx->args->result, PIS_INSN3(PIS_OPCODE_AND, res_tmp, *a, *b));

    CHECK_RETHROW(calc_parity_zero_sign_flags(ctx, &res_tmp));

    *result = res_tmp;

cleanup:
    return err;
}

/// performs an `IMUL` operation on the 2 input operands `a` and `b` and returns an operand
/// containing the result of the operation in `result`.
static err_t binop_imul(ctx_t* ctx, const pis_op_t* a, const pis_op_t* b, pis_op_t* result) {
    err_t err = SUCCESS;

    CHECK(a->size == b->size);
    pis_size_t operand_size = a->size;

    // update CF
    PIS_EMIT(
        &ctx->args->result,
        PIS_INSN3(PIS_OPCODE_SIGNED_MUL_OVERFLOW, pis_reg_to_op(X86_FLAGS_CF), *a, *b)
    );

    // update OF
    PIS_EMIT(
        &ctx->args->result,
        PIS_INSN2(PIS_OPCODE_MOVE, pis_reg_to_op(X86_FLAGS_OF), pis_reg_to_op(X86_FLAGS_CF))
    );

    // perform the actual multiplication
    pis_op_t res_tmp = TMP_ALLOC(&ctx->tmp_allocator, operand_size);
    PIS_EMIT(&ctx->args->result, PIS_INSN3(PIS_OPCODE_SIGNED_MUL, res_tmp, *a, *b));

    *result = res_tmp;

cleanup:
    return err;
}

/// performs a `XOR` operation on the 2 input operands `a` and `b` and returns an operand
/// containing the result of the operation in `result`.
static err_t binop_xor(ctx_t* ctx, const pis_op_t* a, const pis_op_t* b, pis_op_t* result) {
    err_t err = SUCCESS;

    CHECK(a->size == b->size);
    pis_size_t operand_size = a->size;

    pis_op_t res_tmp = TMP_ALLOC(&ctx->tmp_allocator, operand_size);

    // carry flag
    PIS_EMIT(
        &ctx->args->result,
        PIS_INSN2(PIS_OPCODE_MOVE, pis_reg_to_op(X86_FLAGS_CF), PIS_OPERAND_IMM(0, PIS_SIZE_1))
    );

    // overflow flag
    PIS_EMIT(
        &ctx->args->result,
        PIS_INSN2(PIS_OPCODE_MOVE, pis_reg_to_op(X86_FLAGS_OF), PIS_OPERAND_IMM(0, PIS_SIZE_1))
    );

    // perform the actual xor operation
    PIS_EMIT(&ctx->args->result, PIS_INSN3(PIS_OPCODE_XOR, res_tmp, *a, *b));

    CHECK_RETHROW(calc_parity_zero_sign_flags(ctx, &res_tmp));

    *result = res_tmp;

cleanup:
    return err;
}

/// performs an `OR` operation on the 2 input operands `a` and `b` and returns an operand
/// containing the result of the operation in `result`.
static err_t binop_or(ctx_t* ctx, const pis_op_t* a, const pis_op_t* b, pis_op_t* result) {
    err_t err = SUCCESS;

    CHECK(a->size == b->size);
    pis_size_t operand_size = a->size;

    pis_op_t res_tmp = TMP_ALLOC(&ctx->tmp_allocator, operand_size);

    // carry flag
    PIS_EMIT(
        &ctx->args->result,
        PIS_INSN2(PIS_OPCODE_MOVE, pis_reg_to_op(X86_FLAGS_CF), PIS_OPERAND_IMM(0, PIS_SIZE_1))
    );

    // overflow flag
    PIS_EMIT(
        &ctx->args->result,
        PIS_INSN2(PIS_OPCODE_MOVE, pis_reg_to_op(X86_FLAGS_OF), PIS_OPERAND_IMM(0, PIS_SIZE_1))
    );

    // perform the actual or operation
    PIS_EMIT(&ctx->args->result, PIS_INSN3(PIS_OPCODE_OR, res_tmp, *a, *b));

    CHECK_RETHROW(calc_parity_zero_sign_flags(ctx, &res_tmp));

    *result = res_tmp;

cleanup:
    return err;
}

/// the default operand size for near branches.
///
/// please not that the operand size is not the size of the displacement immediate. for example, for
/// an operand size of 8, the displacement is 4 bytes.
static pis_size_t near_branch_operand_default_operand_size(ctx_t* ctx) {
    if (ctx->cpumode == PIS_X86_CPUMODE_64_BIT) {
        // from the intel ia-32 spec:
        // "In 64-bit mode the target operand will always be 64-bits because the operand size is
        // forced to 64-bits for near branches"
        return PIS_SIZE_8;
    } else {
        return get_effective_operand_size(ctx->cpumode, &ctx->prefixes, false);
    }
}

/// the instruction points size of a relative jump using a 16/32 bit displacement.
static pis_size_t rel_jmp_ip_operand_size(ctx_t* ctx) {
    return near_branch_operand_default_operand_size(ctx);
}

/// masks the ip value which is the result of performing a relative jump with a 16/32 bit
/// displacement.
static u64 rel_jmp_mask_ip_value(ctx_t* ctx, u64 ip_value) {
    pis_size_t ip_operand_size = rel_jmp_ip_operand_size(ctx);
    u64 mask = pis_size_max_unsigned_value(ip_operand_size);
    return ip_value & mask;
}

/// generates a ternary expression.
static err_t ternary(
    ctx_t* ctx,
    const pis_op_t* cond,
    const pis_op_t* then_value,
    const pis_op_t* else_value,
    const pis_op_t* result
) {
    err_t err = SUCCESS;

    CHECK(cond->size == PIS_SIZE_1);
    CHECK(then_value->size == else_value->size);
    CHECK(then_value->size == result->size);

    pis_size_t operand_size = then_value->size;
    CHECK(operand_size > PIS_SIZE_1);

    // zero extend the condition
    pis_op_t cond_zero_extended = {};
    CHECK_RETHROW(read_resize_zext(ctx, cond, operand_size, &cond_zero_extended));

    // arithmetically negate the condition to convert it to a bit mask.
    // if the condition is 1, negating it will produce an all 1s mask, and if it is zero, it will
    // produce an all 0s mask.
    pis_op_t cond_mask = TMP_ALLOC(&ctx->tmp_allocator, operand_size);
    PIS_EMIT(&ctx->args->result, PIS_INSN2(PIS_OPCODE_NEG, cond_mask, cond_zero_extended));

    // calculate the negative condition mask
    pis_op_t not_cond_mask = TMP_ALLOC(&ctx->tmp_allocator, operand_size);
    PIS_EMIT(&ctx->args->result, PIS_INSN2(PIS_OPCODE_NOT, not_cond_mask, cond_mask));

    pis_op_t true_case = TMP_ALLOC(&ctx->tmp_allocator, operand_size);
    PIS_EMIT(&ctx->args->result, PIS_INSN3(PIS_OPCODE_AND, true_case, cond_mask, *then_value));

    pis_op_t false_case = TMP_ALLOC(&ctx->tmp_allocator, operand_size);
    PIS_EMIT(&ctx->args->result, PIS_INSN3(PIS_OPCODE_AND, false_case, not_cond_mask, *else_value));

    PIS_EMIT(&ctx->args->result, PIS_INSN3(PIS_OPCODE_OR, *result, true_case, false_case));

cleanup:
    return err;
}

/// extracts the register encoding of an opcode which has a register encoded in its value.
/// this also takes into account the `B` bit of the rex prefix of the instruction.
static u8 opcode_reg_extract(ctx_t* ctx, u8 opcode_byte) {
    return apply_rex_bit_to_reg_encoding(opcode_byte & 0b111, ctx->prefixes.rex.b);
}

/// pushes the given operand to the stack.
static err_t push(ctx_t* ctx, const pis_op_t* operand_to_push) {
    err_t err = SUCCESS;

    pis_op_t sp = ctx->sp;
    u64 operand_size_bytes = pis_size_to_bytes(operand_to_push->size);

    // read the pushed operand into a tmp before subtracting sp. this makes sure that instructions
    // like `push rsp` behave properly, by pushing the original value, before the subtraction.
    pis_op_t tmp = TMP_ALLOC(&ctx->tmp_allocator, operand_to_push->size);
    PIS_EMIT(&ctx->args->result, PIS_INSN2(PIS_OPCODE_MOVE, tmp, *operand_to_push));

    // subtract sp
    PIS_EMIT(
        &ctx->args->result,
        PIS_INSN3(PIS_OPCODE_ADD, sp, sp, PIS_OPERAND_IMM_NEG(operand_size_bytes, sp.size))
    );

    // write the memory
    PIS_EMIT(&ctx->args->result, PIS_INSN2(PIS_OPCODE_STORE, sp, tmp));
cleanup:
    return err;
}

/// generates a ternary expression with conditional expressions.
static err_t cond_expr_ternary(
    ctx_t* ctx,
    const pis_op_t* cond,
    const pis_op_t* then_value,
    const pis_op_t* else_value,
    const pis_op_t* result
) {
    err_t err = SUCCESS;

    // make sure that all operands are one byte conditional expressions.
    CHECK(cond->size == PIS_SIZE_1);
    CHECK(then_value->size == PIS_SIZE_1);
    CHECK(else_value->size == PIS_SIZE_1);

    pis_op_t not_cond = TMP_ALLOC(&ctx->tmp_allocator, PIS_SIZE_1);
    PIS_EMIT(&ctx->args->result, PIS_INSN2(PIS_OPCODE_COND_NEGATE, not_cond, *cond));

    pis_op_t true_case = TMP_ALLOC(&ctx->tmp_allocator, PIS_SIZE_1);
    PIS_EMIT(&ctx->args->result, PIS_INSN3(PIS_OPCODE_AND, true_case, *cond, *then_value));

    pis_op_t false_case = TMP_ALLOC(&ctx->tmp_allocator, PIS_SIZE_1);
    PIS_EMIT(&ctx->args->result, PIS_INSN3(PIS_OPCODE_AND, false_case, not_cond, *else_value));

    PIS_EMIT(&ctx->args->result, PIS_INSN3(PIS_OPCODE_OR, *result, true_case, false_case));

cleanup:
    return err;
}

/// calculates the carry flag of a `SHL` operation. `to_shift` is the value to be shifted, `count`
/// is the masked shift count.
static err_t shl_calc_carry_flag(ctx_t* ctx, const pis_op_t* to_shift, const pis_op_t* count) {
    err_t err = SUCCESS;

    CHECK(count->size == to_shift->size);

    pis_size_t operand_size = to_shift->size;

    // to get the last shifted out bit, shift the original value `size - count` bits to the right.
    pis_op_t right_shift_count = TMP_ALLOC(&ctx->tmp_allocator, operand_size);
    PIS_EMIT(
        &ctx->args->result,
        PIS_INSN3(
            PIS_OPCODE_SUB,
            right_shift_count,
            PIS_OPERAND_IMM(pis_size_to_bits(operand_size), operand_size),
            *count
        )
    );
    pis_op_t right_shifted = TMP_ALLOC(&ctx->tmp_allocator, operand_size);
    PIS_EMIT(
        &ctx->args->result,
        PIS_INSN3(PIS_OPCODE_SHIFT_RIGHT, right_shifted, *to_shift, right_shift_count)
    );
    pis_op_t last_extracted_bit = {};
    CHECK_RETHROW(read_resize_zext(ctx, &right_shifted, PIS_SIZE_1, &last_extracted_bit));

    // now, we only want to set the carry flag if the count is non-zero, otherwise we want to use
    // the original CF value.
    pis_op_t is_count_0 = TMP_ALLOC(&ctx->tmp_allocator, PIS_SIZE_1);
    PIS_EMIT(
        &ctx->args->result,
        PIS_INSN3(PIS_OPCODE_EQUALS, is_count_0, *count, PIS_OPERAND_IMM(0, operand_size))
    );

    pis_op_t cf = pis_reg_to_op(X86_FLAGS_CF);
    CHECK_RETHROW(cond_expr_ternary(ctx, &is_count_0, &cf, &last_extracted_bit, &cf));

cleanup:
    return err;
}

/// calculates the carry flag of a `SHR` operation. `to_shift` is the value to be shifted, `count`
/// is the masked shift count.
static err_t shr_calc_carry_flag(ctx_t* ctx, const pis_op_t* to_shift, const pis_op_t* count) {
    err_t err = SUCCESS;

    CHECK(count->size == to_shift->size);

    pis_size_t operand_size = to_shift->size;

    // to get the last shifted out but, shift the original value `count - 1` bits, and then extract
    // its least significant bit.
    pis_op_t count_minus_1 = TMP_ALLOC(&ctx->tmp_allocator, operand_size);
    PIS_EMIT(
        &ctx->args->result,
        PIS_INSN3(PIS_OPCODE_SUB, count_minus_1, *count, PIS_OPERAND_IMM(1, operand_size))
    );
    pis_op_t shifted_by_count_minus_1 = TMP_ALLOC(&ctx->tmp_allocator, operand_size);
    PIS_EMIT(
        &ctx->args->result,
        PIS_INSN3(PIS_OPCODE_SHIFT_RIGHT, shifted_by_count_minus_1, *to_shift, count_minus_1)
    );
    pis_op_t last_extracted_bit = TMP_ALLOC(&ctx->tmp_allocator, PIS_SIZE_1);
    CHECK_RETHROW(extract_least_significant_bit(ctx, &shifted_by_count_minus_1, &last_extracted_bit)
    );

    // now, we only want to set the carry flag if the count is non-zero, otherwise we want to use
    // the original CF value.
    pis_op_t is_count_0 = TMP_ALLOC(&ctx->tmp_allocator, PIS_SIZE_1);
    PIS_EMIT(
        &ctx->args->result,
        PIS_INSN3(PIS_OPCODE_EQUALS, is_count_0, *count, PIS_OPERAND_IMM(0, operand_size))
    );

    pis_op_t cf = pis_reg_to_op(X86_FLAGS_CF);
    CHECK_RETHROW(cond_expr_ternary(ctx, &is_count_0, &cf, &last_extracted_bit, &cf));

cleanup:
    return err;
}

/// calculates the overflow flag of a `SHL` operation. `to_shift` is the value to be shifted,
/// `count` is the masked shift count.
/// this must be called after calculating the `CF` flag accordingly, since its calculation relies on
/// the `CF` value.
static err_t shl_calc_overflow_flag(
    ctx_t* ctx, const pis_op_t* to_shift, const pis_op_t* count, const pis_op_t* shift_result
) {
    err_t err = SUCCESS;

    CHECK(count->size == to_shift->size);

    pis_size_t operand_size = to_shift->size;

    // the overflow flag is set to `MSB(shift_result) ^ CF`
    pis_op_t msb = TMP_ALLOC(&ctx->tmp_allocator, PIS_SIZE_1);
    CHECK_RETHROW(extract_most_significant_bit(ctx, shift_result, &msb));

    pis_op_t new_overflow_flag_value = TMP_ALLOC(&ctx->tmp_allocator, PIS_SIZE_1);
    PIS_EMIT(
        &ctx->args->result,
        PIS_INSN3(PIS_OPCODE_XOR, new_overflow_flag_value, msb, pis_reg_to_op(X86_FLAGS_CF))
    );

    // we only want to set the overflow flag if the count is 1, otherwise we want to use
    // the original OF value.
    pis_op_t is_count_1 = TMP_ALLOC(&ctx->tmp_allocator, PIS_SIZE_1);
    PIS_EMIT(
        &ctx->args->result,
        PIS_INSN3(PIS_OPCODE_EQUALS, is_count_1, *count, PIS_OPERAND_IMM(1, operand_size))
    );

    pis_op_t of = pis_reg_to_op(X86_FLAGS_OF);
    CHECK_RETHROW(cond_expr_ternary(ctx, &is_count_1, &new_overflow_flag_value, &of, &of));

cleanup:
    return err;
}

/// calculates the overflow flag of a `SHLD` operation. `to_shift` is the value to be shifted,
/// `count` is the masked shift count.
static err_t shld_calc_overflow_flag(ctx_t* ctx, const pis_op_t* to_shift, const pis_op_t* count) {
    err_t err = SUCCESS;

    CHECK(count->size == to_shift->size);

    pis_size_t operand_size = to_shift->size;

    // the overflow flag is set to `MSB(dst << src) ^ MSB(dst)`
    pis_op_t shifted = TMP_ALLOC(&ctx->tmp_allocator, operand_size);
    PIS_EMIT(&ctx->args->result, PIS_INSN3(PIS_OPCODE_SHIFT_LEFT, shifted, *to_shift, *count));

    pis_op_t new_msb = TMP_ALLOC(&ctx->tmp_allocator, PIS_SIZE_1);
    CHECK_RETHROW(extract_most_significant_bit(ctx, &shifted, &new_msb));

    pis_op_t old_msb = TMP_ALLOC(&ctx->tmp_allocator, PIS_SIZE_1);
    CHECK_RETHROW(extract_most_significant_bit(ctx, to_shift, &old_msb));

    pis_op_t new_overflow_flag_value = TMP_ALLOC(&ctx->tmp_allocator, PIS_SIZE_1);
    PIS_EMIT(
        &ctx->args->result,
        PIS_INSN3(PIS_OPCODE_XOR, new_overflow_flag_value, new_msb, old_msb)
    );

    // we only want to set the overflow flag if the count is 1, otherwise we want to use
    // the original OF value.
    pis_op_t is_count_1 = TMP_ALLOC(&ctx->tmp_allocator, PIS_SIZE_1);
    PIS_EMIT(
        &ctx->args->result,
        PIS_INSN3(PIS_OPCODE_EQUALS, is_count_1, *count, PIS_OPERAND_IMM(1, operand_size))
    );

    pis_op_t of = pis_reg_to_op(X86_FLAGS_OF);
    CHECK_RETHROW(cond_expr_ternary(ctx, &is_count_1, &new_overflow_flag_value, &of, &of));

cleanup:
    return err;
}

/// calculates the parity zero and sign flags of a shift operation, and stores the results in the
/// appropriate flag registers. `count` is the masked shift count, and `shift_result` is the shifted
/// value.
static err_t shift_calc_parity_zero_sign_flags(
    ctx_t* ctx, const pis_op_t* count, const pis_op_t* shift_result
) {
    err_t err = SUCCESS;

    CHECK(count->size == shift_result->size);
    pis_size_t operand_size = shift_result->size;

    // only modify the flags if the count is non-zero
    pis_op_t is_count_0 = TMP_ALLOC(&ctx->tmp_allocator, PIS_SIZE_1);
    PIS_EMIT(
        &ctx->args->result,
        PIS_INSN3(PIS_OPCODE_EQUALS, is_count_0, *count, PIS_OPERAND_IMM(0, operand_size))
    );

    pis_op_t new_pf = TMP_ALLOC(&ctx->tmp_allocator, PIS_SIZE_1);
    CHECK_RETHROW(calc_parity_flag_into(ctx, shift_result, &new_pf));
    pis_op_t pf = pis_reg_to_op(X86_FLAGS_PF);
    CHECK_RETHROW(cond_expr_ternary(ctx, &is_count_0, &pf, &new_pf, &pf));

    pis_op_t new_zf = TMP_ALLOC(&ctx->tmp_allocator, PIS_SIZE_1);
    CHECK_RETHROW(calc_zero_flag_into(ctx, shift_result, &new_zf));
    pis_op_t zf = pis_reg_to_op(X86_FLAGS_ZF);
    CHECK_RETHROW(cond_expr_ternary(ctx, &is_count_0, &zf, &new_zf, &zf));

    pis_op_t new_sf = TMP_ALLOC(&ctx->tmp_allocator, PIS_SIZE_1);
    CHECK_RETHROW(extract_most_significant_bit(ctx, shift_result, &new_sf));
    pis_op_t sf = pis_reg_to_op(X86_FLAGS_SF);
    CHECK_RETHROW(cond_expr_ternary(ctx, &is_count_0, &sf, &new_sf, &sf));

cleanup:
    return err;
}

/// masks the `count` operand of a shift operation. in x86, the `count` operand of shift operations
/// is always first masked before being applied.
static err_t mask_shift_count(
    ctx_t* ctx, const pis_op_t* count, const pis_op_t* masked_count, pis_size_t operand_size
) {
    err_t err = SUCCESS;

    u64 count_mask = operand_size == PIS_SIZE_8 ? 0b111111 : 0b11111;
    PIS_EMIT(
        &ctx->args->result,
        PIS_INSN3(PIS_OPCODE_AND, *masked_count, *count, PIS_OPERAND_IMM(count_mask, operand_size))
    );
cleanup:
    return err;
}

/// performs a `SHL` operation on the 2 input operands `a` and `b` and returns an operand
/// containing the result of the operation in `result`.
static err_t binop_shl(ctx_t* ctx, const pis_op_t* a, const pis_op_t* b, pis_op_t* result) {
    err_t err = SUCCESS;

    CHECK(a->size == b->size);
    pis_size_t operand_size = a->size;

    pis_op_t count = TMP_ALLOC(&ctx->tmp_allocator, operand_size);
    CHECK_RETHROW(mask_shift_count(ctx, b, &count, operand_size));

    // carry flag
    CHECK_RETHROW(shl_calc_carry_flag(ctx, a, &count));

    // perform the actual shift
    pis_op_t res_tmp = TMP_ALLOC(&ctx->tmp_allocator, operand_size);
    PIS_EMIT(&ctx->args->result, PIS_INSN3(PIS_OPCODE_SHIFT_LEFT, res_tmp, *a, count));

    // overflow flag
    CHECK_RETHROW(shl_calc_overflow_flag(ctx, a, &count, &res_tmp));

    CHECK_RETHROW(shift_calc_parity_zero_sign_flags(ctx, &count, &res_tmp));

    *result = res_tmp;

cleanup:
    return err;
}

/// performs a `SHLD` operation.
static err_t do_shld(
    ctx_t* ctx,
    const pis_op_t* dst,
    const pis_op_t* src,
    const pis_op_t* count_operand,
    pis_op_t* result
) {
    err_t err = SUCCESS;

    CHECK(dst->size == src->size);
    pis_size_t operand_size = dst->size;

    pis_op_t res_tmp = TMP_ALLOC(&ctx->tmp_allocator, operand_size);

    pis_op_t count = TMP_ALLOC(&ctx->tmp_allocator, operand_size);
    CHECK_RETHROW(mask_shift_count(ctx, count_operand, &count, operand_size));

    // carry flag
    CHECK_RETHROW(shl_calc_carry_flag(ctx, dst, &count));

    // overflow flag
    CHECK_RETHROW(shld_calc_overflow_flag(ctx, dst, &count));

    // perform the actual shift
    PIS_EMIT(&ctx->args->result, PIS_INSN3(PIS_OPCODE_SHIFT_LEFT, res_tmp, *dst, count));

    // copy the bits shifted in from the src operand.
    // to do that, we shift the src operand `size - count` bits, and then OR the result into the
    // result.
    pis_op_t src_shift_count = TMP_ALLOC(&ctx->tmp_allocator, operand_size);
    PIS_EMIT(
        &ctx->args->result,
        PIS_INSN3(
            PIS_OPCODE_SUB,
            src_shift_count,
            PIS_OPERAND_IMM(pis_size_to_bytes(operand_size), operand_size),
            count
        )
    );

    pis_op_t shifted_src = TMP_ALLOC(&ctx->tmp_allocator, operand_size);
    PIS_EMIT(
        &ctx->args->result,
        PIS_INSN3(PIS_OPCODE_SHIFT_RIGHT, shifted_src, *src, src_shift_count)
    );

    PIS_EMIT(&ctx->args->result, PIS_INSN3(PIS_OPCODE_OR, res_tmp, res_tmp, shifted_src));

    CHECK_RETHROW(shift_calc_parity_zero_sign_flags(ctx, &count, &res_tmp));

    *result = res_tmp;

cleanup:
    return err;
}


/// calculates the overflow flag of a `SHRD` operation. `to_shift` is the value to be shifted,
/// `count` is the masked shift count, `shifted` is the result of this `SHRD` operation.
static err_t shrd_calc_overflow_flag(
    ctx_t* ctx, const pis_op_t* to_shift, const pis_op_t* count, const pis_op_t* shifted
) {
    err_t err = SUCCESS;

    CHECK(shifted->size == to_shift->size);
    CHECK(count->size == to_shift->size);

    pis_size_t operand_size = to_shift->size;

    // the overflow flag is set if the sign bit changed

    pis_op_t orig_msb = TMP_ALLOC(&ctx->tmp_allocator, PIS_SIZE_1);
    CHECK_RETHROW(extract_most_significant_bit(ctx, to_shift, &orig_msb));

    pis_op_t new_msb = TMP_ALLOC(&ctx->tmp_allocator, PIS_SIZE_1);
    CHECK_RETHROW(extract_most_significant_bit(ctx, shifted, &new_msb));

    pis_op_t new_overflow_flag = TMP_ALLOC(&ctx->tmp_allocator, PIS_SIZE_1);
    PIS_EMIT(&ctx->args->result, PIS_INSN3(PIS_OPCODE_XOR, new_overflow_flag, orig_msb, new_msb));

    // we only want to set the overflow flag if the count is 1, otherwise we want to use
    // the original OF value.
    pis_op_t is_count_1 = TMP_ALLOC(&ctx->tmp_allocator, PIS_SIZE_1);
    PIS_EMIT(
        &ctx->args->result,
        PIS_INSN3(PIS_OPCODE_EQUALS, is_count_1, *count, PIS_OPERAND_IMM(1, operand_size))
    );

    pis_op_t of = pis_reg_to_op(X86_FLAGS_OF);
    CHECK_RETHROW(cond_expr_ternary(ctx, &is_count_1, &new_overflow_flag, &of, &of));

cleanup:
    return err;
}

static err_t do_shrd(
    ctx_t* ctx,
    const pis_op_t* dst,
    const pis_op_t* src,
    const pis_op_t* count_operand,
    pis_op_t* result
) {
    err_t err = SUCCESS;

    CHECK(dst->size == src->size);
    pis_size_t operand_size = dst->size;

    pis_op_t res_tmp = TMP_ALLOC(&ctx->tmp_allocator, operand_size);

    pis_op_t count = TMP_ALLOC(&ctx->tmp_allocator, operand_size);
    CHECK_RETHROW(mask_shift_count(ctx, count_operand, &count, operand_size));

    // carry flag
    CHECK_RETHROW(shr_calc_carry_flag(ctx, dst, &count));

    // perform the actual shift
    PIS_EMIT(&ctx->args->result, PIS_INSN3(PIS_OPCODE_SHIFT_RIGHT, res_tmp, *dst, count));

    // copy the bits shifted in from the src operand.
    // to do that, we shift the src operand `size - count` bits, and then OR the result into the
    // result.
    pis_op_t src_shift_count = TMP_ALLOC(&ctx->tmp_allocator, operand_size);
    PIS_EMIT(
        &ctx->args->result,
        PIS_INSN3(
            PIS_OPCODE_SUB,
            src_shift_count,
            PIS_OPERAND_IMM(pis_size_to_bytes(operand_size), operand_size),
            count
        )
    );

    pis_op_t shifted_src = TMP_ALLOC(&ctx->tmp_allocator, operand_size);
    PIS_EMIT(
        &ctx->args->result,
        PIS_INSN3(PIS_OPCODE_SHIFT_LEFT, shifted_src, *src, src_shift_count)
    );

    PIS_EMIT(&ctx->args->result, PIS_INSN3(PIS_OPCODE_OR, res_tmp, res_tmp, shifted_src));

    // overflow flag
    CHECK_RETHROW(shrd_calc_overflow_flag(ctx, dst, &count, &res_tmp));

    CHECK_RETHROW(shift_calc_parity_zero_sign_flags(ctx, &count, &res_tmp));

    *result = res_tmp;

cleanup:
    return err;
}

/// calculates the overflow flag of a `SHR` operation. `to_shift` is the value to be shifted,
/// `count` is the masked shift count.
static err_t shr_calc_overflow_flag(ctx_t* ctx, const pis_op_t* to_shift, const pis_op_t* count) {
    err_t err = SUCCESS;

    CHECK(count->size == to_shift->size);

    pis_size_t operand_size = to_shift->size;

    // the overflow flag is set to the msb of the original operand
    pis_op_t new_overflow_flag_value = TMP_ALLOC(&ctx->tmp_allocator, PIS_SIZE_1);
    CHECK_RETHROW(extract_most_significant_bit(ctx, to_shift, &new_overflow_flag_value));

    // we only want to set the overflow flag if the count is 1, otherwise we want to use
    // the original OF value.
    pis_op_t is_count_1 = TMP_ALLOC(&ctx->tmp_allocator, PIS_SIZE_1);
    PIS_EMIT(
        &ctx->args->result,
        PIS_INSN3(PIS_OPCODE_EQUALS, is_count_1, *count, PIS_OPERAND_IMM(1, operand_size))
    );

    pis_op_t of = pis_reg_to_op(X86_FLAGS_OF);
    CHECK_RETHROW(cond_expr_ternary(ctx, &is_count_1, &new_overflow_flag_value, &of, &of));

cleanup:
    return err;
}

/// calculates the overflow flag of a `SAR` operation. `to_shift` is the value to be shifted,
/// `count` is the masked shift count.
static err_t sar_calc_overflow_flag(ctx_t* ctx, const pis_op_t* to_shift, const pis_op_t* count) {
    err_t err = SUCCESS;

    CHECK(count->size == to_shift->size);

    pis_size_t operand_size = to_shift->size;

    // the overflow flag is set to 0 if the count is 1
    pis_op_t new_overflow_flag_value = PIS_OPERAND_IMM(0, PIS_SIZE_1);

    // we only want to set the overflow flag if the count is 1, otherwise we want to use
    // the original OF value.
    pis_op_t is_count_1 = TMP_ALLOC(&ctx->tmp_allocator, PIS_SIZE_1);
    PIS_EMIT(
        &ctx->args->result,
        PIS_INSN3(PIS_OPCODE_EQUALS, is_count_1, *count, PIS_OPERAND_IMM(1, operand_size))
    );

    pis_op_t of = pis_reg_to_op(X86_FLAGS_OF);
    CHECK_RETHROW(cond_expr_ternary(ctx, &is_count_1, &new_overflow_flag_value, &of, &of));

cleanup:
    return err;
}

/// performs a `SHR` operation on the 2 input operands `a` and `b` and returns an operand
/// containing the result of the operation in `result`.
static err_t binop_shr(ctx_t* ctx, const pis_op_t* a, const pis_op_t* b, pis_op_t* result) {
    err_t err = SUCCESS;

    CHECK(a->size == b->size);
    pis_size_t operand_size = a->size;

    pis_op_t res_tmp = TMP_ALLOC(&ctx->tmp_allocator, operand_size);

    pis_op_t count = TMP_ALLOC(&ctx->tmp_allocator, operand_size);
    CHECK_RETHROW(mask_shift_count(ctx, b, &count, operand_size));

    // carry flag
    CHECK_RETHROW(shr_calc_carry_flag(ctx, a, &count));

    // overflow flag
    CHECK_RETHROW(shr_calc_overflow_flag(ctx, a, &count));

    // perform the actual shift
    PIS_EMIT(&ctx->args->result, PIS_INSN3(PIS_OPCODE_SHIFT_RIGHT, res_tmp, *a, count));

    CHECK_RETHROW(shift_calc_parity_zero_sign_flags(ctx, &count, &res_tmp));

    *result = res_tmp;

cleanup:
    return err;
}

/// performs a `SAR` operation on the 2 input operands `a` and `b` and returns an operand
/// containing the result of the operation in `result`.
static err_t binop_sar(ctx_t* ctx, const pis_op_t* a, const pis_op_t* b, pis_op_t* result) {
    err_t err = SUCCESS;

    CHECK(a->size == b->size);
    pis_size_t operand_size = a->size;

    pis_op_t res_tmp = TMP_ALLOC(&ctx->tmp_allocator, operand_size);

    pis_op_t count = TMP_ALLOC(&ctx->tmp_allocator, operand_size);
    CHECK_RETHROW(mask_shift_count(ctx, b, &count, operand_size));

    // carry flag
    CHECK_RETHROW(shr_calc_carry_flag(ctx, a, &count));

    // overflow flag
    CHECK_RETHROW(sar_calc_overflow_flag(ctx, a, &count));

    // perform the actual shift
    PIS_EMIT(&ctx->args->result, PIS_INSN3(PIS_OPCODE_SHIFT_RIGHT_SIGNED, res_tmp, *a, count));

    CHECK_RETHROW(shift_calc_parity_zero_sign_flags(ctx, &count, &res_tmp));

    *result = res_tmp;

cleanup:
    return err;
}

/// performs a `ROL` operation on the 2 input operands `a` and `b` and returns an operand
/// containing the result of the operation in `result`.
static err_t binop_rol(ctx_t* ctx, const pis_op_t* a, const pis_op_t* b, pis_op_t* result) {
    err_t err = SUCCESS;

    CHECK(a->size == b->size);
    pis_size_t operand_size = a->size;

    pis_op_t count = TMP_ALLOC(&ctx->tmp_allocator, operand_size);
    CHECK_RETHROW(mask_shift_count(ctx, b, &count, operand_size));

    // perform the actual rotation
    pis_op_t left_shifted = TMP_ALLOC(&ctx->tmp_allocator, operand_size);
    PIS_EMIT(&ctx->args->result, PIS_INSN3(PIS_OPCODE_SHIFT_LEFT, left_shifted, *a, count));

    pis_op_t right_shift_count = TMP_ALLOC(&ctx->tmp_allocator, operand_size);
    PIS_EMIT(
        &ctx->args->result,
        PIS_INSN3(
            PIS_OPCODE_SUB,
            right_shift_count,
            PIS_OPERAND_IMM(pis_size_to_bits(operand_size), operand_size),
            count
        )
    );

    pis_op_t right_shifted = TMP_ALLOC(&ctx->tmp_allocator, operand_size);
    PIS_EMIT(
        &ctx->args->result,
        PIS_INSN3(PIS_OPCODE_SHIFT_RIGHT, right_shifted, *a, right_shift_count)
    );

    pis_op_t res_tmp = TMP_ALLOC(&ctx->tmp_allocator, operand_size);
    PIS_EMIT(&ctx->args->result, PIS_INSN3(PIS_OPCODE_OR, res_tmp, right_shifted, left_shifted));

    // calculate the carry flag
    pis_op_t last_extracted_bit = TMP_ALLOC(&ctx->tmp_allocator, operand_size);
    PIS_EMIT(
        &ctx->args->result,
        PIS_INSN3(PIS_OPCODE_AND, last_extracted_bit, res_tmp, PIS_OPERAND_IMM(1, operand_size))
    );
    pis_op_t cf = pis_reg_to_op(X86_FLAGS_CF);
    CHECK_RETHROW(write_resize_zext(ctx, &cf, &last_extracted_bit));

    // overflow flag is the same as `shl`
    CHECK_RETHROW(shl_calc_overflow_flag(ctx, a, &count, &res_tmp));

    CHECK_RETHROW(shift_calc_parity_zero_sign_flags(ctx, &count, &res_tmp));

    *result = res_tmp;

cleanup:
    return err;
}

/// pushes the current instruction pointer value. this takes into account the effective operand
/// sizes of the instruction.
static err_t push_ip(ctx_t* ctx) {
    err_t err = SUCCESS;
    u64 cur_insn_end_addr = ctx->args->machine_code_addr + cursor_index(&ctx->args->machine_code);
    u64 push_value = rel_jmp_mask_ip_value(ctx, cur_insn_end_addr);
    CHECK_RETHROW(
        push(ctx, &PIS_OPERAND_IMM(push_value, near_branch_operand_default_operand_size(ctx)))
    );
cleanup:
    return err;
}

/// peforms a division operation that operates on the `ax` and `dx` operands and stores its
/// results in the `ax` and `dx` operands.
static err_t do_div_ax_dx(ctx_t* ctx, const pis_op_t* divisor, bool is_signed) {
    err_t err = SUCCESS;

    pis_size_t operand_size = divisor->size;

    if (operand_size == PIS_SIZE_8) {
        // divide `rdx:rax`.

        // perform the division
        pis_op_t quotient = TMP_ALLOC(&ctx->tmp_allocator, PIS_SIZE_8);
        PIS_EMIT(
            &ctx->args->result,
            PIS_INSN4(
                is_signed ? PIS_OPCODE_SIGNED_DIV_16 : PIS_OPCODE_UNSIGNED_DIV_16,
                quotient,
                pis_reg_to_op(X86_RDX),
                pis_reg_to_op(X86_RAX),
                *divisor
            )
        );

        // perform the remainder calculation
        pis_op_t rem = TMP_ALLOC(&ctx->tmp_allocator, PIS_SIZE_8);
        PIS_EMIT(
            &ctx->args->result,
            PIS_INSN4(
                is_signed ? PIS_OPCODE_SIGNED_REM_16 : PIS_OPCODE_UNSIGNED_REM_16,
                rem,
                pis_reg_to_op(X86_RDX),
                pis_reg_to_op(X86_RAX),
                *divisor
            )
        );

        // write the results back to RAX and RDX
        PIS_EMIT(&ctx->args->result, PIS_INSN2(PIS_OPCODE_MOVE, pis_reg_to_op(X86_RAX), quotient));
        PIS_EMIT(&ctx->args->result, PIS_INSN2(PIS_OPCODE_MOVE, pis_reg_to_op(X86_RDX), rem));

    } else {
        // divide `dx:ax` or `edx:eax`.

        pis_op_t ax = reg_to_op_resize(X86_RAX, operand_size);
        pis_op_t dx = reg_to_op_resize(X86_RDX, operand_size);

        pis_size_t double_operand_size = operand_size * 2;

        // first, combine the 2 registers into a single operand.
        pis_op_t divide_lhs = {};
        CHECK_RETHROW(read_resize_zext(ctx, &ax, double_operand_size, &divide_lhs));

        // zero extend the dx part and shift it left
        pis_op_t zext_dx = {};
        CHECK_RETHROW(read_resize_zext(ctx, &dx, double_operand_size, &zext_dx));
        PIS_EMIT(
            &ctx->args->result,
            PIS_INSN3(
                PIS_OPCODE_SHIFT_LEFT,
                zext_dx,
                zext_dx,
                PIS_OPERAND_IMM(pis_size_to_bits(operand_size), double_operand_size)
            )
        );

        // or the shifted dx value into the result operand
        PIS_EMIT(&ctx->args->result, PIS_INSN3(PIS_OPCODE_OR, divide_lhs, divide_lhs, zext_dx));

        // zero extend the divisor
        pis_op_t zero_extended_divisor = {};
        CHECK_RETHROW(read_resize_zext(ctx, divisor, double_operand_size, &zero_extended_divisor));

        // perform the division
        pis_op_t div_result = TMP_ALLOC(&ctx->tmp_allocator, double_operand_size);
        PIS_EMIT(
            &ctx->args->result,
            PIS_INSN3(
                is_signed ? PIS_OPCODE_SIGNED_DIV : PIS_OPCODE_UNSIGNED_DIV,
                div_result,
                divide_lhs,
                zero_extended_divisor
            )
        );

        // store the division result in ax
        CHECK_RETHROW(write_resize_zext(ctx, &ax, &div_result));

        // perform the remainder calculation
        pis_op_t rem_result = TMP_ALLOC(&ctx->tmp_allocator, double_operand_size);
        PIS_EMIT(
            &ctx->args->result,
            PIS_INSN3(
                is_signed ? PIS_OPCODE_SIGNED_REM : PIS_OPCODE_UNSIGNED_REM,
                rem_result,
                divide_lhs,
                zero_extended_divisor
            )
        );

        // store the division result in dx
        CHECK_RETHROW(write_resize_zext(ctx, &dx, &rem_result));
    }
cleanup:
    return err;
}

/// peforms a multiplication operation that operates on the `ax` operand and stores its
/// result in the `ax` and `dx` operands.
static err_t do_mul_ax(ctx_t* ctx, const pis_op_t* factor) {
    err_t err = SUCCESS;

    pis_size_t operand_size = factor->size;

    pis_op_t result_high = TMP_ALLOC(&ctx->tmp_allocator, operand_size);
    pis_op_t result_low = TMP_ALLOC(&ctx->tmp_allocator, operand_size);

    // compute the result of the multiplication and split it into 2 parts - high and low.
    if (operand_size == PIS_SIZE_8) {
        // when the operand size is 8 we can't use the regular multiplication opcode, since we want
        // a 16-byte result. so, we use a special opcode for it.
        PIS_EMIT(
            &ctx->args->result,
            PIS_INSN4(
                PIS_OPCODE_UNSIGNED_MUL_16,
                result_high,
                result_low,
                pis_reg_to_op(X86_RAX),
                *factor
            )
        );

        // store the result of the multiplication
        PIS_EMIT(
            &ctx->args->result,
            PIS_INSN2(PIS_OPCODE_MOVE, pis_reg_to_op(X86_RDX), result_high)
        );
        PIS_EMIT(
            &ctx->args->result,
            PIS_INSN2(PIS_OPCODE_MOVE, pis_reg_to_op(X86_RAX), result_low)
        );
    } else {
        // operand size is less than 8, so we can use the regular multiplication opcode.
        pis_size_t double_operand_size = operand_size * 2;

        pis_op_t factor_zext = {};
        CHECK_RETHROW(read_resize_zext(ctx, factor, double_operand_size, &factor_zext));

        pis_op_t ax = reg_to_op_resize(X86_RAX, operand_size);

        pis_op_t ax_zext = {};
        CHECK_RETHROW(read_resize_zext(ctx, &ax, double_operand_size, &ax_zext));

        pis_op_t multiplication_result = TMP_ALLOC(&ctx->tmp_allocator, double_operand_size);
        PIS_EMIT(
            &ctx->args->result,
            PIS_INSN3(PIS_OPCODE_UNSIGNED_MUL, multiplication_result, ax_zext, factor_zext)
        );
        // store the result of the multiplication
        if (operand_size == PIS_SIZE_1) {
            PIS_EMIT(
                &ctx->args->result,
                PIS_INSN2(PIS_OPCODE_MOVE, pis_reg_to_op(X86_AX), multiplication_result)
            );
        } else {
            // split the result into the low and high parts
            pis_op_t result_low = {};
            CHECK_RETHROW(read_resize_zext(ctx, &multiplication_result, operand_size, &result_low));

            pis_op_t shifted_multiplication_result =
                TMP_ALLOC(&ctx->tmp_allocator, double_operand_size);
            PIS_EMIT(
                &ctx->args->result,
                PIS_INSN3(
                    PIS_OPCODE_SHIFT_RIGHT,
                    shifted_multiplication_result,
                    multiplication_result,
                    PIS_OPERAND_IMM(pis_size_to_bits(operand_size), double_operand_size)
                )
            );

            pis_op_t result_high = {};
            CHECK_RETHROW(
                read_resize_zext(ctx, &shifted_multiplication_result, operand_size, &result_high)
            );

            pis_op_t dx = reg_to_op_resize(X86_RDX, operand_size);
            PIS_EMIT(&ctx->args->result, PIS_INSN2(PIS_OPCODE_MOVE, dx, result_high));
            PIS_EMIT(&ctx->args->result, PIS_INSN2(PIS_OPCODE_MOVE, ax, result_low));
        }
    }

    // calculate the carry and overflow flags
    pis_op_t is_high_zero = TMP_ALLOC(&ctx->tmp_allocator, PIS_SIZE_1);
    PIS_EMIT(
        &ctx->args->result,
        PIS_INSN3(PIS_OPCODE_EQUALS, is_high_zero, result_high, PIS_OPERAND_IMM(0, operand_size))
    );

    PIS_EMIT(
        &ctx->args->result,
        PIS_INSN2(PIS_OPCODE_COND_NEGATE, pis_reg_to_op(X86_FLAGS_CF), is_high_zero)
    );
    PIS_EMIT(
        &ctx->args->result,
        PIS_INSN2(PIS_OPCODE_MOVE, pis_reg_to_op(X86_FLAGS_OF), pis_reg_to_op(X86_FLAGS_CF))
    );
cleanup:
    return err;
}

/// performs a `BT` operation with the first operand being a memory operand.
static err_t do_bt_memory(ctx_t* ctx, const pis_op_t* bit_base_addr, const pis_op_t* bit_offset) {
    err_t err = SUCCESS;

    // resize the bit offset operand to the address size, since we need to add it to the address
    pis_op_t resized_bit_offset = {};
    CHECK_RETHROW(read_resize_zext(ctx, bit_offset, ctx->addr_size, &resized_bit_offset));

    // divide the bit offset by 8 to get the byte offset. this can be done by shifting it right 3
    // times.
    pis_op_t byte_offset = TMP_ALLOC(&ctx->tmp_allocator, ctx->addr_size);
    PIS_EMIT(
        &ctx->args->result,
        PIS_INSN3(
            PIS_OPCODE_SHIFT_RIGHT_SIGNED,
            byte_offset,
            resized_bit_offset,
            PIS_OPERAND_IMM(3, ctx->addr_size)
        )
    );

    // add the byte offset to the base address to get the byte address
    pis_op_t byte_addr = TMP_ALLOC(&ctx->tmp_allocator, ctx->addr_size);
    PIS_EMIT(&ctx->args->result, PIS_INSN3(PIS_OPCODE_ADD, byte_addr, *bit_base_addr, byte_offset));

    // load the byte from memory
    pis_op_t byte = TMP_ALLOC(&ctx->tmp_allocator, PIS_SIZE_1);
    PIS_EMIT(&ctx->args->result, PIS_INSN2(PIS_OPCODE_LOAD, byte, byte_addr));

    // calculate the in-byte bit offset
    pis_op_t in_byte_bit_offset = {};
    CHECK_RETHROW(read_resize_zext(ctx, bit_offset, PIS_SIZE_1, &in_byte_bit_offset));
    PIS_EMIT(
        &ctx->args->result,
        PIS_INSN3(
            PIS_OPCODE_AND,
            in_byte_bit_offset,
            in_byte_bit_offset,
            PIS_OPERAND_IMM(7, PIS_SIZE_1)
        )
    );

    // extract the bit into the carry flag.
    PIS_EMIT(
        &ctx->args->result,
        PIS_INSN3(PIS_OPCODE_SHIFT_RIGHT, pis_reg_to_op(X86_FLAGS_CF), byte, in_byte_bit_offset)
    );

cleanup:
    return err;
}

/// performs a `BT` operation with the first operand being a register operand.
static err_t do_bt_reg(ctx_t* ctx, const pis_op_t* bit_base_reg, const pis_op_t* bit_offset) {
    err_t err = SUCCESS;

    CHECK(bit_base_reg->size == bit_offset->size);

    pis_size_t operand_size = bit_base_reg->size;
    pis_op_t masked_bit_offset = TMP_ALLOC(&ctx->tmp_allocator, operand_size);
    CHECK_RETHROW(mask_shift_count(ctx, bit_offset, &masked_bit_offset, operand_size));

    // extract the bit
    pis_op_t resulting_bit_tmp = TMP_ALLOC(&ctx->tmp_allocator, operand_size);
    PIS_EMIT(
        &ctx->args->result,
        PIS_INSN3(PIS_OPCODE_SHIFT_RIGHT, resulting_bit_tmp, *bit_base_reg, masked_bit_offset)
    );
    pis_op_t cf = pis_reg_to_op(X86_FLAGS_CF);
    CHECK_RETHROW(extract_least_significant_bit(ctx, &resulting_bit_tmp, &cf));

cleanup:
    return err;
}

/// returns the group 1 prefix of the current instruction.
static legacy_prefix_t group1_prefix(ctx_t* ctx) {
    return ctx->prefixes.legacy.by_group[LEGACY_PREFIX_GROUP_1];
}

/// the context used to implement a REP prefix.
typedef struct {
    bool insn_has_rep_prefix;
    size_t insn_index_at_loop_start;
    pis_insn_t* jmp_end_insn;
} rep_ctx_t;

/// begin implementing a rep loop. this emits the first half of the rep loop which is at the start
/// of the lifted instruction. after calling this, you should emit your logic for a single iteration
/// of the loop, and then call the rep end function to emit the second half of the rep loop.
static err_t rep_begin(ctx_t* ctx, rep_ctx_t* rep_ctx) {
    err_t err = SUCCESS;

    if (group1_prefix(ctx) != LEGACY_PREFIX_REPZ_OR_REP) {
        // no rep prefix, no need to do anything
        rep_ctx->insn_has_rep_prefix = false;
        SUCCESS_CLEANUP();
    }

    rep_ctx->insn_has_rep_prefix = true;

    // save the instruction index at the start of the loop so that we can jump to it later.
    rep_ctx->insn_index_at_loop_start = ctx->args->result.insns_amount;

    // first check if `cx` if zero
    pis_op_t cx = reg_to_op_resize(X86_RCX, ctx->addr_size);
    pis_op_t cx_equals_zero = TMP_ALLOC(&ctx->tmp_allocator, PIS_SIZE_1);
    PIS_EMIT(
        &ctx->args->result,
        PIS_INSN3(PIS_OPCODE_EQUALS, cx_equals_zero, cx, PIS_OPERAND_IMM(0, ctx->addr_size))
    );

    // emit a jump which should skip over the entire code. the offset is currently 0 since we
    // don't know the size of the code, but it will be filled with the correct value later on.
    PIS_EMIT(
        &ctx->args->result,
        PIS_INSN2(PIS_OPCODE_JMP_COND, PIS_OPERAND_IMM(0, PIS_SIZE_1), cx_equals_zero)
    );
    CHECK_RETHROW(pis_lift_res_get_last_emitted_insn(&ctx->args->result, &rep_ctx->jmp_end_insn));

    // now that we know that `cx` is not zero, decrement it.
    PIS_EMIT(
        &ctx->args->result,
        PIS_INSN3(PIS_OPCODE_SUB, cx, cx, PIS_OPERAND_IMM(1, ctx->addr_size))
    );

cleanup:
    return err;
}

/// emits the second half of the rep loop, at the end of the instruction. this should be called
/// after calling the rep begin function and after emitting your code for a single iteration of the
/// rep loop.
static err_t rep_end(ctx_t* ctx, const rep_ctx_t* rep_ctx) {
    err_t err = SUCCESS;

    if (!rep_ctx->insn_has_rep_prefix) {
        // no rep prefix, no need to do anything
        SUCCESS_CLEANUP();
    }

    // now jump back to the start of the loop, for the next iteration of the loop.
    PIS_EMIT(
        &ctx->args->result,
        PIS_INSN1(PIS_OPCODE_JMP, PIS_OPERAND_IMM(rep_ctx->insn_index_at_loop_start, PIS_SIZE_1))
    );

    // now that we finished emitting the code, update the offset of the jmp instruction at the start
    // of the loop which should jump to the end of the instruction.
    rep_ctx->jmp_end_insn->operands[0] =
        PIS_OPERAND_IMM(ctx->args->result.insns_amount, PIS_SIZE_1);

cleanup:
    return err;
}

op_size_t calc_size(ctx_t* ctx, size_t size_info_index) {
    const op_size_info_t* size_info = &op_size_infos_table[size_info_index];
    if (ctx->prefixes.rex.w) {
        return size_info->mode_64_with_rex_w;
    } else if (prefixes_contain_legacy_prefix(
                   &ctx->prefixes,
                   LEGACY_PREFIX_OPERAND_SIZE_OVERRIDE
               )) {
        return size_info->with_operand_size_override;
    } else {
        switch (ctx->cpumode) {
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

static pis_size_t op_size_to_pis_operand_size(op_size_t op_size) {
    return (u32) 1 << (u32) op_size;
}

static err_t get_or_fetch_modrm(ctx_t* ctx, modrm_t* modrm) {
    err_t err = SUCCESS;
    if (!ctx->has_modrm) {
        CHECK_RETHROW(cursor_next_1(&ctx->args->machine_code, &ctx->modrm_byte));
        ctx->has_modrm = true;
    }
    *modrm = modrm_decode_byte(ctx->modrm_byte);
cleanup:
    return err;
}

static pis_op_t decode_specific_reg(specific_reg_t reg, op_size_t size) {
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

// make sure that the instruction doesn't have any size override prefixes
static err_t verify_no_size_override_prefixes(ctx_t* ctx) {
    err_t err = SUCCESS;
    CHECK(!prefixes_contain_legacy_prefix(&ctx->prefixes, LEGACY_PREFIX_OPERAND_SIZE_OVERRIDE));
    CHECK(!prefixes_contain_legacy_prefix(&ctx->prefixes, LEGACY_PREFIX_ADDRESS_SIZE_OVERRIDE));
cleanup:
    return err;
}

static err_t
    lift_op(ctx_t* ctx, u8 opcode_byte, const op_info_t* op_info, lifted_op_t* lifted_operand) {
    err_t err = SUCCESS;
    switch (op_info->kind) {
        case OP_KIND_IMM: {
            op_size_t encoded_size = calc_size(ctx, op_info->imm.encoded_size_info_index);
            op_size_t extended_size = calc_size(ctx, op_info->imm.extended_size_info_index);

            u64 imm = 0;
            imm_ext_kind_t extend_kind = op_info->imm.extend_kind;
            CHECK_RETHROW(cursor_next_imm_ext(
                &ctx->args->machine_code,
                op_size_to_pis_operand_size(encoded_size),
                op_size_to_pis_operand_size(extended_size),
                extend_kind,
                PIS_ENDIANNESS_LITTLE,
                &imm
            ));

            *lifted_operand = (lifted_op_t) {
                .kind = LIFTED_OP_KIND_VALUE,
                .value = PIS_OPERAND_IMM(imm, op_size_to_pis_operand_size(extended_size)),
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
                .value = PIS_OPERAND_IMM(imm, op_size_to_pis_operand_size(size)),
            };

            break;
        }
        case OP_KIND_REG: {
            u8 reg_encoding;
            switch (op_info->reg.encoding) {
                case REG_ENC_MODRM: {
                    modrm_t modrm = {};
                    CHECK_RETHROW(get_or_fetch_modrm(ctx, &modrm));
                    reg_encoding = apply_rex_bit_to_reg_encoding(modrm.reg, ctx->prefixes.rex.r);
                    break;
                }
                case REG_ENC_OPCODE:
                    reg_encoding = opcode_reg_extract(ctx, opcode_byte);
                    break;
            }

            op_size_t size = calc_size(ctx, op_info->reg.size_info_index);

            *lifted_operand = (lifted_op_t) {
                .kind = LIFTED_OP_KIND_REG,
                .reg = reg_get_operand(
                    reg_encoding,
                    op_size_to_pis_operand_size(size),
                    &ctx->prefixes
                ),
            };

            break;
        }
        case OP_KIND_RM: {
            modrm_t modrm = {};
            CHECK_RETHROW(get_or_fetch_modrm(ctx, &modrm));

            op_size_t size = calc_size(ctx, op_info->rm.size_info_index);
            pis_size_t pis_operand_size = op_size_to_pis_operand_size(size);

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
                    .kind = LIFTED_OP_KIND_REG,
                    .reg = rm_operand.addr_or_reg,
                };
            }
            break;
        }
        case OP_KIND_SPECIFIC_REG: {
            op_size_t size = calc_size(ctx, op_info->specific_reg.size_info_index);

            *lifted_operand = (lifted_op_t) {
                .kind = LIFTED_OP_KIND_REG,
                .reg = decode_specific_reg(op_info->specific_reg.reg, size),
            };
            break;
        }
        case OP_KIND_ZEXT_SPECIFIC_REG: {
            op_size_t size = calc_size(ctx, op_info->zext_specific_reg.size_info_index);
            op_size_t extended_size =
                calc_size(ctx, op_info->zext_specific_reg.extended_size_info_index);

            pis_op_t reg_operand = decode_specific_reg(op_info->zext_specific_reg.reg, size);

            pis_op_t extended_reg = {};
            CHECK_RETHROW(read_resize_zext(
                ctx,
                &reg_operand,
                op_size_to_pis_operand_size(extended_size),
                &extended_reg
            ));
            *lifted_operand = (lifted_op_t) {
                .kind = LIFTED_OP_KIND_VALUE,
                .value = extended_reg,
            };

            break;
        }
        case OP_KIND_REL: {
            op_size_t size = calc_size(ctx, op_info->rel.size_info_index);

            u64 rel_offset = 0;
            CHECK_RETHROW(cursor_next_imm_ext(
                &ctx->args->machine_code,
                op_size_to_pis_operand_size(size),
                ctx->addr_size,
                IMM_EXT_KIND_SIGN_EXTEND,
                PIS_ENDIANNESS_LITTLE,
                &rel_offset
            ));

            u64 cur_insn_end_addr =
                ctx->args->machine_code_addr + cursor_index(&ctx->args->machine_code);
            u64 target_addr = rel_jmp_mask_ip_value(ctx, cur_insn_end_addr + rel_offset);

            *lifted_operand = (lifted_op_t) {
                .kind = LIFTED_OP_KIND_VALUE,
                .value = PIS_OPERAND_RAM(target_addr, PIS_SIZE_1),
            };

            break;
        }
        case OP_KIND_MEM_OFFSET: {
            u64 addr = 0;
            CHECK_RETHROW(cursor_next_imm_ext(
                &ctx->args->machine_code,
                ctx->addr_size,
                ctx->addr_size,
                IMM_EXT_KIND_ZERO_EXTEND,
                PIS_ENDIANNESS_LITTLE,
                &addr
            ));

            *lifted_operand = (lifted_op_t) {
                .kind = LIFTED_OP_KIND_MEM,
                .value = PIS_OPERAND_IMM(addr, ctx->addr_size),
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
            pis_op_t cond = {};
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

static pis_size_t lifted_op_size(const lifted_op_t* op) {
    switch (op->kind) {
        case LIFTED_OP_KIND_MEM:
            return op->mem.size;
        case LIFTED_OP_KIND_VALUE:
            return op->value.size;
        case LIFTED_OP_KIND_REG:
            return op->reg.size;
        default:
            // unreachable
            return PIS_SIZE_1;
    }
}

static err_t lifted_op_read(ctx_t* ctx, const lifted_op_t* op, pis_op_t* value) {
    err_t err = SUCCESS;
    switch (op->kind) {
        case LIFTED_OP_KIND_MEM: {
            pis_op_t tmp = TMP_ALLOC(&ctx->tmp_allocator, op->mem.size);
            PIS_EMIT(&ctx->args->result, PIS_INSN2(PIS_OPCODE_LOAD, tmp, op->mem.addr));
            *value = tmp;
            break;
        }
        case LIFTED_OP_KIND_VALUE:
            *value = op->value;
            break;
        case LIFTED_OP_KIND_REG: {
            *value = op->reg;
            break;
        }
        case LIFTED_OP_KIND_IMPLICIT:
            // can't read implicit operands
            UNREACHABLE();
    }
cleanup:
    return err;
}

static err_t lifted_op_write(ctx_t* ctx, const lifted_op_t* op, const pis_op_t* value) {
    err_t err = SUCCESS;
    switch (op->kind) {
        case LIFTED_OP_KIND_MEM: {
            PIS_EMIT(&ctx->args->result, PIS_INSN2(PIS_OPCODE_STORE, op->mem.addr, *value));
            break;
        }
        case LIFTED_OP_KIND_VALUE:
            PIS_EMIT(&ctx->args->result, PIS_INSN2(PIS_OPCODE_MOVE, op->value, *value));
            break;
        case LIFTED_OP_KIND_REG:
            CHECK_RETHROW(write_gpr(ctx, &op->reg, value));
            break;
        case LIFTED_OP_KIND_IMPLICIT:
            // can't write to implicit operands
            UNREACHABLE();
    }
cleanup:
    return err;
}

static err_t handle_mnemonic_binop(
    ctx_t* ctx, const lifted_op_t* ops, size_t ops_amount, binop_fn_t binop, bool store
) {
    err_t err = SUCCESS;
    CHECK(ops_amount == 2);

    pis_op_t lhs = {};
    CHECK_RETHROW(lifted_op_read(ctx, &ops[0], &lhs));

    pis_op_t rhs = {};
    CHECK_RETHROW(lifted_op_read(ctx, &ops[1], &rhs));

    pis_op_t res = {};
    CHECK_RETHROW(binop(ctx, &lhs, &rhs, &res));

    if (store) {
        CHECK_RETHROW(lifted_op_write(ctx, &ops[0], &res));
    }
cleanup:
    return err;
}

static err_t handle_mnemonic_shld(ctx_t* ctx, const lifted_op_t* ops, size_t ops_amount) {
    err_t err = SUCCESS;
    CHECK(ops_amount == 3);

    pis_op_t dst = {};
    CHECK_RETHROW(lifted_op_read(ctx, &ops[0], &dst));

    pis_op_t src = {};
    CHECK_RETHROW(lifted_op_read(ctx, &ops[1], &src));

    pis_op_t count = {};
    CHECK_RETHROW(lifted_op_read(ctx, &ops[1], &count));

    pis_op_t res = {};
    CHECK_RETHROW(do_shld(ctx, &dst, &src, &count, &res));

    CHECK_RETHROW(lifted_op_write(ctx, &ops[0], &res));
cleanup:
    return err;
}

static err_t handle_mnemonic_shrd(ctx_t* ctx, const lifted_op_t* ops, size_t ops_amount) {
    err_t err = SUCCESS;
    CHECK(ops_amount == 3);

    pis_op_t dst = {};
    CHECK_RETHROW(lifted_op_read(ctx, &ops[0], &dst));

    pis_op_t src = {};
    CHECK_RETHROW(lifted_op_read(ctx, &ops[1], &src));

    pis_op_t count = {};
    CHECK_RETHROW(lifted_op_read(ctx, &ops[1], &count));

    pis_op_t res = {};
    CHECK_RETHROW(do_shrd(ctx, &dst, &src, &count, &res));

    CHECK_RETHROW(lifted_op_write(ctx, &ops[0], &res));
cleanup:
    return err;
}

static err_t handle_mnemonic_unary_op(
    ctx_t* ctx, const lifted_op_t* ops, size_t ops_amount, unary_op_fn_t unary_op
) {
    err_t err = SUCCESS;
    CHECK(ops_amount == 1);

    pis_op_t op = {};
    CHECK_RETHROW(lifted_op_read(ctx, &ops[0], &op));

    pis_op_t res = {};
    CHECK_RETHROW(unary_op(ctx, &op, &res));

    CHECK_RETHROW(lifted_op_write(ctx, &ops[0], &res));
cleanup:
    return err;
}

#define DEFINE_BINOP_MNEMONIC_HANDLER(NAME)                                                        \
    static err_t handle_mnemonic_##NAME(ctx_t* ctx, const lifted_op_t* ops, size_t ops_amount) {   \
        err_t err = SUCCESS;                                                                       \
        CHECK_RETHROW(handle_mnemonic_binop(ctx, ops, ops_amount, binop_##NAME, true));            \
    cleanup:                                                                                       \
        return err;                                                                                \
    }

#define DEFINE_COMPARISON_BINOP_MNEMONIC_HANDLER(NAME, BINOP_NAME)                                 \
    static err_t handle_mnemonic_##NAME(ctx_t* ctx, const lifted_op_t* ops, size_t ops_amount) {   \
        err_t err = SUCCESS;                                                                       \
        CHECK_RETHROW(handle_mnemonic_binop(ctx, ops, ops_amount, binop_##BINOP_NAME, false));     \
    cleanup:                                                                                       \
        return err;                                                                                \
    }

#define DEFINE_UNARY_OP_MNEMONIC_HANDLER(NAME)                                                     \
    static err_t handle_mnemonic_##NAME(ctx_t* ctx, const lifted_op_t* ops, size_t ops_amount) {   \
        err_t err = SUCCESS;                                                                       \
        CHECK_RETHROW(handle_mnemonic_unary_op(ctx, ops, ops_amount, unary_op_##NAME));            \
    cleanup:                                                                                       \
        return err;                                                                                \
    }

DEFINE_BINOP_MNEMONIC_HANDLER(add);
DEFINE_BINOP_MNEMONIC_HANDLER(adc);
DEFINE_BINOP_MNEMONIC_HANDLER(sbb);
DEFINE_BINOP_MNEMONIC_HANDLER(and);
DEFINE_BINOP_MNEMONIC_HANDLER(sub);
DEFINE_BINOP_MNEMONIC_HANDLER(shr);
DEFINE_BINOP_MNEMONIC_HANDLER(sar);
DEFINE_BINOP_MNEMONIC_HANDLER(shl);
DEFINE_BINOP_MNEMONIC_HANDLER(rol);
DEFINE_BINOP_MNEMONIC_HANDLER(xor);
DEFINE_BINOP_MNEMONIC_HANDLER(or);

DEFINE_COMPARISON_BINOP_MNEMONIC_HANDLER(cmp, sub);
DEFINE_COMPARISON_BINOP_MNEMONIC_HANDLER(test, and);

DEFINE_UNARY_OP_MNEMONIC_HANDLER(dec);
DEFINE_UNARY_OP_MNEMONIC_HANDLER(inc);
DEFINE_UNARY_OP_MNEMONIC_HANDLER(not );
DEFINE_UNARY_OP_MNEMONIC_HANDLER(neg);

static err_t handle_mnemonic_mov(ctx_t* ctx, const lifted_op_t* ops, size_t ops_amount) {
    err_t err = SUCCESS;
    CHECK(ops_amount == 2);

    pis_op_t rhs = {};
    CHECK_RETHROW(lifted_op_read(ctx, &ops[1], &rhs));

    CHECK_RETHROW(lifted_op_write(ctx, &ops[0], &rhs));
cleanup:
    return err;
}

static err_t handle_mnemonic_xchg(ctx_t* ctx, const lifted_op_t* ops, size_t ops_amount) {
    err_t err = SUCCESS;
    CHECK(ops_amount == 2);

    pis_op_t op0 = {};
    CHECK_RETHROW(lifted_op_read(ctx, &ops[0], &op0));

    pis_op_t op1 = {};
    CHECK_RETHROW(lifted_op_read(ctx, &ops[1], &op1));

    // both operands should have the same size
    CHECK(op0.size == op1.size);

    // save the value of op0 in a tmp operand
    pis_op_t tmp = TMP_ALLOC(&ctx->tmp_allocator, op0.size);
    PIS_EMIT(&ctx->args->result, PIS_INSN2(PIS_OPCODE_MOVE, tmp, op0));

    // overwrite op0 with the value in op1
    CHECK_RETHROW(lifted_op_write(ctx, &ops[0], &op1));

    // overwrite op1 with the original value of op0
    CHECK_RETHROW(lifted_op_write(ctx, &ops[1], &tmp));

cleanup:
    return err;
}

static err_t handle_mnemonic_cwd(ctx_t* ctx, const lifted_op_t* ops, size_t ops_amount) {
    err_t err = SUCCESS;
    CHECK(ops_amount == 2);

    pis_op_t src = {};
    CHECK_RETHROW(lifted_op_read(ctx, &ops[1], &src));

    pis_op_t sign_bit = TMP_ALLOC(&ctx->tmp_allocator, PIS_SIZE_1);
    CHECK_RETHROW(extract_most_significant_bit(ctx, &src, &sign_bit));

    // zero extend the sign bit to the correct size
    pis_size_t dst_size = lifted_op_size(&ops[0]);
    pis_op_t sign_bit_zext = TMP_ALLOC(&ctx->tmp_allocator, dst_size);
    PIS_EMIT(&ctx->args->result, PIS_INSN2(PIS_OPCODE_ZERO_EXTEND, sign_bit_zext, sign_bit));

    // arithmetically negate the sign bit to convert it to a value full of that bit.
    // if the condition is 1, negating it will produce an all 1s value, and if it is zero, it will
    // produce an all 0s value.
    pis_op_t final_value = TMP_ALLOC(&ctx->tmp_allocator, dst_size);
    PIS_EMIT(&ctx->args->result, PIS_INSN2(PIS_OPCODE_NEG, final_value, sign_bit_zext));

    CHECK_RETHROW(lifted_op_write(ctx, &ops[0], &final_value));

cleanup:
    return err;
}

static err_t handle_mnemonic_div(ctx_t* ctx, const lifted_op_t* ops, size_t ops_amount) {
    err_t err = SUCCESS;
    CHECK(ops_amount == 1);

    pis_op_t divide_by = {};
    CHECK_RETHROW(lifted_op_read(ctx, &ops[0], &divide_by));

    CHECK_RETHROW(do_div_ax_dx(ctx, &divide_by, false));

cleanup:
    return err;
}

static err_t handle_mnemonic_idiv(ctx_t* ctx, const lifted_op_t* ops, size_t ops_amount) {
    err_t err = SUCCESS;
    CHECK(ops_amount == 1);

    pis_op_t divide_by = {};
    CHECK_RETHROW(lifted_op_read(ctx, &ops[0], &divide_by));

    CHECK_RETHROW(do_div_ax_dx(ctx, &divide_by, true));

cleanup:
    return err;
}

static err_t handle_mnemonic_mul(ctx_t* ctx, const lifted_op_t* ops, size_t ops_amount) {
    err_t err = SUCCESS;
    CHECK(ops_amount == 1);

    pis_op_t mul_by = {};
    CHECK_RETHROW(lifted_op_read(ctx, &ops[0], &mul_by));

    CHECK_RETHROW(do_mul_ax(ctx, &mul_by));

cleanup:
    return err;
}

static err_t handle_mnemonic_bt(ctx_t* ctx, const lifted_op_t* ops, size_t ops_amount) {
    err_t err = SUCCESS;
    CHECK(ops_amount == 2);

    pis_op_t bit_offset = {};
    CHECK_RETHROW(lifted_op_read(ctx, &ops[1], &bit_offset));

    switch (ops[0].kind) {
        case LIFTED_OP_KIND_MEM:
            CHECK_RETHROW(do_bt_memory(ctx, &ops[0].mem.addr, &bit_offset));
            break;
        case LIFTED_OP_KIND_REG: {
            CHECK_RETHROW(do_bt_reg(ctx, &ops[0].reg, &bit_offset));
            break;
        }
        default:
            UNREACHABLE();
    }

cleanup:
    return err;
}

/// handles a mnemonic which extends the size of the first operand and stores the result in the
/// second operand.
static err_t handle_mnemonic_extend(
    ctx_t* ctx, const lifted_op_t* ops, size_t ops_amount, pis_opcode_t extend_opcode
) {
    err_t err = SUCCESS;
    CHECK(ops_amount == 2);

    pis_op_t rhs = {};
    CHECK_RETHROW(lifted_op_read(ctx, &ops[1], &rhs));

    pis_op_t tmp = TMP_ALLOC(&ctx->tmp_allocator, lifted_op_size(&ops[0]));
    PIS_EMIT(&ctx->args->result, PIS_INSN2(extend_opcode, tmp, rhs));

    CHECK_RETHROW(lifted_op_write(ctx, &ops[0], &tmp));
cleanup:
    return err;
}

static err_t handle_mnemonic_movzx(ctx_t* ctx, const lifted_op_t* ops, size_t ops_amount) {
    err_t err = SUCCESS;
    CHECK_RETHROW(handle_mnemonic_extend(ctx, ops, ops_amount, PIS_OPCODE_ZERO_EXTEND));
cleanup:
    return err;
}

static err_t handle_mnemonic_movsx(ctx_t* ctx, const lifted_op_t* ops, size_t ops_amount) {
    err_t err = SUCCESS;
    CHECK_RETHROW(handle_mnemonic_extend(ctx, ops, ops_amount, PIS_OPCODE_SIGN_EXTEND));
cleanup:
    return err;
}

static err_t handle_mnemonic_movsxd(ctx_t* ctx, const lifted_op_t* ops, size_t ops_amount) {
    err_t err = SUCCESS;
    CHECK(ops_amount == 2);

    // on 32-bit mode, the same byte is used to encode a different instruction, `ARPL`. this
    // behaviour of having a single byte decode to different instructions based on cpumode is
    // currently not supported, so make sure that we are in 64-bit mode here to avoid mis-decoding
    // the instruction.
    CHECK(ctx->cpumode == PIS_X86_CPUMODE_64_BIT);

    if (lifted_op_size(&ops[0]) > lifted_op_size(&ops[1])) {
        CHECK_RETHROW(handle_mnemonic_extend(ctx, ops, ops_amount, PIS_OPCODE_SIGN_EXTEND));
    } else {
        // movsxd may act as a move if its operands are of the same size
        CHECK_RETHROW(handle_mnemonic_mov(ctx, ops, ops_amount));
    }

cleanup:
    return err;
}

static err_t handle_mnemonic_nop(ctx_t* ctx, const lifted_op_t* ops, size_t ops_amount) {
    UNUSED(ctx);
    UNUSED(ops);
    UNUSED(ops_amount);
    return SUCCESS;
}

static err_t handle_mnemonic_imul(ctx_t* ctx, const lifted_op_t* ops, size_t ops_amount) {
    err_t err = SUCCESS;

    switch (ops_amount) {
        case 1:
            TODO();
            break;
        case 2:
            CHECK_RETHROW(handle_mnemonic_binop(ctx, ops, ops_amount, binop_imul, true));
            break;
        case 3: {
            pis_op_t lhs = {};
            CHECK_RETHROW(lifted_op_read(ctx, &ops[1], &lhs));

            pis_op_t rhs = {};
            CHECK_RETHROW(lifted_op_read(ctx, &ops[2], &rhs));

            pis_op_t res = {};
            CHECK_RETHROW(binop_imul(ctx, &lhs, &rhs, &res));

            CHECK_RETHROW(lifted_op_write(ctx, &ops[0], &res));
            break;
        }
        default:
            UNREACHABLE();
    }
cleanup:
    return err;
}

static err_t handle_mnemonic_hlt(ctx_t* ctx, const lifted_op_t* ops, size_t ops_amount) {
    err_t err = SUCCESS;

    CHECK(ops_amount == 0);
    UNUSED(ops);

    PIS_EMIT(&ctx->args->result, PIS_INSN0(PIS_OPCODE_HALT));
cleanup:
    return err;
}

static err_t handle_mnemonic_cmovcc(ctx_t* ctx, const lifted_op_t* ops, size_t ops_amount) {
    err_t err = SUCCESS;
    CHECK(ops_amount == 3);

    pis_size_t operand_size = lifted_op_size(&ops[1]);

    pis_op_t cond = {};
    CHECK_RETHROW(lifted_op_read(ctx, &ops[0], &cond));

    pis_op_t orig_value = {};
    CHECK_RETHROW(lifted_op_read(ctx, &ops[1], &orig_value));

    pis_op_t new_value = {};
    CHECK_RETHROW(lifted_op_read(ctx, &ops[2], &new_value));

    pis_op_t final_value = TMP_ALLOC(&ctx->tmp_allocator, operand_size);
    CHECK_RETHROW(ternary(ctx, &cond, &new_value, &orig_value, &final_value));

    CHECK_RETHROW(lifted_op_write(ctx, &ops[1], &final_value));
cleanup:
    return err;
}

static err_t handle_mnemonic_setcc(ctx_t* ctx, const lifted_op_t* ops, size_t ops_amount) {
    err_t err = SUCCESS;
    CHECK(ops_amount == 2);

    pis_op_t cond = {};
    CHECK_RETHROW(lifted_op_read(ctx, &ops[0], &cond));

    CHECK_RETHROW(lifted_op_write(ctx, &ops[1], &cond));
cleanup:
    return err;
}

static err_t handle_mnemonic_jcc(ctx_t* ctx, const lifted_op_t* ops, size_t ops_amount) {
    err_t err = SUCCESS;
    CHECK(ops_amount == 2);

    // branch instructions behave weirdly when using size override prefixes, so make sure that
    // we don't have any.
    CHECK_RETHROW(verify_no_size_override_prefixes(ctx));

    pis_op_t cond = {};
    CHECK_RETHROW(lifted_op_read(ctx, &ops[0], &cond));

    pis_op_t target = {};
    CHECK_RETHROW(lifted_op_read(ctx, &ops[1], &target));

    PIS_EMIT(&ctx->args->result, PIS_INSN2(PIS_OPCODE_JMP_COND, target, cond));

cleanup:
    return err;
}

static err_t handle_mnemonic_call(ctx_t* ctx, const lifted_op_t* ops, size_t ops_amount) {
    err_t err = SUCCESS;
    CHECK(ops_amount == 1);

    // branch instructions behave weirdly when using size override prefixes, so make sure that
    // we don't have any.
    CHECK_RETHROW(verify_no_size_override_prefixes(ctx));

    pis_op_t target = {};
    CHECK_RETHROW(lifted_op_read(ctx, &ops[0], &target));

    CHECK_RETHROW(push_ip(ctx));

    PIS_EMIT(&ctx->args->result, PIS_INSN1(PIS_OPCODE_JMP_CALL, target));

cleanup:
    return err;
}

static err_t handle_mnemonic_jmp(ctx_t* ctx, const lifted_op_t* ops, size_t ops_amount) {
    err_t err = SUCCESS;
    CHECK(ops_amount == 1);

    // branch instructions behave weirdly when using size override prefixes, so make sure that
    // we don't have any.
    CHECK_RETHROW(verify_no_size_override_prefixes(ctx));

    pis_op_t target = {};
    CHECK_RETHROW(lifted_op_read(ctx, &ops[0], &target));

    PIS_EMIT(&ctx->args->result, PIS_INSN1(PIS_OPCODE_JMP, target));

cleanup:
    return err;
}

static err_t handle_mnemonic_lea(ctx_t* ctx, const lifted_op_t* ops, size_t ops_amount) {
    err_t err = SUCCESS;
    CHECK(ops_amount == 2);

    CHECK(ops[1].kind == LIFTED_OP_KIND_MEM);

    const pis_op_t* mem_addr = &ops[1].mem.addr;

    pis_size_t dst_size = lifted_op_size(&ops[0]);

    // resize the memory address to the desired size
    pis_op_t resized_addr = {};
    CHECK_RETHROW(read_resize_zext(ctx, mem_addr, dst_size, &resized_addr));

    CHECK_RETHROW(lifted_op_write(ctx, &ops[0], &resized_addr));
cleanup:
    return err;
}

static err_t handle_mnemonic_endbr(ctx_t* ctx, const lifted_op_t* ops, size_t ops_amount) {
    // endbr is a nop
    UNUSED(ctx);
    UNUSED(ops);
    UNUSED(ops_amount);
    return SUCCESS;
}

static err_t pop(ctx_t* ctx, pis_size_t pop_size, pis_op_t* result) {
    err_t err = SUCCESS;

    pis_op_t sp = ctx->sp;
    u64 operand_size_bytes = pis_size_to_bytes(pop_size);

    pis_op_t tmp = TMP_ALLOC(&ctx->tmp_allocator, pop_size);

    PIS_EMIT(&ctx->args->result, PIS_INSN2(PIS_OPCODE_LOAD, tmp, sp));

    PIS_EMIT(
        &ctx->args->result,
        PIS_INSN3(PIS_OPCODE_ADD, sp, sp, PIS_OPERAND_IMM(operand_size_bytes, sp.size))
    );

    *result = tmp;
cleanup:
    return err;
}


static err_t handle_mnemonic_pop(ctx_t* ctx, const lifted_op_t* ops, size_t ops_amount) {
    err_t err = SUCCESS;
    CHECK(ops_amount == 1);

    pis_size_t operand_size = lifted_op_size(&ops[0]);
    pis_op_t popped_value = {};
    CHECK_RETHROW(pop(ctx, operand_size, &popped_value));

    CHECK_RETHROW(lifted_op_write(ctx, &ops[0], &popped_value));
cleanup:
    return err;
}

static err_t handle_mnemonic_ret(ctx_t* ctx, const lifted_op_t* ops, size_t ops_amount) {
    err_t err = SUCCESS;
    CHECK(ops_amount == 0);
    UNUSED(ops);

    pis_size_t operand_size = ctx->stack_addr_size;
    pis_op_t popped_value = {};
    CHECK_RETHROW(pop(ctx, operand_size, &popped_value));

    PIS_EMIT(&ctx->args->result, PIS_INSN1(PIS_OPCODE_JMP_RET, popped_value));

cleanup:
    return err;
}

static err_t handle_mnemonic_push(ctx_t* ctx, const lifted_op_t* ops, size_t ops_amount) {
    err_t err = SUCCESS;
    CHECK(ops_amount == 1);

    pis_op_t to_push = {};
    CHECK_RETHROW(lifted_op_read(ctx, &ops[0], &to_push));
    CHECK_RETHROW(push(ctx, &to_push));
cleanup:
    return err;
}

static err_t handle_mnemonic_stos(ctx_t* ctx, const lifted_op_t* ops, size_t ops_amount) {
    err_t err = SUCCESS;

    // we expect 1 implicit operand
    CHECK(ops_amount == 1);
    CHECK(ops[0].kind == LIFTED_OP_KIND_IMPLICIT);

    rep_ctx_t rep_ctx = {};
    CHECK_RETHROW(rep_begin(ctx, &rep_ctx));

    pis_size_t operand_size = ops[0].implicit.size;

    pis_op_t ax = reg_to_op_resize(X86_RAX, operand_size);
    pis_op_t di = reg_to_op_resize(X86_RDI, ctx->addr_size);

    // copy one chunk from ax to [di].
    PIS_EMIT(&ctx->args->result, PIS_INSN2(PIS_OPCODE_STORE, di, ax));

    // increment di
    pis_op_t increment = PIS_OPERAND_IMM(pis_size_to_bytes(operand_size), ctx->addr_size);
    PIS_EMIT(&ctx->args->result, PIS_INSN3(PIS_OPCODE_ADD, di, di, increment));

    CHECK_RETHROW(rep_end(ctx, &rep_ctx));
cleanup:
    return err;
}

static err_t handle_mnemonic_movs(ctx_t* ctx, const lifted_op_t* ops, size_t ops_amount) {
    err_t err = SUCCESS;

    // we expect 1 implicit operand
    CHECK(ops_amount == 1);
    CHECK(ops[0].kind == LIFTED_OP_KIND_IMPLICIT);

    rep_ctx_t rep_ctx = {};
    CHECK_RETHROW(rep_begin(ctx, &rep_ctx));

    pis_size_t operand_size = ops[0].implicit.size;

    pis_op_t si = reg_to_op_resize(X86_RSI, ctx->addr_size);
    pis_op_t di = reg_to_op_resize(X86_RDI, ctx->addr_size);

    // copy one chunk from [si] to [di].
    pis_op_t byte_tmp = TMP_ALLOC(&ctx->tmp_allocator, operand_size);
    PIS_EMIT(&ctx->args->result, PIS_INSN2(PIS_OPCODE_LOAD, byte_tmp, si));
    PIS_EMIT(&ctx->args->result, PIS_INSN2(PIS_OPCODE_STORE, di, byte_tmp));

    // increment si and di
    pis_op_t increment = PIS_OPERAND_IMM(pis_size_to_bytes(operand_size), ctx->addr_size);
    PIS_EMIT(&ctx->args->result, PIS_INSN3(PIS_OPCODE_ADD, si, si, increment));
    PIS_EMIT(&ctx->args->result, PIS_INSN3(PIS_OPCODE_ADD, di, di, increment));

    CHECK_RETHROW(rep_end(ctx, &rep_ctx));
cleanup:
    return err;
}

typedef struct {
    mnemonic_handler_t handler;
    u8 allow_lock_prefix : 1;
    u8 allow_repz_or_rep_prefix : 1;
    u8 allow_repnz_or_bnd_prefix : 1;
} PACKED mnemonic_info_t;

static const mnemonic_info_t mnemonics_table[MNEMONIC_MAX + 1] = {
    [MNEMONIC_SHR] =
        {
            .handler = handle_mnemonic_shr,
            .allow_lock_prefix = false,
            .allow_repz_or_rep_prefix = false,
            .allow_repnz_or_bnd_prefix = false,
        },
    [MNEMONIC_XOR] =
        {
            .handler = handle_mnemonic_xor,
            .allow_lock_prefix = false,
            .allow_repz_or_rep_prefix = false,
            .allow_repnz_or_bnd_prefix = false,
        },
    [MNEMONIC_ADD] =
        {
            .handler = handle_mnemonic_add,
            .allow_lock_prefix = false,
            .allow_repz_or_rep_prefix = false,
            .allow_repnz_or_bnd_prefix = false,
        },
    [MNEMONIC_AND] =
        {
            .handler = handle_mnemonic_and,
            .allow_lock_prefix = false,
            .allow_repz_or_rep_prefix = false,
            .allow_repnz_or_bnd_prefix = false,
        },
    [MNEMONIC_SUB] =
        {
            .handler = handle_mnemonic_sub,
            .allow_lock_prefix = false,
            .allow_repz_or_rep_prefix = false,
            .allow_repnz_or_bnd_prefix = false,
        },
    [MNEMONIC_OR] =
        {
            .handler = handle_mnemonic_or,
            .allow_lock_prefix = false,
            .allow_repz_or_rep_prefix = false,
            .allow_repnz_or_bnd_prefix = false,
        },
    [MNEMONIC_MOV] =
        {
            .handler = handle_mnemonic_mov,
            .allow_lock_prefix = false,
            .allow_repz_or_rep_prefix = false,
            .allow_repnz_or_bnd_prefix = false,
        },
    [MNEMONIC_ENDBR] =
        {
            .handler = handle_mnemonic_endbr,
            .allow_lock_prefix = false,
            .allow_repz_or_rep_prefix = true,
            .allow_repnz_or_bnd_prefix = false,
        },
    [MNEMONIC_POP] =
        {
            .handler = handle_mnemonic_pop,
            .allow_lock_prefix = false,
            .allow_repz_or_rep_prefix = false,
            .allow_repnz_or_bnd_prefix = false,
        },
    [MNEMONIC_PUSH] =
        {
            .handler = handle_mnemonic_push,
            .allow_lock_prefix = false,
            .allow_repz_or_rep_prefix = false,
            .allow_repnz_or_bnd_prefix = false,
        },
    [MNEMONIC_LEA] =
        {
            .handler = handle_mnemonic_lea,
            .allow_lock_prefix = false,
            .allow_repz_or_rep_prefix = false,
            .allow_repnz_or_bnd_prefix = false,
        },
    [MNEMONIC_STOS] =
        {
            .handler = handle_mnemonic_stos,
            .allow_lock_prefix = false,
            .allow_repz_or_rep_prefix = true,
            .allow_repnz_or_bnd_prefix = false,
        },
    [MNEMONIC_CMP] =
        {
            .handler = handle_mnemonic_cmp,
            .allow_lock_prefix = false,
            .allow_repz_or_rep_prefix = false,
            .allow_repnz_or_bnd_prefix = false,
        },
    [MNEMONIC_JCC] =
        {
            .handler = handle_mnemonic_jcc,
            .allow_lock_prefix = false,
            .allow_repz_or_rep_prefix = false,
            .allow_repnz_or_bnd_prefix = false,
        },
    [MNEMONIC_CALL] =
        {
            .handler = handle_mnemonic_call,
            .allow_lock_prefix = false,
            .allow_repz_or_rep_prefix = false,
            .allow_repnz_or_bnd_prefix = false,
        },
    [MNEMONIC_JMP] =
        {
            .handler = handle_mnemonic_jmp,
            .allow_lock_prefix = false,
            .allow_repz_or_rep_prefix = false,
            .allow_repnz_or_bnd_prefix = false,
        },
    [MNEMONIC_TEST] =
        {
            .handler = handle_mnemonic_test,
            .allow_lock_prefix = false,
            .allow_repz_or_rep_prefix = false,
            .allow_repnz_or_bnd_prefix = false,
        },
    [MNEMONIC_DEC] =
        {
            .handler = handle_mnemonic_dec,
            .allow_lock_prefix = false,
            .allow_repz_or_rep_prefix = false,
            .allow_repnz_or_bnd_prefix = false,
        },
    [MNEMONIC_CMOVCC] =
        {
            .handler = handle_mnemonic_cmovcc,
            .allow_lock_prefix = false,
            .allow_repz_or_rep_prefix = false,
            .allow_repnz_or_bnd_prefix = false,
        },
    [MNEMONIC_MOVZX] =
        {
            .handler = handle_mnemonic_movzx,
            .allow_lock_prefix = false,
            .allow_repz_or_rep_prefix = false,
            .allow_repnz_or_bnd_prefix = false,
        },
    [MNEMONIC_BT] =
        {
            .handler = handle_mnemonic_bt,
            .allow_lock_prefix = false,
            .allow_repz_or_rep_prefix = false,
            .allow_repnz_or_bnd_prefix = false,
        },
    [MNEMONIC_SBB] =
        {
            .handler = handle_mnemonic_sbb,
            .allow_lock_prefix = false,
            .allow_repz_or_rep_prefix = false,
            .allow_repnz_or_bnd_prefix = false,
        },
    [MNEMONIC_INC] =
        {
            .handler = handle_mnemonic_inc,
            .allow_lock_prefix = false,
            .allow_repz_or_rep_prefix = false,
            .allow_repnz_or_bnd_prefix = false,
        },
    [MNEMONIC_MOVSXD] =
        {
            .handler = handle_mnemonic_movsxd,
            .allow_lock_prefix = false,
            .allow_repz_or_rep_prefix = false,
            .allow_repnz_or_bnd_prefix = false,
        },
    [MNEMONIC_RET] =
        {
            .handler = handle_mnemonic_ret,
            .allow_lock_prefix = false,
            .allow_repz_or_rep_prefix = false,
            .allow_repnz_or_bnd_prefix = false,
        },
    [MNEMONIC_NOP] =
        {
            .handler = handle_mnemonic_nop,
            .allow_lock_prefix = false,
            .allow_repz_or_rep_prefix = false,
            .allow_repnz_or_bnd_prefix = false,
        },
    [MNEMONIC_HLT] =
        {
            .handler = handle_mnemonic_hlt,
            .allow_lock_prefix = false,
            .allow_repz_or_rep_prefix = false,
            .allow_repnz_or_bnd_prefix = false,
        },
    [MNEMONIC_SAR] =
        {
            .handler = handle_mnemonic_sar,
            .allow_lock_prefix = false,
            .allow_repz_or_rep_prefix = false,
            .allow_repnz_or_bnd_prefix = false,
        },
    [MNEMONIC_SHL] =
        {
            .handler = handle_mnemonic_shl,
            .allow_lock_prefix = false,
            .allow_repz_or_rep_prefix = false,
            .allow_repnz_or_bnd_prefix = false,
        },
    [MNEMONIC_IMUL] =
        {
            .handler = handle_mnemonic_imul,
            .allow_lock_prefix = false,
            .allow_repz_or_rep_prefix = false,
            .allow_repnz_or_bnd_prefix = false,
        },
    [MNEMONIC_MOVS] =
        {
            .handler = handle_mnemonic_movs,
            .allow_lock_prefix = false,
            .allow_repz_or_rep_prefix = true,
            .allow_repnz_or_bnd_prefix = false,
        },
    [MNEMONIC_NOT] =
        {
            .handler = handle_mnemonic_not,
            .allow_lock_prefix = false,
            .allow_repz_or_rep_prefix = false,
            .allow_repnz_or_bnd_prefix = false,
        },
    [MNEMONIC_NEG] =
        {
            .handler = handle_mnemonic_neg,
            .allow_lock_prefix = false,
            .allow_repz_or_rep_prefix = false,
            .allow_repnz_or_bnd_prefix = false,
        },
    [MNEMONIC_MOVSX] =
        {
            .handler = handle_mnemonic_movsx,
            .allow_lock_prefix = false,
            .allow_repz_or_rep_prefix = false,
            .allow_repnz_or_bnd_prefix = false,
        },
    [MNEMONIC_SETCC] =
        {
            .handler = handle_mnemonic_setcc,
            .allow_lock_prefix = false,
            .allow_repz_or_rep_prefix = false,
            .allow_repnz_or_bnd_prefix = false,
        },
    [MNEMONIC_ROL] =
        {
            .handler = handle_mnemonic_rol,
            .allow_lock_prefix = false,
            .allow_repz_or_rep_prefix = false,
            .allow_repnz_or_bnd_prefix = false,
        },
    [MNEMONIC_DIV] =
        {
            .handler = handle_mnemonic_div,
            .allow_lock_prefix = false,
            .allow_repz_or_rep_prefix = false,
            .allow_repnz_or_bnd_prefix = false,
        },
    [MNEMONIC_MUL] =
        {
            .handler = handle_mnemonic_mul,
            .allow_lock_prefix = false,
            .allow_repz_or_rep_prefix = false,
            .allow_repnz_or_bnd_prefix = false,
        },
    [MNEMONIC_ADC] =
        {
            .handler = handle_mnemonic_adc,
            .allow_lock_prefix = false,
            .allow_repz_or_rep_prefix = false,
            .allow_repnz_or_bnd_prefix = false,
        },
    [MNEMONIC_XCHG] =
        {
            .handler = handle_mnemonic_xchg,
            .allow_lock_prefix = false,
            .allow_repz_or_rep_prefix = false,
            .allow_repnz_or_bnd_prefix = false,
        },
    [MNEMONIC_CWD] =
        {
            .handler = handle_mnemonic_cwd,
            .allow_lock_prefix = false,
            .allow_repz_or_rep_prefix = false,
            .allow_repnz_or_bnd_prefix = false,
        },
    [MNEMONIC_IDIV] =
        {
            .handler = handle_mnemonic_idiv,
            .allow_lock_prefix = false,
            .allow_repz_or_rep_prefix = false,
            .allow_repnz_or_bnd_prefix = false,
        },
    [MNEMONIC_SHLD] =
        {
            .handler = handle_mnemonic_shld,
            .allow_lock_prefix = false,
            .allow_repz_or_rep_prefix = false,
            .allow_repnz_or_bnd_prefix = false,
        },
    [MNEMONIC_SHRD] =
        {
            .handler = handle_mnemonic_shrd,
            .allow_lock_prefix = false,
            .allow_repz_or_rep_prefix = false,
            .allow_repnz_or_bnd_prefix = false,
        },
};

static err_t lift_mnemonic(
    ctx_t* ctx,
    u32 mnemonic,
    mnemonic_info_t mnemonic_info,
    const lifted_op_t* ops,
    size_t ops_amount
) {
    err_t err = SUCCESS;

    // under some configurations, this argument is unused, so tell the compiler that we are ok with
    // this.
    UNUSED(mnemonic);

    // make sure that the group 1 prefix of the instruction is allowed for this mnemonic.
    switch (ctx->prefixes.legacy.by_group[LEGACY_PREFIX_GROUP_1]) {
        case LEGACY_PREFIX_LOCK:
            CHECK_TRACE_CODE(
                mnemonic_info.allow_lock_prefix,
                PIS_ERR_UNSUPPORTED_INSN,
                "mnemonic %u is not allowed with a lock prefix",
                mnemonic
            );
            break;
        case LEGACY_PREFIX_REPZ_OR_REP:
            CHECK_TRACE_CODE(
                mnemonic_info.allow_repz_or_rep_prefix,
                PIS_ERR_UNSUPPORTED_INSN,
                "mnemonic %u is not allowed with a repz/rep prefix",
                mnemonic
            );
            break;
        case LEGACY_PREFIX_REPNZ_OR_BND:
            CHECK_TRACE_CODE(
                mnemonic_info.allow_repnz_or_bnd_prefix,
                PIS_ERR_UNSUPPORTED_INSN,
                "mnemonic %u is not allowed with a repnz/bnd prefix",
                mnemonic
            );
            break;
        default:
            break;
    }

    CHECK_RETHROW(mnemonic_info.handler(ctx, ops, ops_amount));

cleanup:
    return err;
}

static err_t
    lift_regular_insn_info(ctx_t* ctx, uint8_t opcode_byte, const regular_insn_info_t* insn_info) {
    err_t err = SUCCESS;

    CHECK_TRACE_CODE(
        insn_info->mnemonic != MNEMONIC_UNSUPPORTED,
        PIS_ERR_UNSUPPORTED_INSN,
        "unsupported opcode byte 0x%x",
        opcode_byte
    );

    lifted_op_t lifted_ops[X86_TABLES_INSN_MAX_OPS] = {};
    const uint8_t* op_info_indexes = &laid_out_ops_infos_table[insn_info->first_op_index];
    size_t ops_amount = insn_info->ops_amount;
    u32 mnemonic = insn_info->mnemonic;
    for (size_t i = 0; i < ops_amount; i++) {
        uint8_t op_info_index = op_info_indexes[i];
        const op_info_t* op_info = &op_infos_table[op_info_index];
        CHECK_RETHROW(lift_op(ctx, opcode_byte, op_info, &lifted_ops[i]));
    }
    mnemonic_info_t mnemonic_info = mnemonics_table[mnemonic];
    CHECK_TRACE_CODE(
        mnemonic_info.handler != NULL,
        PIS_ERR_UNSUPPORTED_INSN,
        "unsupported mnemonic %d",
        mnemonic
    );
    CHECK_RETHROW(lift_mnemonic(ctx, mnemonic, mnemonic_info, lifted_ops, ops_amount));
cleanup:
    return err;
}

static err_t lift_modrm_reg_opcode_ext_insn_info(
    ctx_t* ctx, u8 opcode_byte, const modrm_reg_opcode_ext_table_t* table
) {
    err_t err = SUCCESS;

    modrm_t modrm = {};
    CHECK_RETHROW(get_or_fetch_modrm(ctx, &modrm));

    CHECK_RETHROW(lift_regular_insn_info(ctx, opcode_byte, &table->by_reg_value[modrm.reg]));

cleanup:
    return err;
}

static err_t lift_opcode_byte(ctx_t* ctx, u8 opcode_byte, const insn_info_t* opcode_byte_table) {
    err_t err = SUCCESS;
    const insn_info_t* insn_info = &opcode_byte_table[opcode_byte];
    if (insn_info->mnemonic == MNEMONIC_MODRM_REG_OPCODE_EXT) {
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
static err_t post_prefixes_lift(ctx_t* ctx) {
    err_t err = SUCCESS;

    u8 first_opcode_byte = 0;
    CHECK_RETHROW(cursor_next_1(&ctx->args->machine_code, &first_opcode_byte));
    if (first_opcode_byte == 0x0f) {
        // 2 or 3 byte opcode
        u8 second_opcode_byte = 0;
        CHECK_RETHROW(cursor_next_1(&ctx->args->machine_code, &second_opcode_byte));
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

/// lift the next instruction.
err_t pis_x86_lift(pis_lift_args_t* args, pis_x86_cpumode_t cpumode) {
    err_t err = SUCCESS;

    size_t start_index = cursor_index(&args->machine_code);

    ctx_t ctx = {
        .args = args,
        .prefixes = {},
        .cpumode = cpumode,
        .tmp_allocator = TMP_ALLOCATOR_INIT,
        .addr_size = 0,
        .stack_addr_size = 0,
        .sp = {},
        .has_modrm = false,
        .modrm_byte = 0,
    };

    CHECK_RETHROW(parse_prefixes(args, cpumode, &ctx.prefixes));

    // initialize some fields after fetching prefixes
    ctx.addr_size = get_effective_addr_size(cpumode, &ctx.prefixes);
    ctx.stack_addr_size = get_effective_stack_addr_size(cpumode);
    ctx.sp = reg_to_op_resize(X86_RSP, ctx.stack_addr_size);

    CHECK_RETHROW(post_prefixes_lift(&ctx));

    args->result.machine_insn_len = cursor_index(&args->machine_code) - start_index;

    // make sure that we actually processed any bytes
    CHECK(args->result.machine_insn_len > 0);

cleanup:
    return err;
}

err_t pis_lifter_x86_64(pis_lift_args_t* args) {
    err_t err = SUCCESS;

    CHECK_RETHROW(pis_x86_lift(args, PIS_X86_CPUMODE_64_BIT));

cleanup:
    return err;
}

err_t pis_lifter_i686(pis_lift_args_t* args) {
    err_t err = SUCCESS;

    CHECK_RETHROW(pis_x86_lift(args, PIS_X86_CPUMODE_32_BIT));

cleanup:
    return err;
}

const pis_arch_def_t pis_arch_def_x86_64 = {
    .lifter = pis_lifter_x86_64,
    .endianness = PIS_ENDIANNESS_LITTLE,
    .return_value = &X86_RAX,
    .params =
        {
            &X86_RDI,
            &X86_RSI,
            &X86_RDX,
        },
};

const pis_arch_def_t pis_arch_def_i686 = {
    .lifter = pis_lifter_i686,
    .endianness = PIS_ENDIANNESS_LITTLE,
    .return_value = &X86_EAX,
    .params =
        {
            &X86_EAX,
            &X86_EDX,
            &X86_ECX,
        },
};
