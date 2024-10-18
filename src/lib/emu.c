#include "emu.h"
#include "emu/mem_storage.h"
#include "errors.h"
#include "except.h"
#include "pis.h"
#include "utils.h"
#include <endian.h>
#include <limits.h>
#include <string.h>

typedef u64 (*binary_operator_fn_t)(u64 lhs, u64 rhs);
typedef i64 (*signed_binary_operator_fn_t)(i64 lhs, i64 rhs);

typedef u64 (*unary_operator_fn_t)(u64 x);

void pis_emu_init(pis_emu_t* emu, pis_endianness_t endianness) {
    memset(emu, 0, sizeof(pis_emu_t));
    emu->endianness = endianness;
}

static err_t
    read_byte_off(const pis_emu_t* emu, const pis_addr_t* addr, u64 offset, u8* byte_value) {
    err_t err = SUCCESS;

    pis_addr_t new_addr = {};
    CHECK_RETHROW(pis_addr_add(addr, offset, &new_addr));

    CHECK_RETHROW(pis_emu_storage_read_byte(&emu->storage, &new_addr, byte_value));

cleanup:
    return err;
}

static err_t write_byte_off(pis_emu_t* emu, const pis_addr_t* addr, u64 offset, u8 byte_value) {
    err_t err = SUCCESS;

    pis_addr_t new_addr = {};
    CHECK_RETHROW(pis_addr_add(addr, offset, &new_addr));

    CHECK_RETHROW(pis_emu_storage_write_byte(&emu->storage, &new_addr, byte_value));

cleanup:
    return err;
}

static err_t read_bytes(const pis_emu_t* emu, const pis_addr_t* addr, u8* bytes, size_t len) {
    err_t err = SUCCESS;

    for (size_t i = 0; i < len; i++) {
        CHECK_RETHROW(read_byte_off(emu, addr, i, &bytes[i]));
    }

cleanup:
    return err;
}

static err_t write_bytes(pis_emu_t* emu, const pis_addr_t* addr, const u8* bytes, size_t len) {
    err_t err = SUCCESS;

    for (size_t i = 0; i < len; i++) {
        CHECK_RETHROW(write_byte_off(emu, addr, i, bytes[i]));
    }

cleanup:
    return err;
}

static err_t read_mem_bytes(const pis_emu_t* emu, u64 addr, u8* bytes, size_t len) {
    err_t err = SUCCESS;

    CHECK_CODE(addr <= UINT64_MAX - len, PIS_ERR_ADDR_OVERFLOW);

    for (size_t i = 0; i < len; i++) {
        CHECK_RETHROW(pis_emu_mem_storage_read_byte(&emu->mem_storage, addr + i, &bytes[i]));
    }

cleanup:
    return err;
}

static err_t write_mem_bytes(pis_emu_t* emu, u64 addr, const u8* bytes, size_t len) {
    err_t err = SUCCESS;

    CHECK_CODE(addr <= UINT64_MAX - len, PIS_ERR_ADDR_OVERFLOW);

    for (size_t i = 0; i < len; i++) {
        CHECK_RETHROW(pis_emu_mem_storage_write_byte(&emu->mem_storage, addr + i, bytes[i]));
    }

cleanup:
    return err;
}

typedef union {
    u8 bytes[sizeof(u64)];
    u64 u64;
} u64_bytes_t;

static void endianness_swap_bytes_if_needed(const pis_emu_t* emu, u8* bytes, size_t len) {
    if (emu->endianness != pis_endianness_native()) {
        // endianness is not the same as native, reverse the bytes
        for (size_t i = 0; i < len / 2; i++) {
            u8 tmp = bytes[i];
            bytes[i] = bytes[len - i - 1];
            bytes[len - i - 1] = tmp;
        }
    }
}

err_t pis_emu_read_operand(const pis_emu_t* emu, const pis_operand_t* operand, u64* operand_value) {
    err_t err = SUCCESS;

    if (operand->addr.space == PIS_SPACE_CONST) {
        u64 const_value = operand->addr.offset;
        u64 max_value = pis_operand_size_max_unsigned_value(operand->size);
        CHECK(const_value <= max_value);
        *operand_value = const_value;
    } else {
        size_t operand_size_in_bytes = pis_operand_size_to_bytes(operand->size);

        u64_bytes_t converter = {.u64 = 0};
        CHECK(operand_size_in_bytes <= ARRAY_SIZE(converter.bytes));
        CHECK_RETHROW(read_bytes(emu, &operand->addr, converter.bytes, operand_size_in_bytes));

        endianness_swap_bytes_if_needed(emu, converter.bytes, operand_size_in_bytes);

        *operand_value = converter.u64;
    }

cleanup:
    return err;
}

err_t pis_emu_write_operand(pis_emu_t* emu, const pis_operand_t* operand, u64 value) {
    err_t err = SUCCESS;

    size_t operand_size_in_bytes = pis_operand_size_to_bytes(operand->size);

    u64_bytes_t converter = {.u64 = value};
    CHECK(operand_size_in_bytes <= ARRAY_SIZE(converter.bytes));
    endianness_swap_bytes_if_needed(emu, converter.bytes, operand_size_in_bytes);

    CHECK_RETHROW(write_bytes(emu, &operand->addr, converter.bytes, operand_size_in_bytes));

cleanup:
    return err;
}

err_t pis_emu_read_mem_value(
    const pis_emu_t* emu, u64 addr, pis_operand_size_t value_size, u64* value
) {
    err_t err = SUCCESS;

    size_t operand_size_in_bytes = pis_operand_size_to_bytes(value_size);

    u64_bytes_t converter = {.u64 = 0};
    CHECK(operand_size_in_bytes <= ARRAY_SIZE(converter.bytes));
    CHECK_RETHROW(read_mem_bytes(emu, addr, converter.bytes, operand_size_in_bytes));

    endianness_swap_bytes_if_needed(emu, converter.bytes, operand_size_in_bytes);

    *value = converter.u64;

cleanup:
    return err;
}

err_t pis_emu_write_mem_value(pis_emu_t* emu, u64 addr, u64 value, pis_operand_size_t value_size) {
    err_t err = SUCCESS;

    size_t operand_size_in_bytes = pis_operand_size_to_bytes(value_size);

    u64_bytes_t converter = {.u64 = value};
    CHECK(operand_size_in_bytes <= ARRAY_SIZE(converter.bytes));
    endianness_swap_bytes_if_needed(emu, converter.bytes, operand_size_in_bytes);

    CHECK_RETHROW(write_mem_bytes(emu, addr, converter.bytes, operand_size_in_bytes));

cleanup:
    return err;
}

static i64 sign_extend_value(u64 value, pis_operand_size_t value_size) {
    u32 value_size_in_bits = pis_operand_size_to_bits(value_size);
    u64 sign_bit = value >> (value_size_in_bits - 1);
    if (!sign_bit) {
        return value;
    }

    // a mask for the bits that are actually used in the value
    u64 used_bits_mask = pis_operand_size_max_unsigned_value(value_size);
    u64 added_bits = UINT64_MAX & (~used_bits_mask);

    u64 result = value | added_bits;
    return (i64) result;
}

err_t pis_emu_read_operand_signed(
    const pis_emu_t* emu, const pis_operand_t* operand, i64* operand_value
) {
    err_t err = SUCCESS;
    u64 unsigned_value = 0;
    CHECK_RETHROW(pis_emu_read_operand(emu, operand, &unsigned_value));

    *operand_value = sign_extend_value(unsigned_value, operand->size);

cleanup:
    return err;
}

static err_t run_binary_operator(pis_emu_t* emu, const pis_insn_t* insn, binary_operator_fn_t fn) {
    err_t err = SUCCESS;
    CHECK_CODE(insn->operands_amount == 3, PIS_ERR_EMU_OPCODE_WRONG_OPERANDS_AMOUNT);

    // make sure that all operands are of the same size
    CHECK_TRACE_CODE(
        insn->operands[0].size == insn->operands[1].size &&
            insn->operands[1].size == insn->operands[2].size,
        PIS_ERR_EMU_OPERAND_SIZE_MISMATCH,
        "operand size mismatch in binary operator %s, operand sizes: %u %u %u",
        pis_opcode_to_str(insn->opcode),
        insn->operands[0].size,
        insn->operands[1].size,
        insn->operands[2].size
    );

    u64 lhs = 0;
    CHECK_RETHROW(pis_emu_read_operand(emu, &insn->operands[1], &lhs));
    u64 rhs = 0;
    CHECK_RETHROW(pis_emu_read_operand(emu, &insn->operands[2], &rhs));

    u64 result = fn(lhs, rhs);
    CHECK_RETHROW(pis_emu_write_operand(emu, &insn->operands[0], result));
cleanup:
    return err;
}

static err_t run_unary_operator(pis_emu_t* emu, const pis_insn_t* insn, unary_operator_fn_t fn) {
    err_t err = SUCCESS;
    CHECK_CODE(insn->operands_amount == 2, PIS_ERR_EMU_OPCODE_WRONG_OPERANDS_AMOUNT);

    // make sure that all operands are of the same size
    CHECK_TRACE_CODE(
        insn->operands[0].size == insn->operands[1].size,
        PIS_ERR_EMU_OPERAND_SIZE_MISMATCH,
        "operand size mismatch in unary operator %s, operand sizes: %u %u",
        pis_opcode_to_str(insn->opcode),
        insn->operands[0].size,
        insn->operands[1].size
    );

    u64 x = 0;
    CHECK_RETHROW(pis_emu_read_operand(emu, &insn->operands[2], &x));

    u64 result = fn(x);
    CHECK_RETHROW(pis_emu_write_operand(emu, &insn->operands[0], result));
cleanup:
    return err;
}

static err_t run_signed_binary_operator(
    pis_emu_t* emu, const pis_insn_t* insn, signed_binary_operator_fn_t fn
) {
    err_t err = SUCCESS;
    CHECK_CODE(insn->operands_amount == 3, PIS_ERR_EMU_OPCODE_WRONG_OPERANDS_AMOUNT);

    // make sure that all operands are of the same size
    CHECK_CODE(
        insn->operands[0].size == insn->operands[1].size &&
            insn->operands[1].size == insn->operands[2].size,
        PIS_ERR_EMU_OPERAND_SIZE_MISMATCH
    );

    i64 lhs = 0;
    CHECK_RETHROW(pis_emu_read_operand_signed(emu, &insn->operands[1], &lhs));
    i64 rhs = 0;
    CHECK_RETHROW(pis_emu_read_operand_signed(emu, &insn->operands[2], &rhs));

    i64 result = fn(lhs, rhs);
    CHECK_RETHROW(pis_emu_write_operand(emu, &insn->operands[0], (u64) result));
cleanup:
    return err;
}

#define DEFINE_BINARY_OPERATOR(NAME, OP)                                                           \
    static u64 binary_operator_##NAME(u64 lhs, u64 rhs) {                                          \
        return lhs OP rhs;                                                                         \
    }

#define DEFINE_SIGNED_BINARY_OPERATOR(NAME, OP)                                                    \
    static i64 signed_binary_operator_##NAME(i64 lhs, i64 rhs) {                                   \
        return lhs OP rhs;                                                                         \
    }

DEFINE_BINARY_OPERATOR(add, +);
DEFINE_BINARY_OPERATOR(sub, -);
DEFINE_BINARY_OPERATOR(xor, ^);
DEFINE_BINARY_OPERATOR(and, &);
DEFINE_BINARY_OPERATOR(or, |);
DEFINE_BINARY_OPERATOR(shl, <<);
DEFINE_BINARY_OPERATOR(shr, >>);
DEFINE_BINARY_OPERATOR(mul, *);
DEFINE_BINARY_OPERATOR(div, /);
DEFINE_BINARY_OPERATOR(rem, %);
DEFINE_SIGNED_BINARY_OPERATOR(mul, *);
DEFINE_SIGNED_BINARY_OPERATOR(sar, >>);

#define DEFINE_UNARY_OPERATOR(NAME, OP)                                                            \
    static u64 unary_operator_##NAME(u64 x) {                                                      \
        return OP x;                                                                               \
    }

DEFINE_UNARY_OPERATOR(not, ~);
DEFINE_UNARY_OPERATOR(neg, -);

void div128(u64 dividend_high, u64 dividend_low, u64 divisor, u64* quotient, u64* rem) {
    // compute initial quotient and remainder
    u64 initial_quot_high = dividend_high / divisor;
    u64 initial_rem_high = dividend_high % divisor;

    // combine remainder from high part with the upper 32 bits of the low part of the dividend
    u64 upper_dividend_low = (initial_rem_high << 32) | (dividend_low >> 32);
    u64 quot_mid = upper_dividend_low / divisor;
    u64 rem_mid = upper_dividend_low % divisor;

    // combine remainder with the lower 32 bits of the low part of the dividend
    u64 lower_dividend_low = (rem_mid << 32) | (dividend_low & 0xFFFFFFFF);
    u64 final_quot_low = lower_dividend_low / divisor;
    *rem = lower_dividend_low % divisor;

    // combine the three parts of the quotient
    *quotient = (initial_quot_high << 32) | (quot_mid << 32) | final_quot_low;
}

err_t pis_emu_run_one(pis_emu_t* emu, const pis_insn_t* insn) {
    err_t err = SUCCESS;
    switch (insn->opcode) {
    case PIS_OPCODE_MOVE: {
        CHECK_CODE(insn->operands_amount == 2, PIS_ERR_EMU_OPCODE_WRONG_OPERANDS_AMOUNT);

        // check operand sizes
        CHECK_CODE(
            insn->operands[0].size == insn->operands[1].size,
            PIS_ERR_EMU_OPERAND_SIZE_MISMATCH
        );

        u64 value = 0;
        CHECK_RETHROW(pis_emu_read_operand(emu, &insn->operands[1], &value));

        CHECK_RETHROW(pis_emu_write_operand(emu, &insn->operands[0], value));

        break;
    }
    case PIS_OPCODE_ADD:
        CHECK_RETHROW(run_binary_operator(emu, insn, binary_operator_add));
        break;
    case PIS_OPCODE_SUB:
        CHECK_RETHROW(run_binary_operator(emu, insn, binary_operator_sub));
        break;
    case PIS_OPCODE_XOR:
        CHECK_RETHROW(run_binary_operator(emu, insn, binary_operator_xor));
        break;
    case PIS_OPCODE_AND:
        CHECK_RETHROW(run_binary_operator(emu, insn, binary_operator_and));
        break;
    case PIS_OPCODE_OR:
        CHECK_RETHROW(run_binary_operator(emu, insn, binary_operator_or));
        break;
    case PIS_OPCODE_SHIFT_LEFT:
        CHECK_RETHROW(run_binary_operator(emu, insn, binary_operator_shl));
        break;
    case PIS_OPCODE_STORE: {
        u64 value = 0;
        CHECK_RETHROW(pis_emu_read_operand(emu, &insn->operands[1], &value));

        u64 addr = 0;
        CHECK_RETHROW(pis_emu_read_operand(emu, &insn->operands[0], &addr));

        CHECK_RETHROW(pis_emu_write_mem_value(emu, addr, value, insn->operands[1].size));

        break;
    }
    case PIS_OPCODE_LOAD: {
        u64 addr = 0;
        CHECK_RETHROW(pis_emu_read_operand(emu, &insn->operands[1], &addr));

        u64 value = 0;
        CHECK_RETHROW(pis_emu_read_mem_value(emu, addr, insn->operands[0].size, &value));

        CHECK_RETHROW(pis_emu_write_operand(emu, &insn->operands[0], value));

        break;
    }
    case PIS_OPCODE_UNSIGNED_CARRY: {
        CHECK_CODE(insn->operands_amount == 3, PIS_ERR_EMU_OPCODE_WRONG_OPERANDS_AMOUNT);

        // check operand sizes
        CHECK_CODE(
            insn->operands[1].size == insn->operands[2].size,
            PIS_ERR_EMU_OPERAND_SIZE_MISMATCH
        );
        CHECK_CODE(insn->operands[0].size == PIS_OPERAND_SIZE_1, PIS_ERR_EMU_OPERAND_SIZE_MISMATCH);

        u64 lhs = 0;
        CHECK_RETHROW(pis_emu_read_operand(emu, &insn->operands[1], &lhs));
        u64 rhs = 0;
        CHECK_RETHROW(pis_emu_read_operand(emu, &insn->operands[2], &rhs));

        pis_operand_size_t src_operand_size = insn->operands[1].size;
        u64 max_value = pis_operand_size_max_unsigned_value(src_operand_size);
        bool is_overflow = lhs > max_value - rhs;

        CHECK_RETHROW(pis_emu_write_operand(emu, &insn->operands[0], (u64) is_overflow));

        break;
    }
    case PIS_OPCODE_SIGNED_CARRY: {
        CHECK_CODE(insn->operands_amount == 3, PIS_ERR_EMU_OPCODE_WRONG_OPERANDS_AMOUNT);

        // check operand sizes
        CHECK_CODE(
            insn->operands[1].size == insn->operands[2].size,
            PIS_ERR_EMU_OPERAND_SIZE_MISMATCH
        );
        CHECK_CODE(insn->operands[0].size == PIS_OPERAND_SIZE_1, PIS_ERR_EMU_OPERAND_SIZE_MISMATCH);

        u64 lhs = 0;
        CHECK_RETHROW(pis_emu_read_operand(emu, &insn->operands[1], &lhs));

        u64 rhs = 0;
        CHECK_RETHROW(pis_emu_read_operand(emu, &insn->operands[2], &rhs));

        u64 result = lhs + rhs;

        pis_operand_size_t src_operand_size = insn->operands[1].size;
        u32 src_operand_size_in_bits = pis_operand_size_to_bits(src_operand_size);
        u32 sign_bit_shift_amount = src_operand_size_in_bits - 1;

        u64 lhs_sign_bit = (lhs >> sign_bit_shift_amount) & 1;
        u64 rhs_sign_bit = (rhs >> sign_bit_shift_amount) & 1;
        u64 result_sign_bit = (result >> sign_bit_shift_amount) & 1;

        // signed overflow occurs when adding 2 values of the same sign and getting a result of a
        // different sign.
        bool is_overflow = lhs_sign_bit == rhs_sign_bit && lhs_sign_bit != result_sign_bit;

        CHECK_RETHROW(pis_emu_write_operand(emu, &insn->operands[0], (u64) is_overflow));

        break;
    }
    case PIS_OPCODE_GET_LOW_BITS: {
        CHECK_CODE(insn->operands_amount == 2, PIS_ERR_EMU_OPCODE_WRONG_OPERANDS_AMOUNT);

        // check operand sizes
        CHECK_CODE(
            insn->operands[0].size < insn->operands[1].size,
            PIS_ERR_EMU_OPERAND_SIZE_MISMATCH
        );

        u64 value = 0;
        CHECK_RETHROW(pis_emu_read_operand(emu, &insn->operands[1], &value));

        CHECK_RETHROW(pis_emu_write_operand(emu, &insn->operands[0], value));

        break;
    }
    case PIS_OPCODE_PARITY: {
        CHECK_CODE(insn->operands_amount == 2, PIS_ERR_EMU_OPCODE_WRONG_OPERANDS_AMOUNT);

        // check operand sizes
        CHECK_CODE(insn->operands[0].size == PIS_OPERAND_SIZE_1, PIS_ERR_EMU_OPERAND_SIZE_MISMATCH);

        u64 value = 0;
        CHECK_RETHROW(pis_emu_read_operand(emu, &insn->operands[1], &value));

        // naive calculation of parity. we don't care about performance here.
        u32 value_size_in_bits = pis_operand_size_to_bits(insn->operands[1].size);
        u32 bits_amount = 0;
        for (size_t i = 0; i < value_size_in_bits; i++) {
            if (((value >> i) & 1) != 0) {
                bits_amount++;
            }
        }
        bool parity_bit = bits_amount % 2 == 0;

        CHECK_RETHROW(pis_emu_write_operand(emu, &insn->operands[0], (u64) parity_bit));

        break;
    }
    case PIS_OPCODE_EQUALS: {
        CHECK_CODE(insn->operands_amount == 3, PIS_ERR_EMU_OPCODE_WRONG_OPERANDS_AMOUNT);

        // check operand sizes
        CHECK_CODE(
            insn->operands[1].size == insn->operands[2].size,
            PIS_ERR_EMU_OPERAND_SIZE_MISMATCH
        );
        CHECK_CODE(insn->operands[0].size == PIS_OPERAND_SIZE_1, PIS_ERR_EMU_OPERAND_SIZE_MISMATCH);

        u64 lhs = 0;
        CHECK_RETHROW(pis_emu_read_operand(emu, &insn->operands[1], &lhs));

        u64 rhs = 0;
        CHECK_RETHROW(pis_emu_read_operand(emu, &insn->operands[2], &rhs));

        bool equals = lhs == rhs;

        CHECK_RETHROW(pis_emu_write_operand(emu, &insn->operands[0], (u64) equals));

        break;
    }
    case PIS_OPCODE_NOT:
        CHECK_RETHROW(run_unary_operator(emu, insn, unary_operator_not));
        break;
    case PIS_OPCODE_NEG:
        CHECK_RETHROW(run_unary_operator(emu, insn, unary_operator_neg));
        break;
    case PIS_OPCODE_SHIFT_RIGHT:
        CHECK_RETHROW(run_binary_operator(emu, insn, binary_operator_shr));
        break;
    case PIS_OPCODE_SHIFT_RIGHT_SIGNED:
        CHECK_RETHROW(run_signed_binary_operator(emu, insn, signed_binary_operator_sar));
        break;
    case PIS_OPCODE_UNSIGNED_LESS_THAN: {
        CHECK_CODE(insn->operands_amount == 3, PIS_ERR_EMU_OPCODE_WRONG_OPERANDS_AMOUNT);

        // check operand sizes
        CHECK_CODE(
            insn->operands[1].size == insn->operands[2].size,
            PIS_ERR_EMU_OPERAND_SIZE_MISMATCH
        );
        CHECK_CODE(insn->operands[0].size == PIS_OPERAND_SIZE_1, PIS_ERR_EMU_OPERAND_SIZE_MISMATCH);

        u64 lhs = 0;
        CHECK_RETHROW(pis_emu_read_operand(emu, &insn->operands[1], &lhs));

        u64 rhs = 0;
        CHECK_RETHROW(pis_emu_read_operand(emu, &insn->operands[2], &rhs));

        bool result = lhs < rhs;

        CHECK_RETHROW(pis_emu_write_operand(emu, &insn->operands[0], (u64) result));

        break;
    }
    case PIS_OPCODE_SIGNED_BORROW: {
        CHECK_CODE(insn->operands_amount == 3, PIS_ERR_EMU_OPCODE_WRONG_OPERANDS_AMOUNT);

        // check operand sizes
        CHECK_CODE(
            insn->operands[1].size == insn->operands[2].size,
            PIS_ERR_EMU_OPERAND_SIZE_MISMATCH
        );
        CHECK_CODE(insn->operands[0].size == PIS_OPERAND_SIZE_1, PIS_ERR_EMU_OPERAND_SIZE_MISMATCH);

        u64 lhs = 0;
        CHECK_RETHROW(pis_emu_read_operand(emu, &insn->operands[1], &lhs));

        u64 rhs = 0;
        CHECK_RETHROW(pis_emu_read_operand(emu, &insn->operands[2], &rhs));

        u64 result = lhs - rhs;

        pis_operand_size_t src_operand_size = insn->operands[1].size;
        u32 src_operand_size_in_bits = pis_operand_size_to_bits(src_operand_size);
        u32 sign_bit_shift_amount = src_operand_size_in_bits - 1;

        u64 lhs_sign_bit = (lhs >> sign_bit_shift_amount) & 1;
        u64 rhs_sign_bit = (rhs >> sign_bit_shift_amount) & 1;
        u64 result_sign_bit = (result >> sign_bit_shift_amount) & 1;

        // signed overflow occurs when subtracting a rhs of a different sign than the lhs makes the
        // sign of the lhs change.
        bool is_overflow = lhs_sign_bit != rhs_sign_bit && lhs_sign_bit != result_sign_bit;

        CHECK_RETHROW(pis_emu_write_operand(emu, &insn->operands[0], (u64) is_overflow));

        break;
    }
    case PIS_OPCODE_JMP_COND:
        UNREACHABLE();
        break;
    case PIS_OPCODE_JMP:
        CHECK_CODE(insn->operands_amount == 1, PIS_ERR_EMU_OPCODE_WRONG_OPERANDS_AMOUNT);

        const pis_operand_t* jump_target = &insn->operands[0];

        // determine the jump target address
        u64 addr = 0;
        switch (jump_target->addr.space) {
        case PIS_SPACE_RAM:
            // jump to a fixed ram address
            addr = jump_target->addr.offset;
            break;
        default:
            // symbolic address, evaluate it
            CHECK_RETHROW(pis_emu_read_operand(emu, jump_target, &addr));
        }

        emu->did_jump = true;
        emu->jump_addr = addr;
        break;
    case PIS_OPCODE_SIGN_EXTEND: {
        CHECK_CODE(insn->operands_amount == 2, PIS_ERR_EMU_OPCODE_WRONG_OPERANDS_AMOUNT);

        // check operand sizes
        CHECK_CODE(
            insn->operands[0].size > insn->operands[1].size,
            PIS_ERR_EMU_OPERAND_SIZE_MISMATCH
        );

        i64 value = 0;
        CHECK_RETHROW(pis_emu_read_operand_signed(emu, &insn->operands[1], &value));

        CHECK_RETHROW(pis_emu_write_operand(emu, &insn->operands[0], value));

        break;
    }
    case PIS_OPCODE_ZERO_EXTEND: {
        CHECK_CODE(insn->operands_amount == 2, PIS_ERR_EMU_OPCODE_WRONG_OPERANDS_AMOUNT);

        // check operand sizes
        CHECK_CODE(
            insn->operands[0].size > insn->operands[1].size,
            PIS_ERR_EMU_OPERAND_SIZE_MISMATCH
        );

        u64 value = 0;
        CHECK_RETHROW(pis_emu_read_operand(emu, &insn->operands[1], &value));

        CHECK_RETHROW(pis_emu_write_operand(emu, &insn->operands[0], value));

        break;
    }
    case PIS_OPCODE_SIGNED_MUL:
        CHECK_RETHROW(run_signed_binary_operator(emu, insn, signed_binary_operator_mul));
        break;
    case PIS_OPCODE_SIGNED_MUL_OVERFLOW: {
        CHECK_CODE(insn->operands_amount == 3, PIS_ERR_EMU_OPCODE_WRONG_OPERANDS_AMOUNT);

        // check operand sizes
        CHECK_CODE(
            insn->operands[1].size == insn->operands[2].size,
            PIS_ERR_EMU_OPERAND_SIZE_MISMATCH
        );
        CHECK_CODE(insn->operands[0].size == PIS_OPERAND_SIZE_1, PIS_ERR_EMU_OPERAND_SIZE_MISMATCH);

        u64 lhs = 0;
        CHECK_RETHROW(pis_emu_read_operand(emu, &insn->operands[1], &lhs));

        u64 rhs = 0;
        CHECK_RETHROW(pis_emu_read_operand(emu, &insn->operands[2], &rhs));

        u64 result = lhs * rhs;

        bool is_overflow = (rhs != 0) && ((result / rhs) != lhs);

        CHECK_RETHROW(pis_emu_write_operand(emu, &insn->operands[0], (u64) is_overflow));

        break;
    }
    case PIS_OPCODE_UNSIGNED_MUL:
        CHECK_RETHROW(run_binary_operator(emu, insn, binary_operator_mul));
        break;
    case PIS_OPCODE_UNSIGNED_DIV:
        CHECK_RETHROW(run_binary_operator(emu, insn, binary_operator_div));
        break;
    case PIS_OPCODE_UNSIGNED_DIV_16: {
        CHECK_CODE(insn->operands_amount == 4, PIS_ERR_EMU_OPCODE_WRONG_OPERANDS_AMOUNT);

        // make sure that all operands are of the same size
        CHECK_TRACE_CODE(
            insn->operands[0].size == insn->operands[1].size &&
                insn->operands[1].size == insn->operands[2].size &&
                insn->operands[2].size == insn->operands[3].size,
            PIS_ERR_EMU_OPERAND_SIZE_MISMATCH,
            "operand size mismatch in binary operator %s, operand sizes: %u %u %u %u",
            pis_opcode_to_str(insn->opcode),
            insn->operands[0].size,
            insn->operands[1].size,
            insn->operands[2].size,
            insn->operands[3].size
        );

        u64 lhs_high = 0;
        CHECK_RETHROW(pis_emu_read_operand(emu, &insn->operands[1], &lhs_high));
        u64 lhs_low = 0;
        CHECK_RETHROW(pis_emu_read_operand(emu, &insn->operands[2], &lhs_low));
        u64 rhs = 0;
        CHECK_RETHROW(pis_emu_read_operand(emu, &insn->operands[3], &rhs));

        u64 quotient = 0;
        u64 rem = 0;
        div128(lhs_high, lhs_low, rhs, &quotient, &rem);

        CHECK_RETHROW(pis_emu_write_operand(emu, &insn->operands[0], quotient));
        break;
    }
    case PIS_OPCODE_UNSIGNED_REM_16: {
        CHECK_CODE(insn->operands_amount == 4, PIS_ERR_EMU_OPCODE_WRONG_OPERANDS_AMOUNT);

        // make sure that all operands are of the same size
        CHECK_TRACE_CODE(
            insn->operands[0].size == insn->operands[1].size &&
                insn->operands[1].size == insn->operands[2].size &&
                insn->operands[2].size == insn->operands[3].size,
            PIS_ERR_EMU_OPERAND_SIZE_MISMATCH,
            "operand size mismatch in binary operator %s, operand sizes: %u %u %u %u",
            pis_opcode_to_str(insn->opcode),
            insn->operands[0].size,
            insn->operands[1].size,
            insn->operands[2].size,
            insn->operands[3].size
        );

        u64 lhs_high = 0;
        CHECK_RETHROW(pis_emu_read_operand(emu, &insn->operands[1], &lhs_high));
        u64 lhs_low = 0;
        CHECK_RETHROW(pis_emu_read_operand(emu, &insn->operands[2], &lhs_low));
        u64 rhs = 0;
        CHECK_RETHROW(pis_emu_read_operand(emu, &insn->operands[3], &rhs));

        u64 quotient = 0;
        u64 rem = 0;
        div128(lhs_high, lhs_low, rhs, &quotient, &rem);

        CHECK_RETHROW(pis_emu_write_operand(emu, &insn->operands[0], rem));
        break;
    }
    case PIS_OPCODE_UNSIGNED_REM:
        CHECK_RETHROW(run_binary_operator(emu, insn, binary_operator_rem));
        break;
    case PIS_OPCODE_COND_NEGATE:
        CHECK_CODE(insn->operands_amount == 2, PIS_ERR_EMU_OPCODE_WRONG_OPERANDS_AMOUNT);

        // check operand sizes
        CHECK_TRACE_CODE(
            insn->operands[0].size == PIS_OPERAND_SIZE_1 &&
                insn->operands[1].size == PIS_OPERAND_SIZE_1,
            PIS_ERR_EMU_OPERAND_SIZE_MISMATCH,
            "operand size mismatch in opcode %s, operand sizes: %u %u",
            pis_opcode_to_str(insn->opcode),
            insn->operands[0].size,
            insn->operands[1].size
        );

        u64 input = 0;
        CHECK_RETHROW(pis_emu_read_operand(emu, &insn->operands[1], &input));

        // the input should be a conditional expression and should have a value of 0 or 1.
        CHECK_TRACE_CODE(
            input == 0 || input == 1,
            PIS_ERR_EMU_COND_EXPR_WRONG_VALUE,
            "wrong value %lu for conditional expression",
            input
        );

        CHECK_RETHROW(pis_emu_write_operand(emu, &insn->operands[0], !input));

        break;
    case PIS_OPCODE_HALT:
        CHECK_FAIL();
        break;
    }
cleanup:
    return err;
}

err_t pis_emu_run(pis_emu_t* emu, const pis_lift_result_t* lift_result) {
    err_t err = SUCCESS;
    for (size_t i = 0; i < lift_result->insns_amount; i++) {
        CHECK_RETHROW(pis_emu_run_one(emu, &lift_result->insns[i]));
    }
cleanup:
    return err;
}
