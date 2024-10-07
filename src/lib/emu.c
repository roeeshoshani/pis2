#include "emu.h"
#include "emu/storage.h"
#include "errors.h"
#include "except.h"
#include "pis.h"
#include "utils.h"
#include <endian.h>
#include <limits.h>

typedef u64 (*binary_operator_fn_t)(u64 lhs, u64 rhs);

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

static err_t read_operand(const pis_emu_t* emu, const pis_operand_t* operand, u64* operand_value) {
    err_t err = SUCCESS;

    size_t operand_size_in_bytes = pis_operand_size_to_bytes(operand->size);

    u64_bytes_t value = {.u64 = 0};
    CHECK(operand_size_in_bytes <= ARRAY_SIZE(value.bytes));
    CHECK_RETHROW(read_bytes(emu, &operand->addr, value.bytes, operand_size_in_bytes));

    endianness_swap_bytes_if_needed(emu, value.bytes, operand_size_in_bytes);

    *operand_value = value.u64;

cleanup:
    return err;
}

static err_t write_operand(pis_emu_t* emu, const pis_operand_t* operand, u64 value) {
    err_t err = SUCCESS;

    size_t operand_size_in_bytes = pis_operand_size_to_bytes(operand->size);

    u64_bytes_t fixed_value = {.u64 = value};
    CHECK(operand_size_in_bytes <= ARRAY_SIZE(fixed_value.bytes));
    endianness_swap_bytes_if_needed(emu, fixed_value.bytes, operand_size_in_bytes);

    CHECK_RETHROW(write_bytes(emu, &operand->addr, fixed_value.bytes, operand_size_in_bytes));

cleanup:
    return err;
}

static err_t run_binary_operator(pis_emu_t* emu, const pis_insn_t* insn, binary_operator_fn_t fn) {
    err_t err = SUCCESS;
    CHECK_CODE(insn->operands_amount == 3, PIS_ERR_EMU_OPCODE_WRONG_OPERANDS_AMOUNT);

    u64 lhs = 0;
    CHECK_RETHROW(read_operand(emu, &insn->operands[1], &lhs));
    u64 rhs = 0;
    CHECK_RETHROW(read_operand(emu, &insn->operands[2], &rhs));

    u64 result = fn(lhs, rhs);
    CHECK_RETHROW(write_operand(emu, &insn->operands[0], result));
cleanup:
    return err;
}

#define DEFINE_BINARY_OPERATOR(NAME, OP)                                                           \
    static u64 binary_operator_##NAME(u64 lhs, u64 rhs) {                                          \
        return lhs OP rhs;                                                                         \
    }

DEFINE_BINARY_OPERATOR(add, +);
DEFINE_BINARY_OPERATOR(sub, -);
DEFINE_BINARY_OPERATOR(xor, ^);
DEFINE_BINARY_OPERATOR(and, &);

static err_t pis_emu_run_one(pis_emu_t* emu, const pis_insn_t* insn) {
    err_t err = SUCCESS;
    switch (insn->opcode) {
    case PIS_OPCODE_MOVE:
        CHECK_CODE(insn->operands_amount == 2, PIS_ERR_EMU_OPCODE_WRONG_OPERANDS_AMOUNT);

        u64 value = 0;
        CHECK_RETHROW(read_operand(emu, &insn->operands[1], &value));

        CHECK_RETHROW(write_operand(emu, &insn->operands[0], value));

        break;
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
    case PIS_OPCODE_STORE:
        break;
    case PIS_OPCODE_LOAD:
        break;
    case PIS_OPCODE_UNSIGNED_CARRY:
        break;
    case PIS_OPCODE_SIGNED_CARRY:
        break;
    case PIS_OPCODE_GET_LOW_BITS:
        break;
    case PIS_OPCODE_PARITY:
        break;
    case PIS_OPCODE_EQUALS:
        break;
    case PIS_OPCODE_NOT:
        break;
    case PIS_OPCODE_SHIFT_RIGHT:
        break;
    case PIS_OPCODE_UNSIGNED_LESS_THAN:
        break;
    case PIS_OPCODE_SIGNED_BORROW:
        break;
    case PIS_OPCODE_JMP_COND:
        break;
    case PIS_OPCODE_JMP:
        break;
    case PIS_OPCODE_SIGN_EXTEND:
        break;
    case PIS_OPCODE_ZERO_EXTEND:
        break;
    case PIS_OPCODE_SIGNED_MUL:
        break;
    case PIS_OPCODE_SIGNED_MUL_OVERFLOW:
        break;
    case PIS_OPCODE_UNSIGNED_MUL:
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
