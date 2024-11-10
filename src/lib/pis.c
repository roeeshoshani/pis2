#include "pis.h"
#include "errors.h"
#include "except.h"
#include "trace.h"
#include <limits.h>

STR_ENUM_IMPL(pis_opcode, PIS_OPCODE);
STR_ENUM_IMPL(pis_space, PIS_SPACE);

void pis_addr_dump(const pis_addr_t* addr) {
    TRACE_NO_NEWLINE("%s[0x%lx]", pis_space_to_str(addr->space), (unsigned long) addr->offset);
}

bool pis_addr_equals(const pis_addr_t* a, const pis_addr_t* b) {
    return a->space == b->space && a->offset == b->offset;
}

void pis_operand_dump(const pis_operand_t* operand) {
    pis_addr_dump(&operand->addr);
    TRACE_NO_NEWLINE(":0x%x", (unsigned) pis_operand_size_to_bytes(operand->size));
}

bool pis_operand_equals(const pis_operand_t* a, const pis_operand_t* b) {
    return a->size == b->size && pis_addr_equals(&a->addr, &b->addr);
}

void pis_insn_dump(const pis_insn_t* insn) {
    TRACE_NO_NEWLINE("%s (", pis_opcode_to_str(insn->opcode));
    size_t operands_amount = MIN(insn->operands_amount, PIS_INSN_MAX_OPERANDS_AMOUNT);
    for (size_t i = 0; i < operands_amount; i++) {
        pis_operand_dump(&insn->operands[i]);
        if (i + 1 < operands_amount) {
            // not the last operand, add a comma
            TRACE_NO_NEWLINE(", ");
        }
    }
    TRACE_NO_NEWLINE(")");
}

bool pis_insn_equals(const pis_insn_t* a, const pis_insn_t* b) {
    if (a->opcode != b->opcode) {
        return false;
    }
    if (a->operands_amount != b->operands_amount) {
        return false;
    }
    size_t operands_amount = MIN(a->operands_amount, PIS_INSN_MAX_OPERANDS_AMOUNT);
    for (size_t i = 0; i < operands_amount; i++) {
        if (!pis_operand_equals(&a->operands[i], &b->operands[i])) {
            return false;
        }
    }
    return true;
}

err_t pis_lift_result_emit(pis_lift_result_t* result, const pis_insn_t* insn) {
    err_t err = SUCCESS;

    CHECK_CODE(result->insns_amount < PIS_LIFT_MAX_INSNS_AMOUNT, PIS_ERR_TOO_MANY_INSNS);

    result->insns[result->insns_amount] = *insn;
    result->insns_amount++;

cleanup:
    return err;
}

void pis_lift_result_dump(const pis_lift_result_t* result) {
    for (size_t i = 0; i < result->insns_amount; i++) {
        pis_insn_dump(&result->insns[i]);

        // add a newline after each instruction
        TRACE();
    }
}

void pis_lift_result_reset(pis_lift_result_t* result) {
    result->insns_amount = 0;
    result->machine_insn_len = 0;
}

err_t pis_lift_result_get_last_emitted_insn(pis_lift_result_t* result, pis_insn_t** insn) {
    err_t err = SUCCESS;

    CHECK(result->insns_amount > 0);
    *insn = &result->insns[result->insns_amount - 1];

cleanup:
    return err;
}

u64 pis_const_negate(u64 const_value, pis_operand_size_t operand_size) {
    u32 operand_size_bits = pis_operand_size_to_bits(operand_size);
    if (operand_size_bits == 64) {
        return -const_value;
    } else {
        return (1UL << operand_size_bits) - const_value;
    }
}

u64 pis_sign_extend_byte(i8 byte, pis_operand_size_t desired_size) {
    switch (desired_size) {
        case PIS_OPERAND_SIZE_1:
            return (u8) byte;
        case PIS_OPERAND_SIZE_2:
            return (u16) ((i16) byte);
        case PIS_OPERAND_SIZE_4:
            return (u32) ((i32) byte);
        case PIS_OPERAND_SIZE_8:
            return (u64) ((i64) byte);
        default:
            // unreachable
            return 0;
    }
}

err_t pis_addr_add(const pis_addr_t* addr, u64 amount, pis_addr_t* new_addr) {
    err_t err = SUCCESS;
    CHECK_CODE(addr->offset <= UINT64_MAX - amount, PIS_ERR_ADDR_OVERFLOW);

    pis_addr_t sum = *addr;
    sum.offset += amount;

    *new_addr = sum;

cleanup:
    return err;
}
