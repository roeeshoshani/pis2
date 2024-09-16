#include "pis.h"
#include "errors.h"
#include "trace.h"

STR_ENUM_IMPL(pis_opcode, PIS_OPCODE);
STR_ENUM_IMPL(pis_space, PIS_SPACE);

void pis_addr_dump(const pis_addr_t* addr) {
    TRACE_NO_NEWLINE("%s[0x%lx]", pis_space_to_str(addr->space), (unsigned long) addr->offset);
}

void pis_operand_dump(const pis_operand_t* operand) {
    pis_addr_dump(&operand->addr);
    TRACE_NO_NEWLINE(":0x%x", (unsigned) pis_operand_size_to_bytes(operand->size));
}

void pis_insn_dump(const pis_insn_t* insn) {
    TRACE_NO_NEWLINE("%s (", pis_opcode_to_str(insn->opcode));
    pis_operand_dump(&insn->operands[0]);
    TRACE_NO_NEWLINE(", ");
    pis_operand_dump(&insn->operands[1]);
    TRACE_NO_NEWLINE(")");
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

u32 pis_operand_size_to_bytes(pis_operand_size_t operand_size) {
    return (u32) operand_size;
}

u32 pis_operand_size_to_bits(pis_operand_size_t operand_size) {
    return pis_operand_size_to_bytes(operand_size) * 8;
}

u64 pis_const_negate(u64 const_value, pis_operand_size_t operand_size) {
    u32 operand_size_bits = pis_operand_size_to_bits(operand_size);
    if (operand_size_bits == 64) {
        return -const_value;
    } else {
        return (1UL << operand_size_bits) - const_value;
    }
}
