#include "pis.h"
#include "errors.h"
#include "except.h"
#include "size.h"
#include "trace.h"
#include <limits.h>

STR_ENUM_IMPL(pis_opcode, PIS_OPCODE);
STR_ENUM_IMPL(pis_var_space, PIS_VAR_SPACE);
STR_ENUM_IMPL(pis_op_kind, PIS_OP_KIND);

void pis_var_dump(pis_var_t var) {
    TRACE_NO_NEWLINE(
        "%s[0x%x]:%u",
        pis_var_space_to_str(var.space),
        var.offset,
        pis_size_to_bytes(var.size)
    );
}

bool pis_var_equals(pis_var_t a, pis_var_t b) {
    return a.space == b.space && a.offset == b.offset && a.size == b.size;
}

void pis_op_dump(const pis_op_t* operand) {
    switch (operand->kind) {
        case PIS_OP_KIND_IMM:
            TRACE_NO_NEWLINE("0x%lx", operand->v.imm.value);
            break;
        case PIS_OP_KIND_VAR:
            pis_var_dump(operand->v.var);
            break;
        case PIS_OP_KIND_RAM:
            TRACE_NO_NEWLINE("RAM[0x%lx]", operand->v.ram.addr);
            break;
    }
}

bool pis_operand_equals(const pis_op_t* a, const pis_op_t* b) {
    if (a->kind != b->kind) {
        return false;
    }
    switch (a->kind) {
        case PIS_OP_KIND_IMM:
            return a->v.imm.value == b->v.imm.value;
        case PIS_OP_KIND_VAR:
            return pis_var_equals(a->v.var, b->v.var);
        case PIS_OP_KIND_RAM:
            return a->v.ram.addr == b->v.ram.addr;
        default:
            return false;
    }
}

void pis_insn_dump(const pis_insn_t* insn) {
    TRACE_NO_NEWLINE("%s (", pis_opcode_to_str(insn->opcode));
    size_t operands_amount = MIN(insn->operands_amount, PIS_INSN_MAX_OPERANDS_AMOUNT);
    for (size_t i = 0; i < operands_amount; i++) {
        pis_op_dump(&insn->operands[i]);
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

err_t pis_lift_res_emit(pis_lift_res_t* result, const pis_insn_t* insn) {
    err_t err = SUCCESS;

    CHECK_CODE(result->insns_amount < PIS_LIFT_MAX_INSNS_AMOUNT, PIS_ERR_TOO_MANY_INSNS);

    result->insns[result->insns_amount] = *insn;
    result->insns_amount++;

cleanup:
    return err;
}

void pis_lift_res_dump(const pis_lift_res_t* result) {
    for (size_t i = 0; i < result->insns_amount; i++) {
        pis_insn_dump(&result->insns[i]);

        // add a newline after each instruction
        TRACE();
    }
}

void pis_lift_res_reset(pis_lift_res_t* result) {
    result->insns_amount = 0;
    result->machine_insn_len = 0;
}

err_t pis_lift_res_get_last_emitted_insn(pis_lift_res_t* result, pis_insn_t** insn) {
    err_t err = SUCCESS;

    CHECK(result->insns_amount > 0);
    *insn = &result->insns[result->insns_amount - 1];

cleanup:
    return err;
}

u64 pis_const_negate(u64 const_value, pis_size_t operand_size) {
    u32 operand_size_bits = pis_size_to_bits(operand_size);
    if (operand_size_bits == 64) {
        return -const_value;
    } else {
        return (1UL << operand_size_bits) - const_value;
    }
}

u64 pis_sign_extend_byte(i8 byte, pis_size_t desired_size) {
    switch (desired_size) {
        case PIS_SIZE_1:
            return (u8) byte;
        case PIS_SIZE_2:
            return (u16) ((i16) byte);
        case PIS_SIZE_4:
            return (u32) ((i32) byte);
        case PIS_SIZE_8:
            return (u64) ((i64) byte);
        default:
            // unreachable
            return 0;
    }
}

bool pis_opcode_is_jmp(pis_opcode_t opcode) {
    switch (opcode) {
        case PIS_OPCODE_JMP:
        case PIS_OPCODE_JMP_CALL:
        case PIS_OPCODE_JMP_RET:
        case PIS_OPCODE_JMP_COND:
        case PIS_OPCODE_JMP_CALL_COND:
            return true;
        default:
            return false;
    }
}

/// checks if the given var fully contains the given sub-var.
bool pis_var_contains(pis_var_t var, pis_var_t sub_var) {
    if (var.space != sub_var.space) {
        return false;
    }
    pis_var_off_t var_start = var.offset;
    pis_var_off_t var_end = var_start + pis_size_to_bytes(var.size);

    pis_var_off_t sub_var_start = sub_var.offset;
    pis_var_off_t sub_var_end = sub_var_start + pis_size_to_bytes(sub_var.size);

    return sub_var_start >= var_start && sub_var_end <= var_end;
}

/// checks if the given 2 operands intersect. that is, there is at least one byte of operand space
/// which is included in both operands.
bool pis_vars_intersect(pis_var_t var_a, pis_var_t var_b) {
    if (var_a.space != var_b.space) {
        return false;
    }
    pis_var_off_t var_a_start = var_a.offset;
    pis_var_off_t var_a_end = var_a_start + pis_size_to_bytes(var_a.size);

    pis_var_off_t var_b_start = var_b.offset;
    pis_var_off_t var_b_end = var_b_start + pis_size_to_bytes(var_b.size);

    return var_a_start < var_b_end && var_b_start < var_a_end;
}
