#pragma once

#include "except.h"
#include "str_enum.h"
#include "types.h"

#define PIS_INSN_OPERANDS_AMOUNT (2)

#define PIS_LIFT_MAX_INSNS_AMOUNT (64)

#define PIS_INSN(OPCODE, OPERAND_1, OPERAND_2)                                                     \
    ((pis_insn_t) { .opcode = (OPCODE), .operands = { (OPERAND_1), (OPERAND_2) } })

#define PIS_ADDR(SPACE, OFFSET) ((pis_addr_t) { .space = (SPACE), .offset = (OFFSET) })

#define PIS_OPERAND(ADDR, SIZE) ((pis_operand_t) { .addr = (ADDR), .size = (SIZE) })

#define PIS_OPERAND_REG(OFFSET, SIZE) (PIS_OPERAND(PIS_ADDR(PIS_SPACE_REG, OFFSET), SIZE))

#define PIS_OPERAND_CONST(VALUE, SIZE) (PIS_OPERAND(PIS_ADDR(PIS_SPACE_CONST, VALUE), SIZE))

#define PIS_LIFT_RESULT_EMIT(LIFT_RESULT, INSN)                                                    \
    CHECK_RETHROW(pis_lift_result_emit((LIFT_RESULT), &(INSN)))

#define PIS_OPCODE(_)                                                                              \
    _(PIS_OPCODE_MOVE, )                                                                           \
    _(PIS_OPCODE_ADD, )
STR_ENUM(pis_opcode, PIS_OPCODE);

#define PIS_SPACE(_)                                                                               \
    _(PIS_SPACE_CONST, )                                                                           \
    _(PIS_SPACE_REG, )                                                                             \
    _(PIS_SPACE_RAM, )
STR_ENUM(pis_space, PIS_SPACE);

typedef struct {
    pis_space_t space;
    u64 offset;
} pis_addr_t;

typedef struct {
    pis_addr_t addr;
    u32 size;
} pis_operand_t;

typedef struct {
    pis_opcode_t opcode;
    pis_operand_t operands[PIS_INSN_OPERANDS_AMOUNT];
} pis_insn_t;

typedef struct {
    pis_insn_t insns[PIS_LIFT_MAX_INSNS_AMOUNT];
    size_t insns_amount;
} pis_lift_result_t;

void pis_addr_dump(const pis_addr_t* addr);

void pis_operand_dump(const pis_operand_t* operand);

void pis_insn_dump(const pis_insn_t* insn);

err_t pis_lift_result_emit(pis_lift_result_t* result, const pis_insn_t* insn);

void pis_lift_result_dump(const pis_lift_result_t* result);
