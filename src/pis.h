#pragma once

#include "except.h"
#include "str_enum.h"
#include "types.h"

#define PIS_INSN_OPERANDS_AMOUNT (2)

#define PIS_LIFT_MAX_INSNS_AMOUNT (64)

#define PIS_INSN(OPCODE, OPERAND_1, OPERAND_2)                                                     \
    ((pis_insn_t) {.opcode = (OPCODE), .operands = {(OPERAND_1), (OPERAND_2)}})

#define PIS_ADDR(SPACE, OFFSET) ((pis_addr_t) {.space = (SPACE), .offset = (OFFSET)})

#define PIS_OPERAND(ADDR, SIZE) ((pis_operand_t) {.addr = (ADDR), .size = (SIZE)})

#define PIS_OPERAND_REG(OFFSET, SIZE) (PIS_OPERAND(PIS_ADDR(PIS_SPACE_REG, OFFSET), SIZE))

#define PIS_OPERAND_CONST(VALUE, SIZE) (PIS_OPERAND(PIS_ADDR(PIS_SPACE_CONST, VALUE), SIZE))

#define PIS_LIFT_RESULT_EMIT(LIFT_RESULT, INSN)                                                    \
    CHECK_RETHROW(pis_lift_result_emit((LIFT_RESULT), &(INSN)))

#define DECLARE_REG_OPERAND(NAME)                                                     \
    const pis_operand_t NAME;

#define DECLARE_REG_OPERANDS(...) MAP(DECLARE_REG_OPERAND, ##__VA_ARGS__)

#define DEFINE_REG_OPERAND(NAME, OFFSET, SIZE)                                                     \
    const pis_operand_t NAME = PIS_OPERAND_REG(OFFSET, SIZE)

#define DEFINE_REG_OPERANDS(                                                                       \
    START_OFFSET,                                                                                  \
    OFFSET_STEP_SIZE,                                                                              \
    OPERAND_SIZE,                                                                                  \
    FIRST_NAME,                                                                                    \
    SECOND_NAME,                                                                                   \
    ...                                                                                            \
)                                                                                                  \
    DEFINE_REG_OPERAND(FIRST_NAME, START_OFFSET, OPERAND_SIZE);                                    \
    REC_MACRO_EVAL(_DEFINE_REG_OPERANDS_REC_0(                                                       \
        START_OFFSET,                                                                              \
        OFFSET_STEP_SIZE,                                                                          \
        OPERAND_SIZE,                                                                              \
        SECOND_NAME,                                                                               \
        ##__VA_ARGS__,                                                                             \
        REC_MACRO_END,                                                                      \
        0                                                                                          \
    ))

#define _DEFINE_REG_OPERANDS_REC_0(                                                                  \
    PREV_OFFSET,                                                                                   \
    OFFSET_STEP_SIZE,                                                                              \
    OPERAND_SIZE,                                                                                  \
    CUR_NAME,                                                                                      \
    NEXT_NAME,                                                                                     \
    ...                                                                                            \
)                                                                                                  \
    DEFINE_REG_OPERAND(CUR_NAME, PREV_OFFSET + OFFSET_STEP_SIZE, OPERAND_SIZE);                    \
    REC_MACRO_TEST(NEXT_NAME, _DEFINE_REG_OPERANDS_REC_1)                                            \
    (PREV_OFFSET + OFFSET_STEP_SIZE, OFFSET_STEP_SIZE, OPERAND_SIZE, NEXT_NAME, ##__VA_ARGS__)

#define _DEFINE_REG_OPERANDS_REC_1(                                                                  \
    PREV_OFFSET,                                                                                   \
    OFFSET_STEP_SIZE,                                                                              \
    OPERAND_SIZE,                                                                                  \
    CUR_NAME,                                                                                      \
    NEXT_NAME,                                                                                     \
    ...                                                                                            \
)                                                                                                  \
    DEFINE_REG_OPERAND(CUR_NAME, PREV_OFFSET + OFFSET_STEP_SIZE, OPERAND_SIZE);                    \
    REC_MACRO_TEST(NEXT_NAME, _DEFINE_REG_OPERANDS_REC_0)                                            \
    (PREV_OFFSET + OFFSET_STEP_SIZE, OFFSET_STEP_SIZE, OPERAND_SIZE, NEXT_NAME, ##__VA_ARGS__)

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
