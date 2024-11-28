#pragma once

#include "pis.h"
#include "space.h"

#define DECLARE_REG_OPERAND(NAME) extern const pis_reg_t NAME;

#define DECLARE_REG_OPERANDS(...) MAP(DECLARE_REG_OPERAND, ##__VA_ARGS__)

#define DEFINE_REG_OPERAND(NAME, OFFSET, SIZE)                                                     \
    const pis_reg_t NAME = {                                                                       \
        .region =                                                                                  \
            {                                                                                      \
                .offset = OFFSET,                                                                  \
                .size = SIZE,                                                                      \
            },                                                                                     \
    }

#define DEFINE_REG_OPERANDS(                                                                       \
    START_OFFSET,                                                                                  \
    OFFSET_STEP_SIZE,                                                                              \
    OPERAND_SIZE,                                                                                  \
    FIRST_NAME,                                                                                    \
    SECOND_NAME,                                                                                   \
    ...                                                                                            \
)                                                                                                  \
    DEFINE_REG_OPERAND(FIRST_NAME, START_OFFSET, OPERAND_SIZE);                                    \
    REC_MACRO_EVAL(_DEFINE_REG_OPERANDS_REC_0(                                                     \
        START_OFFSET,                                                                              \
        OFFSET_STEP_SIZE,                                                                          \
        OPERAND_SIZE,                                                                              \
        SECOND_NAME,                                                                               \
        ##__VA_ARGS__,                                                                             \
        REC_MACRO_END,                                                                             \
        0                                                                                          \
    ))

#define _DEFINE_REG_OPERANDS_REC_0(                                                                \
    PREV_OFFSET,                                                                                   \
    OFFSET_STEP_SIZE,                                                                              \
    OPERAND_SIZE,                                                                                  \
    CUR_NAME,                                                                                      \
    NEXT_NAME,                                                                                     \
    ...                                                                                            \
)                                                                                                  \
    DEFINE_REG_OPERAND(CUR_NAME, PREV_OFFSET + OFFSET_STEP_SIZE, OPERAND_SIZE);                    \
    REC_MACRO_TEST(NEXT_NAME, _DEFINE_REG_OPERANDS_REC_1)                                          \
    (PREV_OFFSET + OFFSET_STEP_SIZE, OFFSET_STEP_SIZE, OPERAND_SIZE, NEXT_NAME, ##__VA_ARGS__)

#define _DEFINE_REG_OPERANDS_REC_1(                                                                \
    PREV_OFFSET,                                                                                   \
    OFFSET_STEP_SIZE,                                                                              \
    OPERAND_SIZE,                                                                                  \
    CUR_NAME,                                                                                      \
    NEXT_NAME,                                                                                     \
    ...                                                                                            \
)                                                                                                  \
    DEFINE_REG_OPERAND(CUR_NAME, PREV_OFFSET + OFFSET_STEP_SIZE, OPERAND_SIZE);                    \
    REC_MACRO_TEST(NEXT_NAME, _DEFINE_REG_OPERANDS_REC_0)                                          \
    (PREV_OFFSET + OFFSET_STEP_SIZE, OFFSET_STEP_SIZE, OPERAND_SIZE, NEXT_NAME, ##__VA_ARGS__)


/// a register.
typedef struct {
    /// the region in the operand space that is used by this register.
    pis_region_t region;
} PACKED pis_reg_t;

void pis_reg_dump(pis_reg_t reg);

bool pis_reg_contains(pis_reg_t reg, pis_reg_t sub_reg);

bool pis_regs_equal(pis_reg_t a, pis_reg_t b);

bool pis_regs_intersect(pis_reg_t a, pis_reg_t b);

pis_op_t pis_reg_to_op(pis_reg_t reg);
