#pragma once

#include "except.h"
#include "recursive_macros.h"
#include "str_enum.h"
#include "types.h"

#define PIS_INSN_MAX_OPERANDS_AMOUNT (4)

#define PIS_LIFT_MAX_INSNS_AMOUNT (64)

#define PIS_INSN0(OPCODE)                                                                          \
    ((pis_insn_t) {                                                                                \
        .opcode = (OPCODE),                                                                        \
        .operands = {},                                                                            \
        .operands_amount = 0,                                                                      \
    })

#define PIS_INSN1(OPCODE, OPERAND_1)                                                               \
    ((pis_insn_t) {                                                                                \
        .opcode = (OPCODE),                                                                        \
        .operands = {(OPERAND_1)},                                                                 \
        .operands_amount = 1,                                                                      \
    })

#define PIS_INSN2(OPCODE, OPERAND_1, OPERAND_2)                                                    \
    ((pis_insn_t) {                                                                                \
        .opcode = (OPCODE),                                                                        \
        .operands = {(OPERAND_1), (OPERAND_2)},                                                    \
        .operands_amount = 2,                                                                      \
    })

#define PIS_INSN3(OPCODE, OPERAND_1, OPERAND_2, OPERAND_3)                                         \
    ((pis_insn_t) {                                                                                \
        .opcode = (OPCODE),                                                                        \
        .operands = {(OPERAND_1), (OPERAND_2), (OPERAND_3)},                                       \
        .operands_amount = 3,                                                                      \
    })

#define PIS_INSN4(OPCODE, OPERAND_1, OPERAND_2, OPERAND_3, OPERAND_4)                              \
    ((pis_insn_t) {                                                                                \
        .opcode = (OPCODE),                                                                        \
        .operands = {(OPERAND_1), (OPERAND_2), (OPERAND_3), (OPERAND_4)},                          \
        .operands_amount = 4,                                                                      \
    })

#define PIS_ADDR(SPACE, OFFSET) ((pis_addr_t) {.space = (SPACE), .offset = (OFFSET)})

#define PIS_OPERAND(ADDR, SIZE) ((pis_operand_t) {.addr = (ADDR), .size = (SIZE)})

#define PIS_OPERAND_REG(OFFSET, SIZE) (PIS_OPERAND(PIS_ADDR(PIS_SPACE_REG, OFFSET), SIZE))

#define PIS_OPERAND_RAM(OFFSET, SIZE) (PIS_OPERAND(PIS_ADDR(PIS_SPACE_RAM, OFFSET), SIZE))

#define PIS_OPERAND_TMP(OFFSET, SIZE) (PIS_OPERAND(PIS_ADDR(PIS_SPACE_TMP, OFFSET), SIZE))

#define PIS_OPERAND_CONST(VALUE, SIZE) (PIS_OPERAND(PIS_ADDR(PIS_SPACE_CONST, VALUE), SIZE))

#define PIS_OPERAND_CONST_NEG(ABS_VALUE, SIZE)                                                     \
    (PIS_OPERAND(PIS_ADDR(PIS_SPACE_CONST, pis_const_negate(ABS_VALUE, SIZE)), SIZE))

#define PIS_LIFT_RESULT_EMIT(LIFT_RESULT, INSN)                                                    \
    CHECK_RETHROW(pis_lift_result_emit((LIFT_RESULT), &(INSN)))

#define DECLARE_REG_OPERAND(NAME) extern const pis_operand_t NAME;

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

#define PIS_OPCODE(_)                                                                              \
    _(PIS_OPCODE_MOVE, )                                                                           \
    _(PIS_OPCODE_ADD, )                                                                            \
    _(PIS_OPCODE_SUB, )                                                                            \
    _(PIS_OPCODE_XOR, )                                                                            \
    _(PIS_OPCODE_AND, )                                                                            \
    _(PIS_OPCODE_OR, )                                                                             \
    _(PIS_OPCODE_STORE, )                                                                          \
    _(PIS_OPCODE_LOAD, )                                                                           \
    _(PIS_OPCODE_HALT, )                                                                           \
    _(PIS_OPCODE_UNSIGNED_CARRY, )                                                                 \
    _(PIS_OPCODE_SIGNED_CARRY, )                                                                   \
    _(PIS_OPCODE_GET_LOW_BITS, )                                                                   \
    _(PIS_OPCODE_PARITY, )                                                                         \
    _(PIS_OPCODE_EQUALS, )                                                                         \
    _(PIS_OPCODE_NOT, )                                                                            \
    _(PIS_OPCODE_NEG, )                                                                            \
    _(PIS_OPCODE_SHIFT_RIGHT, )                                                                    \
    _(PIS_OPCODE_SHIFT_RIGHT_SIGNED, )                                                             \
    _(PIS_OPCODE_SHIFT_LEFT, )                                                                     \
    _(PIS_OPCODE_UNSIGNED_LESS_THAN, )                                                             \
    _(PIS_OPCODE_SIGNED_BORROW, )                                                                  \
    _(PIS_OPCODE_JMP_COND, )                                                                       \
    _(PIS_OPCODE_JMP, )                                                                            \
    _(PIS_OPCODE_COND_NEGATE, )                                                                    \
    _(PIS_OPCODE_SIGN_EXTEND, )                                                                    \
    _(PIS_OPCODE_ZERO_EXTEND, )                                                                    \
    _(PIS_OPCODE_SIGNED_MUL, )                                                                     \
    _(PIS_OPCODE_SIGNED_MUL_OVERFLOW, )                                                            \
    _(PIS_OPCODE_UNSIGNED_MUL, )                                                                   \
    _(PIS_OPCODE_UNSIGNED_DIV_16, )                                                                \
    _(PIS_OPCODE_UNSIGNED_REM_16, )                                                                \
    _(PIS_OPCODE_UNSIGNED_MUL_16, )                                                                \
    _(PIS_OPCODE_UNSIGNED_REM, )                                                                   \
    _(PIS_OPCODE_UNSIGNED_DIV, )
STR_ENUM(pis_opcode, PIS_OPCODE);

#define PIS_SPACE(_)                                                                               \
    _(PIS_SPACE_CONST, )                                                                           \
    _(PIS_SPACE_REG, )                                                                             \
    _(PIS_SPACE_RAM, )                                                                             \
    _(PIS_SPACE_TMP, )
STR_ENUM(pis_space, PIS_SPACE);

typedef enum {
    PIS_ENDIANNESS_LITTLE,
    PIS_ENDIANNESS_BIG,
} pis_endianness_t;

typedef enum {
    /// 1 byte
    PIS_OPERAND_SIZE_1 = 1,
    /// 2 bytes
    PIS_OPERAND_SIZE_2 = 2,
    /// 4 bytes
    PIS_OPERAND_SIZE_4 = 4,
    /// 8 bytes
    PIS_OPERAND_SIZE_8 = 8,
} pis_operand_size_t;

typedef struct {
    pis_space_t space;
    u64 offset;
} pis_addr_t;

typedef struct {
    pis_addr_t addr;
    pis_operand_size_t size;
} pis_operand_t;

typedef struct {
    pis_opcode_t opcode;
    pis_operand_t operands[PIS_INSN_MAX_OPERANDS_AMOUNT];
    size_t operands_amount;
} pis_insn_t;

typedef struct {
    pis_insn_t insns[PIS_LIFT_MAX_INSNS_AMOUNT];
    size_t insns_amount;
    size_t machine_insn_len;
} pis_lift_result_t;

void pis_addr_dump(const pis_addr_t* addr);
bool pis_addr_equals(const pis_addr_t* a, const pis_addr_t* b);

void pis_operand_dump(const pis_operand_t* operand);
bool pis_operand_equals(const pis_operand_t* a, const pis_operand_t* b);

void pis_insn_dump(const pis_insn_t* insn);
bool pis_insn_equals(const pis_insn_t* a, const pis_insn_t* b);

err_t pis_lift_result_emit(pis_lift_result_t* result, const pis_insn_t* insn);

void pis_lift_result_dump(const pis_lift_result_t* result);

void pis_lift_result_reset(pis_lift_result_t* result);

err_t pis_lift_result_get_last_emitted_insn(pis_lift_result_t* result, pis_insn_t** insn);

u32 pis_operand_size_to_bytes(pis_operand_size_t operand_size);

u32 pis_operand_size_to_bits(pis_operand_size_t operand_size);

u64 pis_operand_size_max_unsigned_value(pis_operand_size_t operand_size);

u64 pis_const_negate(u64 const_value, u32 operand_size);

u64 pis_sign_extend_byte(i8 byte, pis_operand_size_t desired_size);

err_t pis_addr_add(const pis_addr_t* addr, u64 amount, pis_addr_t* new_addr);

pis_endianness_t pis_endianness_native();
