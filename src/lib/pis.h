#pragma once

#include "endianness.h"
#include "except.h"
#include "recursive_macros.h"
#include "size.h"
#include "str_enum.h"
#include "types.h"

#define PIS_INSN_MAX_OPERANDS_AMOUNT (4)

#define PIS_LIFT_MAX_INSNS_AMOUNT (128)

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

#define PIS_ADDR_INIT(SPACE, OFFSET) {.space = SPACE, .offset = OFFSET}

#define PIS_ADDR(SPACE, OFFSET) ((pis_addr_t) PIS_ADDR_INIT(SPACE, OFFSET))

#define PIS_OPERAND_INIT(ADDR, SIZE) {.addr = ADDR, .size = SIZE}

#define PIS_OPERAND(ADDR, SIZE) ((pis_operand_t) PIS_OPERAND_INIT(ADDR, SIZE))

#define PIS_OPERAND_REG(OFFSET, SIZE) (PIS_OPERAND(PIS_ADDR(PIS_SPACE_REG, OFFSET), SIZE))

#define PIS_OPERAND_RAM(OFFSET, SIZE) (PIS_OPERAND(PIS_ADDR(PIS_SPACE_RAM, OFFSET), SIZE))

#define PIS_OPERAND_TMP(OFFSET, SIZE) (PIS_OPERAND(PIS_ADDR(PIS_SPACE_TMP, OFFSET), SIZE))

#define PIS_OPERAND_CONST(VALUE, SIZE) (PIS_OPERAND(PIS_ADDR(PIS_SPACE_CONST, VALUE), SIZE))

#define PIS_OPERAND_CONST_NEG(ABS_VALUE, SIZE)                                                     \
    (PIS_OPERAND(PIS_ADDR(PIS_SPACE_CONST, pis_const_negate(ABS_VALUE, SIZE)), SIZE))

#define PIS_EMIT(LIFT_RES, INSN) CHECK_RETHROW(pis_lift_res_emit((LIFT_RES), &(INSN)))

#define DECLARE_REG_OPERAND(NAME) extern const pis_operand_t NAME;

#define DECLARE_REG_OPERANDS(...) MAP(DECLARE_REG_OPERAND, ##__VA_ARGS__)

#define DEFINE_REG_OPERAND(NAME, OFFSET, SIZE)                                                     \
    const pis_operand_t NAME = PIS_OPERAND_INIT(PIS_ADDR_INIT(PIS_SPACE_REG, OFFSET), SIZE)

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
    _(PIS_OPCODE_SIGNED_LESS_THAN, )                                                               \
    _(PIS_OPCODE_JMP_COND, )                                                                       \
    _(PIS_OPCODE_JMP, )                                                                            \
    _(PIS_OPCODE_JMP_CALL_COND, )                                                                  \
    _(PIS_OPCODE_JMP_CALL, )                                                                       \
    _(PIS_OPCODE_JMP_RET, )                                                                        \
    _(PIS_OPCODE_COND_NEGATE, )                                                                    \
    _(PIS_OPCODE_SIGN_EXTEND, )                                                                    \
    _(PIS_OPCODE_ZERO_EXTEND, )                                                                    \
    _(PIS_OPCODE_LEADING_ZEROES, )                                                                 \
    _(PIS_OPCODE_SIGNED_MUL, )                                                                     \
    _(PIS_OPCODE_SIGNED_MUL_OVERFLOW, )                                                            \
    _(PIS_OPCODE_UNSIGNED_MUL, )                                                                   \
    _(PIS_OPCODE_UNSIGNED_DIV_16, )                                                                \
    _(PIS_OPCODE_UNSIGNED_REM_16, )                                                                \
    _(PIS_OPCODE_SIGNED_DIV_16, )                                                                  \
    _(PIS_OPCODE_SIGNED_REM_16, )                                                                  \
    _(PIS_OPCODE_UNSIGNED_MUL_16, )                                                                \
    _(PIS_OPCODE_SIGNED_REM, )                                                                     \
    _(PIS_OPCODE_SIGNED_DIV, )                                                                     \
    _(PIS_OPCODE_UNSIGNED_REM, )                                                                   \
    _(PIS_OPCODE_UNSIGNED_DIV, )                                                                   \
    _(PIS_OPCODES_AMOUNT, )
STR_ENUM(pis_opcode, PIS_OPCODE, PACKED);

#define PIS_VAR_SPACE(_)                                                                           \
    _(PIS_VAR_SPACE_REG, )                                                                         \
    _(PIS_VAR_SPACE_TMP, )
STR_ENUM(pis_var_space, PIS_VAR_SPACE, PACKED);

#define PIS_OP_KIND(_)                                                                             \
    _(PIS_OP_KIND_IMM, )                                                                           \
    _(PIS_OP_KIND_VAR, )                                                                           \
    _(PIS_OP_KIND_RAM, )
STR_ENUM(pis_op_kind, PIS_OP_KIND, PACKED);

/// a type used to represent the offset of a variable in an operand space.
typedef u16 pis_var_off_t;

/// a variable operand. this is used to represent registers and tmps.
typedef union {
    pis_var_space_t space;
    pis_var_off_t offset;
    pis_size_t size;
} pis_var_t;

/// an immediate operand.
typedef union {
    u64 value;
} pis_imm_op_t;

/// a ram operand.
typedef union {
    u64 addr;
} pis_ram_op_t;

typedef union {
    pis_var_t var;
    pis_ram_op_t ram;
    pis_imm_op_t imm;
} pis_op_value_t;

typedef struct {
    pis_op_kind_t kind;
    pis_op_value_t v;
} PACKED pis_op_t;

typedef struct {
    u8 operands_amount;
    pis_opcode_t opcode;
    pis_op_t operands[PIS_INSN_MAX_OPERANDS_AMOUNT];
} PACKED pis_insn_t;

typedef struct {
    pis_insn_t insns[PIS_LIFT_MAX_INSNS_AMOUNT];
    u8 insns_amount;
    u8 machine_insn_len;
} pis_lift_res_t;

void pis_var_dump(pis_var_t var);
bool pis_var_equals(pis_var_t a, pis_var_t b);

void pis_op_dump(const pis_op_t* operand);
bool pis_op_equals(const pis_op_t* a, const pis_op_t* b);

void pis_insn_dump(const pis_insn_t* insn);
bool pis_insn_equals(const pis_insn_t* a, const pis_insn_t* b);

err_t pis_lift_res_emit(pis_lift_res_t* result, const pis_insn_t* insn);

void pis_lift_res_dump(const pis_lift_res_t* result);

void pis_lift_res_reset(pis_lift_res_t* result);

err_t pis_lift_res_get_last_emitted_insn(pis_lift_res_t* result, pis_insn_t** insn);

u64 pis_const_negate(u64 const_value, pis_size_t operand_size);

u64 pis_sign_extend_byte(i8 byte, pis_size_t desired_size);

bool pis_opcode_is_jmp(pis_opcode_t opcode);

bool pis_var_contains(pis_var_t var, pis_var_t sub_var);

bool pis_vars_intersect(pis_var_t var_a, pis_var_t var_b);
