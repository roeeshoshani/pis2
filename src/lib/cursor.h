#pragma once

#include "types.h"
#include "except.h"
#include "pis.h"

#define CURSOR_INIT(PTR, LEN) { .start = (PTR), .cur = (PTR), .end = ((PTR) + (LEN)) }

typedef struct {
    const u8* start;
    const u8* cur;
    const u8* end;
} cursor_t;

typedef enum {
    /// use zero extension
    CURSOR_IMM_EXT_KIND_ZERO,
    /// use sign extension
    CURSOR_IMM_EXT_KIND_SIGN,
} cursor_imm_ext_kind_t;

bool cursor_eof(const cursor_t* cursor);

size_t cursor_index(const cursor_t* cursor);

void cursor_advance(cursor_t* cursor, size_t n);

err_t cursor_next_n(cursor_t* cursor, size_t n, u8* bytes);

err_t cursor_next_1(cursor_t* cursor, u8* value);

err_t cursor_next_2(cursor_t* cursor, u16* value, pis_endianness_t endianness);

err_t cursor_next_4(cursor_t* cursor, u32* value, pis_endianness_t endianness);

err_t cursor_next_8(cursor_t* cursor, u64* value, pis_endianness_t endianness);

err_t cursor_peek_n(const cursor_t* cursor, size_t n, u8* bytes);

err_t cursor_peek_1(const cursor_t* cursor, u8* value);

err_t cursor_peek_2(const cursor_t* cursor, u16* value, pis_endianness_t endianness);

err_t cursor_peek_4(const cursor_t* cursor, u32* value, pis_endianness_t endianness);

err_t cursor_peek_8(const cursor_t* cursor, u64* value, pis_endianness_t endianness);

err_t cursor_next_imm_ext(
    cursor_t* cursor,
    pis_operand_size_t encoded_size,
    pis_operand_size_t extended_size,
    cursor_imm_ext_kind_t ext_kind,
    pis_endianness_t endianness,
    u64* imm
);
