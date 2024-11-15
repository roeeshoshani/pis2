#include "cursor.h"
#include "except.h"
#include "pis.h"
#include "types.h"

bool cursor_eof(const cursor_t* cursor) {
    return cursor->cur >= cursor->end;
}

size_t cursor_index(const cursor_t* cursor) {
    return cursor->cur - cursor->start;
}

void cursor_advance(cursor_t* cursor, size_t n) {
    cursor->cur += n;
}

err_t cursor_next_n(cursor_t* cursor, size_t n, u8* bytes) {
    err_t err = SUCCESS;

    CHECK_CODE(cursor->cur + n <= cursor->end, PIS_ERR_EARLY_EOF);

    for (size_t i = 0; i < n; i++) {
        bytes[i] = cursor->cur[i];
    }

    cursor_advance(cursor, n);

cleanup:
    return err;
}

err_t cursor_next_1(cursor_t* cursor, u8* value) {
    err_t err = SUCCESS;
    CHECK_RETHROW(cursor_next_n(cursor, 1, value));
cleanup:
    return err;
}

static err_t
    cursor_next_n_endianness(cursor_t* cursor, size_t n, u8* bytes, pis_endianness_t endianness) {
    err_t err = SUCCESS;

    CHECK_RETHROW(cursor_next_n(cursor, n, bytes));
    pis_endianness_swap_bytes_if_needed(endianness, bytes, n);

cleanup:
    return err;
}

err_t cursor_next_2(cursor_t* cursor, u16* value, pis_endianness_t endianness) {
    err_t err = SUCCESS;
    CHECK_RETHROW(cursor_next_n_endianness(cursor, 2, (u8*) value, endianness));
cleanup:
    return err;
}

err_t cursor_next_4(cursor_t* cursor, u32* value, pis_endianness_t endianness) {
    err_t err = SUCCESS;
    CHECK_RETHROW(cursor_next_n_endianness(cursor, 4, (u8*) value, endianness));
cleanup:
    return err;
}

err_t cursor_next_8(cursor_t* cursor, u64* value, pis_endianness_t endianness) {
    err_t err = SUCCESS;
    CHECK_RETHROW(cursor_next_n_endianness(cursor, 8, (u8*) value, endianness));
cleanup:
    return err;
}

err_t cursor_peek_n(const cursor_t* cursor, size_t n, u8* bytes) {
    err_t err = SUCCESS;

    CHECK_CODE(cursor->cur + n <= cursor->end, PIS_ERR_EARLY_EOF);

    for (size_t i = 0; i < n; i++) {
        bytes[i] = cursor->cur[i];
    }

cleanup:
    return err;
}

err_t cursor_peek_1(const cursor_t* cursor, u8* value) {
    err_t err = SUCCESS;
    CHECK_RETHROW(cursor_peek_n(cursor, 1, value));
cleanup:
    return err;
}

static err_t cursor_peek_n_endianness(
    const cursor_t* cursor, size_t n, u8* bytes, pis_endianness_t endianness
) {
    err_t err = SUCCESS;

    CHECK_RETHROW(cursor_peek_n(cursor, n, bytes));
    pis_endianness_swap_bytes_if_needed(endianness, bytes, n);

cleanup:
    return err;
}

err_t cursor_peek_2(const cursor_t* cursor, u16* value, pis_endianness_t endianness) {
    err_t err = SUCCESS;
    CHECK_RETHROW(cursor_peek_n_endianness(cursor, 2, (u8*) value, endianness));
cleanup:
    return err;
}

err_t cursor_peek_4(const cursor_t* cursor, u32* value, pis_endianness_t endianness) {
    err_t err = SUCCESS;
    CHECK_RETHROW(cursor_peek_n_endianness(cursor, 4, (u8*) value, endianness));
cleanup:
    return err;
}

err_t cursor_peek_8(const cursor_t* cursor, u64* value, pis_endianness_t endianness) {
    err_t err = SUCCESS;
    CHECK_RETHROW(cursor_peek_n_endianness(cursor, 8, (u8*) value, endianness));
cleanup:
    return err;
}

err_t cursor_next_imm_ext(
    cursor_t* cursor,
    pis_size_t encoded_size,
    pis_size_t extended_size,
    imm_ext_kind_t ext_kind,
    pis_endianness_t endianness,
    u64* imm
) {
    err_t err = SUCCESS;

    CHECK(extended_size >= encoded_size);

    u64 extended_to_64_bits;
    switch (encoded_size) {
        case PIS_SIZE_1: {
            u8 value = 0;
            CHECK_RETHROW(cursor_next_1(cursor, &value));
            if (ext_kind == IMM_EXT_KIND_SIGN_EXTEND) {
                extended_to_64_bits = (i64) (i8) value;
            } else {
                extended_to_64_bits = value;
            }
            break;
        }
        case PIS_SIZE_2: {
            u16 value = 0;
            CHECK_RETHROW(cursor_next_2(cursor, &value, endianness));
            if (ext_kind == IMM_EXT_KIND_SIGN_EXTEND) {
                extended_to_64_bits = (i64) (i16) value;
            } else {
                extended_to_64_bits = value;
            }
            break;
        }
        case PIS_SIZE_4: {
            u32 value = 0;
            CHECK_RETHROW(cursor_next_4(cursor, &value, endianness));
            if (ext_kind == IMM_EXT_KIND_SIGN_EXTEND) {
                extended_to_64_bits = (i64) (i32) value;
            } else {
                extended_to_64_bits = value;
            }
            break;
        }
        case PIS_SIZE_8: {
            u64 value = 0;
            CHECK_RETHROW(cursor_next_8(cursor, &value, endianness));
            if (ext_kind == IMM_EXT_KIND_SIGN_EXTEND) {
                extended_to_64_bits = (i64) (i64) value;
            } else {
                extended_to_64_bits = value;
            }
            break;
        }
        default:
            UNREACHABLE();
    }

    *imm = extended_to_64_bits & pis_size_max_unsigned_value(extended_size);

cleanup:
    return err;
}
