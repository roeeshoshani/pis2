#include "bitmap.h"
#include "except.h"
#include <string.h>

void bitmap_init(bitmap_t* bitmap, size_t bit_size) {
    bitmap->bit_size = bit_size;
    bitmap_clear(bitmap);
}

void bitmap_clear(bitmap_t* bitmap) {
    size_t elems_amount = bitmap->bit_size;
    memset(&bitmap->elems, 0, elems_amount * sizeof(bitmap_elem_t));
}

typedef struct {
    size_t elem_index;
    size_t bit_value;
} bit_info_t;

static err_t get_bit_info(const bitmap_t* bitmap, size_t bit_index, bit_info_t* indexes) {
    err_t err = SUCCESS;

    CHECK(bit_index < bitmap->bit_size);

    indexes->elem_index = bit_index / BITMAP_ELEM_BIT_SIZE;
    indexes->bit_value = ((bitmap_elem_t) 1 << bit_index % BITMAP_ELEM_BIT_SIZE);

cleanup:
    return err;
}

err_t bitmap_set(bitmap_t* bitmap, size_t bit_index, bool value) {
    err_t err = SUCCESS;

    bit_info_t bit_info = {};
    CHECK_RETHROW(get_bit_info(bitmap, bit_index, &bit_info));

    bitmap_elem_t* elem = &bitmap->elems[bit_info.elem_index];

    if (value) {
        *elem |= bit_info.bit_value;
    } else {
        *elem &= (~bit_info.bit_value);
    }

cleanup:
    return err;
}

err_t bitmap_get(const bitmap_t* bitmap, size_t bit_index, bool* value) {
    err_t err = SUCCESS;

    bit_info_t bit_info = {};
    CHECK_RETHROW(get_bit_info(bitmap, bit_index, &bit_info));

    *value = bitmap->elems[bit_info.elem_index] & bit_info.bit_value;

cleanup:
    return err;
}

err_t bitmap_swap(bitmap_t* bitmap, size_t bit_index, bool* value) {
    err_t err = SUCCESS;

    bit_info_t bit_info = {};
    CHECK_RETHROW(get_bit_info(bitmap, bit_index, &bit_info));

    bitmap_elem_t* elem = &bitmap->elems[bit_info.elem_index];

    // remember the new value that we want to set this bit to
    bool new_value = *value;

    // return the current state of the bit to the caller
    *value = (*elem) & bit_info.bit_value;

    if (new_value) {
        *elem |= bit_info.bit_value;
    } else {
        *elem &= (~bit_info.bit_value);
    }

cleanup:
    return err;
}
