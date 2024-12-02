#pragma once

#include "except.h"
#include "types.h"

typedef u32 bitmap_elem_t;

typedef struct {
    size_t bit_size;
    bitmap_elem_t elems[0];
} bitmap_t;

#define BITMAP_ELEM_BIT_SIZE (sizeof(bitmap_elem_t) * 8)

#define BITMAP_ELEMS_AMOUNT(BIT_SIZE) ((BIT_SIZE) / (BITMAP_ELEM_BIT_SIZE))

#define BITMAP_DECLARE(NAME, BIT_SIZE)                                                             \
    bitmap_t NAME;                                                                                 \
    bitmap_elem_t NAME##_bitmap_elems[BITMAP_ELEMS_AMOUNT(BIT_SIZE)]

void bitmap_init(bitmap_t* bitmap, size_t bit_size);

void bitmap_clear(bitmap_t* bitmap);

err_t bitmap_set(bitmap_t* bitmap, size_t bit_index, bool value);

err_t bitmap_get(const bitmap_t* bitmap, size_t bit_index, bool* value);

err_t bitmap_swap(bitmap_t* bitmap, size_t bit_index, bool* value);
