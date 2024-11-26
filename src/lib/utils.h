#pragma once

#define _STRINGIFY(X) #X
#define STRINGIFY(X) _STRINGIFY(X)

#define UNUSED(X) (void) X

#define GET_BIT_VALUE(VALUE, BIT_INDEX) (((VALUE) >> (BIT_INDEX)) & 1)
#define GET_BITS(VALUE, START_BIT_INDEX, BITS_AMOUNT)                                              \
    (((VALUE) >> (START_BIT_INDEX)) & ((1 << BITS_AMOUNT) - 1))

#define ARRAY_SIZE(ARRAY) ((sizeof(ARRAY)) / (sizeof(*(ARRAY))))

#define MAX(A, B) ((A) >= (B) ? (A) : (B))
#define MIN(A, B) ((A) <= (B) ? (A) : (B))

#define USED __attribute__((used))
#define UNUSED_ATTR __attribute__((unused))

#define PACKED __attribute__((packed))
