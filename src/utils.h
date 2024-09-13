#pragma once

#define _STRINGIFY(X) #X
#define STRINGIFY(X) _STRINGIFY(X)

#define UNUSED(X) (void) X

#define GET_BIT_VALUE(VALUE, BIT_INDEX) (((VALUE) >> (BIT_INDEX)) & 1)

#define ARRAY_SIZE(ARRAY) ((sizeof(ARRAY)) / (sizeof(*(ARRAY))))
