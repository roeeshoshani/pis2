#pragma once

#include "utils.h"

#define STR_ENUM(NAME, FIELDS_FN, ATTRS)                                                           \
    typedef enum ATTRS {                                                                           \
        FIELDS_FN(STR_ENUM_BODY_FIELDS_CALLBACK)                                                   \
    } NAME##_t;                                                                                    \
    const char* NAME##_to_str(NAME##_t value)

#define STR_ENUM_BODY_FIELDS_CALLBACK(NAME, VALUE) NAME VALUE,

#define STR_ENUM_IMPL(NAME, FIELDS_FN)                                                             \
    static const char* NAME##_to_long_str(NAME##_t value) {                                        \
        switch (value) {                                                                           \
            FIELDS_FN(STR_ENUM_IMPL_FIELDS_CALLBACK)                                               \
            default:                                                                               \
                return STRINGIFY(FIELDS_FN) "_INVALID_VALUE";                                      \
        }                                                                                          \
    }                                                                                              \
    const char* NAME##_to_str(NAME##_t value) {                                                    \
        const char* long_str = NAME##_to_long_str(value);                                          \
        return long_str + sizeof(STRINGIFY(FIELDS_FN));                                            \
    }

#define STR_ENUM_IMPL_FIELDS_CALLBACK(NAME, VALUE)                                                 \
    case NAME:                                                                                     \
        return STRINGIFY(NAME);
