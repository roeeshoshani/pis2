#pragma once

#include "utils.h"

#define STR_ENUM(NAME, FIELDS_FN)                                                                                              \
    typedef enum {                                                                                                             \
        FIELDS_FN(STR_ENUM_BODY_FIELDS_CALLBACK)                                                                               \
    } NAME##_t;                                                                                                                \
    const char* NAME##_to_str(NAME##_t value)

#define STR_ENUM_BODY_FIELDS_CALLBACK(NAME, VALUE) NAME VALUE,

#define STR_ENUM_IMPL(NAME, FIELDS_FN)                                                                                         \
    const char* NAME##_to_str(NAME##_t value) {                                                                                \
        switch (value) {                                                                                                       \
            FIELDS_FN(STR_ENUM_IMPL_FIELDS_CALLBACK)                                                                           \
        default:                                                                                                               \
            return "invalid " STRINGIFY(NAME##_t) " value>";                                                                   \
        }                                                                                                                      \
    }

#define STR_ENUM_IMPL_FIELDS_CALLBACK(NAME, VALUE)                                                                             \
    case NAME:                                                                                                                 \
        return STRINGIFY(NAME);
