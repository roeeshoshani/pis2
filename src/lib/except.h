#pragma once

#include "errors.h"
#include "trace.h"
#include <stdbool.h>

#define SUCCESS (PIS_ERR_SUCCESS)

#if defined(PIS_MINI)
#    define CHECK_TRACE_CODE(EXPR, CODE, FMT, ...)                                                 \
        do {                                                                                       \
            if (!(EXPR)) {                                                                         \
                err = CODE;                                                                        \
                goto cleanup;                                                                      \
            }                                                                                      \
        } while (0)
#else // defined(PIS_MINI)
#    define CHECK_TRACE_CODE(EXPR, CODE, FMT, ...)                                                 \
        do {                                                                                       \
            if (!(EXPR)) {                                                                         \
                err = CODE;                                                                        \
                TRACE_WITH_INFO(FMT, ##__VA_ARGS__);                                               \
                goto cleanup;                                                                      \
            }                                                                                      \
        } while (0)
#endif // defined(PIS_MINI)

#define CHECK_TRACE(EXPR, FMT, ...) CHECK_TRACE_CODE(EXPR, PIS_ERR_GENERIC, FMT, ##__VA_ARGS__)
#define CHECK_CODE(EXPR, CODE) CHECK_TRACE_CODE(EXPR, CODE, "error")
#define CHECK(EXPR) CHECK_CODE(EXPR, PIS_ERR_GENERIC)

#define CHECK_FAIL_TRACE_CODE(CODE, FMT, ...) CHECK_TRACE_CODE(false, CODE, FMT, ##__VA_ARGS__)
#define CHECK_FAIL_TRACE(FMT, ...) CHECK_TRACE(false, FMT, ##__VA_ARGS__)
#define CHECK_FAIL_CODE(CODE) CHECK_CODE(false, CODE)
#define CHECK_FAIL() CHECK(false)

#define UNREACHABLE() CHECK_FAIL_TRACE("uncreachable code was reached")

#define TODO() CHECK_FAIL_TRACE("unimplemented code was reached")

#define CHECK_RETHROW(EXPR)                                                                        \
    do {                                                                                           \
        err_t ___res = (EXPR);                                                                     \
        CHECK_TRACE_CODE(___res == SUCCESS, ___res, "rethrow");                                    \
    } while (0)

#define CHECK_RETHROW_VERBOSE(EXPR)                                                                \
    do {                                                                                           \
        err_t ___res = (EXPR);                                                                     \
        CHECK_TRACE_CODE(___res == SUCCESS, ___res, "rethrow from (" #EXPR ")");                   \
    } while (0)

#define CHECK_RETHROW_TRACE(EXPR, FMT, ...)                                                        \
    do {                                                                                           \
        err_t ___res = (EXPR);                                                                     \
        CHECK_TRACE_CODE(___res == SUCCESS, ___res, FMT, ##__VA_ARGS__);                           \
    } while (0)

#define SUCCESS_CLEANUP()                                                                          \
    do {                                                                                           \
        err = SUCCESS;                                                                             \
        goto cleanup;                                                                              \
    } while (0)
