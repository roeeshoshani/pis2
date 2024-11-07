#pragma once

#include "../lib/emu.h"
#include "../lib/pis.h"
#include "../lib/types.h"

typedef err_t (*test_fn_t)();

typedef struct {
    test_fn_t fn;
    const char* name;
} test_entry_t;

extern test_entry_t __start_test_entries[];
extern test_entry_t __stop_test_entries[];

typedef struct {
    const pis_insn_t* insns;
    size_t amount;
} expected_insns_t;

typedef struct {
    const u8* code;
    size_t len;
} code_t;

#define EXPECTED_INSNS(...)                                                                        \
    ({                                                                                             \
        (expected_insns_t) {                                                                       \
            .insns = (pis_insn_t[]) {__VA_ARGS__},                                                 \
            .amount = sizeof((pis_insn_t[]) {__VA_ARGS__}) / sizeof(pis_insn_t),                   \
        };                                                                                         \
    })

#define CODE(...)                                                                                  \
    ({                                                                                             \
        static const u8 code[] = {__VA_ARGS__};                                                    \
        (code_t) {                                                                                 \
            .code = code,                                                                          \
            .len = ARRAY_SIZE(code),                                                               \
        };                                                                                         \
    })

#define DEFINE_TEST(NAME)                                                                          \
    static err_t NAME();                                                                           \
    static test_entry_t __attribute__((used, section("test_entries"))) NAME##_test_entry = {       \
        .fn = NAME,                                                                                \
        .name = STRINGIFY(NAME),                                                                   \
    };                                                                                             \
    static err_t NAME()

#define MAGIC64_1 (0x1122334455667788ULL)
#define MAGIC64_2 (0xaabbccddaabbccddULL)
#define MAGIC64_3 (0x1a2b3c4d1a2b3c4dULL)

extern pis_emu_t g_emu;
