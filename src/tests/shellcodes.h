#pragma once

#include "types.h"

typedef struct {
    u8* code;
    size_t code_len;
} shellcode_t;

#define EACH_ARCH(_, ...)                                                                          \
    _(i386, ##__VA_ARGS__)                                                                         \
    _(x86_64, ##__VA_ARGS__)

#define _ARCH_DEFINE_SHELLCODE_FIELD(ARCH) shellcode_t ARCH;

typedef struct {
    EACH_ARCH(_ARCH_DEFINE_SHELLCODE_FIELD);
} per_arch_shellcode_t;

#define DECLARE_ARCH_SPECIFIC_SHELLCODE(ARCH, NAME)                                                \
    extern u8 __start_shellcode_##NAME##_##ARCH[];                                                 \
    extern u8 __end_shellcode_##NAME##_##ARCH[];

#define ARCH_SPECIFIC_SHELLCODE(ARCH, NAME)                                                        \
    ((shellcode_t) {                                                                               \
        .code = __start_shellcode_##NAME##_##ARCH,                                                 \
        .code_len = __end_shellcode_##NAME##_##ARCH - __start_shellcode_##NAME##_##ARCH,           \
    })

#define DECLARE_SHELLCODE(NAME) EACH_ARCH(DECLARE_ARCH_SPECIFIC_SHELLCODE, NAME)

// #define _ARCH_INIT_SHELLCODE_FIELD(ARCH, NAME) .ARCH = ARCH_SPECIFIC_SHELLCODE(ARCH, NAME)
#define _ARCH_INIT_SHELLCODE_FIELD(ARCH, NAME) .ARCH = ARCH_SPECIFIC_SHELLCODE(ARCH, NAME),
#define SHELLCODE(NAME) ((per_arch_shellcode_t) {EACH_ARCH(_ARCH_INIT_SHELLCODE_FIELD, NAME)})

DECLARE_SHELLCODE(factorial);
