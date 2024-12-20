#pragma once

#include "../lib/types.h"
#include "../lib/utils.h"

typedef struct {
    u8* code;
    u8* code_end;
    const char* name;
} shellcode_t;

#define EACH_ARCH(_, ...)                                                                          \
    _(i686, ##__VA_ARGS__)                                                                         \
    _(x86_64, ##__VA_ARGS__)                                                                       \
    _(mipsbe32r1, ##__VA_ARGS__)                                                                   \
    _(mipsel32r1, ##__VA_ARGS__)

#define _ARCH_DEFINE_SHELLCODE_FIELD(ARCH) shellcode_t ARCH;

typedef struct {
    EACH_ARCH(_ARCH_DEFINE_SHELLCODE_FIELD);
} per_arch_shellcode_t;

#define _DECLARE_ARCH_SPECIFIC_SHELLCODE(ARCH, NAME, DIR)                                          \
    extern u8 __start_shellcode_##DIR##_##NAME##_##ARCH[];                                         \
    extern u8 __end_shellcode_##DIR##_##NAME##_##ARCH[];

#define _ARCH_SPECIFIC_SHELLCODE(ARCH, NAME, DIR)                                                  \
    {                                                                                              \
        .code = __start_shellcode_##DIR##_##NAME##_##ARCH,                                         \
        .code_end = __end_shellcode_##DIR##_##NAME##_##ARCH, .name = STRINGIFY(NAME##_##ARCH)      \
    }

#define DECLARE_SHELLCODE(NAME, DIR) EACH_ARCH(_DECLARE_ARCH_SPECIFIC_SHELLCODE, NAME, DIR);

#define _ARCH_INIT_SHELLCODE_FIELD(ARCH, NAME, DIR)                                                \
    .ARCH = _ARCH_SPECIFIC_SHELLCODE(ARCH, NAME, DIR),
#define DEFINE_SHELLCODE(NAME, DIR)                                                                \
    const per_arch_shellcode_t shellcode_##NAME = {                                                \
        EACH_ARCH(_ARCH_INIT_SHELLCODE_FIELD, NAME, DIR)};

#define SHELLCODE_BASE_ADDR 0x10000000
