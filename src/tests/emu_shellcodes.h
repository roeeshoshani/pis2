#pragma once

#include "shellcodes.h"

#define EACH_EMU_SHELLCODE(_, ...)                                                                          \
    _(factorial, ##__VA_ARGS__)                                                                                   \
    _(gcd, ##__VA_ARGS__)                                                                                         \
    _(ackermann, ##__VA_ARGS__)                                                                                   \
    _(json, ##__VA_ARGS__)                                                                                        \
    _(regex, ##__VA_ARGS__)                                                                                       \
    _(chacha20, ##__VA_ARGS__)

EACH_EMU_SHELLCODE(DECLARE_SHELLCODE, emu);
