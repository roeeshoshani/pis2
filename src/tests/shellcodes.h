#pragma once

#include "types.h"

typedef struct {
  u8* code;
  size_t code_len;
} test_shellcode_t;

#define DECLARE_SHELLCODE()

#define SHELLCODE(NAME) ((test_shellcode_t) {.code = })
