#pragma once

#include "types.h"

typedef struct {
  u8 mod;
  u8 reg;
  u8 rm;
} modrm_t;

modrm_t decode_modrm_byte(u8 modrm_byte);
