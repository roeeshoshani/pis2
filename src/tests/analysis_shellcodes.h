#pragma once

#include "shellcodes.h"

#define EACH_ANALYSIS_SHELLCODE(_, ...) _(struct_size, ##__VA_ARGS__)

EACH_ANALYSIS_SHELLCODE(DECLARE_SHELLCODE, analysis);
