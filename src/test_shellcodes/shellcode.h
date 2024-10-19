#pragma once

#include <stddef.h>

typedef void (*shellcode_finish_t)(size_t result);

#define SHELLCODE_FINISH(RESULT) ((shellcode_finish_t)NULL)(RESULT)
