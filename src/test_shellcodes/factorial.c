#include <stddef.h>

#include "shellcode.h"

void _start(size_t input) {
    size_t result = 0;
    for (size_t i = 1; i <= input; i++) {
        result += i;
    }
    SHELLCODE_FINISH(result);
}
