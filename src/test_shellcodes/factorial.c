#include <stddef.h>

size_t _start(size_t input) {
    size_t result = 1;
    for (size_t i = 2; i <= input; i++) {
        result *= i;
    }
    return result;
}
