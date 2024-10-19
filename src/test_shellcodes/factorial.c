#include <stddef.h>

size_t _start(size_t input) {
    size_t result = 0;
    for (size_t i = 1; i <= input; i++) {
        result += i;
    }
    return result;
}
