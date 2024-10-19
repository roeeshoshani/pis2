#include <stddef.h>

size_t _start(size_t a, size_t b) {
    while (b != 0) {
        int temp = b;
        b = a % b;
        a = temp;
    }
    return a;
}
