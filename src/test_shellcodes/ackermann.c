#include "shellcode.h"

static size_t ackermann(size_t m, size_t n) {
    if (m == 0) {
        return n + 1;
    } else if (n == 0) {
        return ackermann(m - 1, 1);
    } else {
        return ackermann(m - 1, ackermann(m, n - 1));
    }
}

size_t SHELLCODE_ENTRY _start(size_t m, size_t n) {
    return ackermann(m, n);
}
