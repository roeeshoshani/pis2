#include "my_std.h"

void* memcpy(void* dest, const void* src, size_t n) {
    char* d = dest;
    const char* s = src;
    while (n--) {
        *d++ = *s++;
    }
    return dest;
}


void* memset(void* s, int c, size_t n) {
    unsigned char* p = s;
    while (n--) {
        *p++ = (unsigned char) c;
    }
    return s;
}

void __attribute__((noreturn)) abort() {
    __attribute__((noreturn)) void (*fn)() = NULL;
    fn();
}

void assert(bool cond) {
    if (!cond) {
        abort();
    }
}

size_t strlen(const char* str) {
    size_t length = 0;
    while (str[length] != '\0') {
        length++;
    }
    return length;
}
