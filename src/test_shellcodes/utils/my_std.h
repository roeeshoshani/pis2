#pragma once

#include <stdbool.h>
#include <stddef.h>

static inline int isdigit(int c) {
    return (c >= '0' && c <= '9');
}

static inline int isalpha(int c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
}

static inline int isxdigit(int c) {
    return ((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f'));
}

void* memcpy(void* dest, const void* src, size_t n);

void* memset(void* s, int c, size_t n);

void assert(bool cond);

void __attribute__((noreturn)) abort();

size_t strlen(const char* str);
