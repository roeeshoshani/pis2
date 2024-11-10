#include "bump_allocator.h"

#define BUMP_ALLOCATOR_ALIGNMENT 16

#define BUMP_ALLOCATOR_ALIGN_UP(X)                                                                 \
    (((X + (BUMP_ALLOCATOR_ALIGNMENT - 1)) / BUMP_ALLOCATOR_ALIGNMENT) * BUMP_ALLOCATOR_ALIGNMENT)

#define STORAGE_SIZE (1024)

static u8 g_storage[STORAGE_SIZE] __attribute__((aligned(BUMP_ALLOCATOR_ALIGNMENT))) = {};
static size_t g_offset = 0;

void* bump_alloc(size_t size) {
    size_t new_off = BUMP_ALLOCATOR_ALIGN_UP(g_offset + size);
    if (new_off > STORAGE_SIZE) {
        return NULL;
    }

    void* result = g_storage + g_offset;

    g_offset = new_off;

    return result;
}
