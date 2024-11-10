#include "endianness.h"

pis_endianness_t pis_endianness_native() {
#if __BYTE_ORDER == __LITTLE_ENDIAN
    return PIS_ENDIANNESS_LITTLE;
#elif __BYTE_ORDER == __BIG_ENDIAN
    return PIS_ENDIANNESS_BIG;
#else
#    error "unknown endianness"
#endif
}

void pis_endianness_swap_bytes_if_needed(pis_endianness_t endianness, u8* bytes, size_t len) {
    if (endianness != pis_endianness_native()) {
        // endianness is not the same as native, reverse the bytes
        for (size_t i = 0; i < len / 2; i++) {
            u8 tmp = bytes[i];
            bytes[i] = bytes[len - i - 1];
            bytes[len - i - 1] = tmp;
        }
    }
}
