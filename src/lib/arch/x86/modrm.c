#include "modrm.h"

modrm_t decode_modrm_byte(u8 modrm_byte) {
    return (modrm_t) {
        .mod = modrm_byte >> 6,
        .reg = (modrm_byte >> 3) & 0b111,
        .rm = modrm_byte & 0b111,
    };
}
