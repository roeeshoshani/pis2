#include "../shellcode.h"

struct my_struct {
    u8 x[1337];
};

size_t SHELLCODE_ENTRY _start(struct my_struct* input, size_t len) {
    u8 checksum = 0;
    for (size_t i = 0; i < len; i++) {
        checksum += input[i].x[0];
    }
    return checksum;
}
