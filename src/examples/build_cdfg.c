#include "../lib/arch/mips/lift.h"
#include "../lib/arch/x86/lift.h"
#include "../lib/cdfg.h"
#include "../lib/cfg.h"
#include "../lib/except.h"
#include <stdarg.h>
#include <stdio.h>

// define an example trace function
void trace(const char* format, ...) {
    va_list args;
    va_start(args, format);
    vprintf(format, args);
    va_end(args);
}

int main() {
    err_t err = SUCCESS;
    const u8 code[] = {
        0x00, 0x00, 0x18, 0x25, 0x00, 0x00, 0x10, 0x25, 0x14, 0x65, 0x00, 0x03,
        0x24, 0x63, 0x00, 0x01, 0x03, 0xe0, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00,
        0x90, 0x86, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46, 0x10, 0x21,
        0x30, 0x42, 0x00, 0xff, 0x10, 0x00, 0xff, 0xf7, 0x24, 0x84, 0x05, 0x39,
    };

    cfg_builder_t cfg_builder = {};
    CHECK_RETHROW(cfg_build(&cfg_builder, &pis_arch_def_mipsbe32r1, code, ARRAY_SIZE(code), 0));

    cdfg_builder_t cdfg_builder = {};
    CHECK_RETHROW(cdfg_build(&cdfg_builder, &cfg_builder.cfg));

    cdfg_dump_dot(&cdfg_builder.cdfg);

cleanup:
    return err;
}
