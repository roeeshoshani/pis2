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
        0xf3, 0x0f, 0x1e, 0xfa, 0x31, 0xd2, 0x31, 0xc0, 0x48, 0x39, 0xf2,
        0x74, 0x0f, 0x48, 0x69, 0xca, 0x39, 0x05, 0x00, 0x00, 0x48, 0xff,
        0xc2, 0x02, 0x04, 0x0f, 0xeb, 0xec, 0x0f, 0xb6, 0xc0, 0xc3,
    };

    cfg_builder_t cfg_builder = {};
    CHECK_RETHROW(cfg_build(&cfg_builder, &pis_arch_def_x86_64, code, ARRAY_SIZE(code), 0));

    cdfg_builder_t cdfg_builder = {};
    CHECK_RETHROW(cdfg_build(&cdfg_builder, &cfg_builder.cfg));

    cdfg_dump_dot(&cdfg_builder.cdfg);

cleanup:
    return err;
}
