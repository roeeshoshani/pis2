#include "arch/x86/ctx.h"
#include "except.h"
#include "pis.h"
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
    pis_lift_result_t result = {};

    pis_x86_ctx_t ctx = {
        .cpumode = PIS_X86_CPUMODE_32_BIT,
    };

    const u8 code[] = {0x89, 0x68, 0xff};

    CHECK_RETHROW(pis_x86_lift(&ctx, code, sizeof(code), &result));

    pis_lift_result_dump(&result);

cleanup:
    return err;
}
