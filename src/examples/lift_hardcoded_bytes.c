#include "../lib/arch/x86/ctx.h"
#include "../lib/except.h"
#include "../lib/pis.h"
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
    pis_x86_ctx_t ctx = {
        .cpumode = PIS_X86_CPUMODE_64_BIT,
    };
    const u8 code[] = {0xF3, 0x0F, 0x1E, 0xFB};
    pis_lift_result_t result = {};
    CHECK_RETHROW(pis_x86_lift(&ctx, code, ARRAY_SIZE(code), 0, &result));
    for (size_t i = 0; i < result.insns_amount; i++) {
        pis_insn_dump(&result.insns[i]);
        TRACE();
    }

cleanup:
    return err;
}
