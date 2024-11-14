#include "../lib/arch/x86/lift.h"
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
    const u8 code[] = {0xF3, 0x0F, 0x1E, 0xFB};
    pis_lift_args_t args = {
        .machine_code = CURSOR_INIT(code, ARRAY_SIZE(code)),
        .machine_code_addr = 0,
    };
    CHECK_RETHROW(pis_x86_lift(&args, PIS_X86_CPUMODE_64_BIT));
    for (size_t i = 0; i < args.result.insns_amount; i++) {
        pis_insn_dump(&args.result.insns[i]);
        TRACE();
    }

cleanup:
    return err;
}
