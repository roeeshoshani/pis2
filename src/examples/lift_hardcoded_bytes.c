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
    const u8 code[] = {
        0xf3,
        0x0f,
        0x1e,
        0xfa,
        0x39,
        0xfe,
        0x89,
        0xf8,
        0x0f,
        0x43,
        0xc6,
        0xc3,
    };

    u64 off = 0;
    while (off < ARRAY_SIZE(code)) {
        pis_lift_args_t args = {
            .machine_code = CURSOR_INIT(code + off, ARRAY_SIZE(code) - off),
            .machine_code_addr = 0,
        };
        TRACE("LIFTING AT OFFSET 0x%lx", off);
        TRACE("====");
        CHECK_RETHROW(pis_x86_lift(&args, PIS_X86_CPUMODE_64_BIT));
        for (size_t i = 0; i < args.result.insns_amount; i++) {
            pis_insn_dump(&args.result.insns[i]);
            TRACE();
        }
        TRACE("====");
        TRACE();
        off += args.result.machine_insn_len;
    }

cleanup:
    return err;
}
