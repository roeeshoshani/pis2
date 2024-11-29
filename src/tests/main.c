#include "test_utils.h"
#include <stdarg.h>
#include <stdio.h>

pis_emu_t g_emu;

// define an example trace function
void trace(const char* format, ...) {
    va_list args;
    va_start(args, format);
    vprintf(format, args);
    va_end(args);
}

int main() {
    err_t err = SUCCESS;

    for (test_entry_t* cur = __start_test_entries; cur < __stop_test_entries; cur++) {
        TRACE("[*] %s", cur->name);
        CHECK_RETHROW_TRACE(cur->fn(), "[!] %s", cur->name);
    }

    TRACE(":)");

cleanup:
    return err;
}
