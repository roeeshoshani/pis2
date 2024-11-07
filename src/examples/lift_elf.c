#include "arch/x86/ctx.h"
#include "except.h"
#include "pis.h"
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define CLEANUP_FD(FD)                                                                             \
    do {                                                                                           \
        if ((FD) != -1) {                                                                          \
            close(FD);                                                                             \
            FD = -1;                                                                               \
        }                                                                                          \
    } while (0)

#define CHECK_ERRNO(EXPR) CHECK_TRACE(EXPR, "error (errno = %d)", errno)

// define an example trace function
void trace(const char* format, ...) {
    va_list args;
    va_start(args, format);
    vprintf(format, args);
    va_end(args);
}

int main(int argc, char** argv) {
    err_t err = SUCCESS;
    int fd = -1;
    struct stat stat_buf = {};
    void* mapping = NULL;

    if (argc != 2) {
        printf("usage: %s <elf file>\n", argv[0]);
        return -1;
    }

    static char cmd[4096];
    memset(cmd, 0, sizeof(cmd));
    sprintf(cmd, "objcopy -j .text -O binary %s build/lib/example.text.bin", argv[1]);

    errno = 0;
    int objcopy_res = system(cmd);
    CHECK_ERRNO(errno == 0);
    CHECK(objcopy_res == 0);

    fd = open("build/lib/example.text.bin", O_RDONLY);
    CHECK_ERRNO(fd != -1);

    CHECK_ERRNO(fstat(fd, &stat_buf) == 0);

    mapping = mmap(NULL, stat_buf.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
    CHECK(mapping != NULL && mapping != MAP_FAILED);

    u8* code = mapping;
    size_t code_len = stat_buf.st_size;
    size_t cur_offset = 0;

    pis_lift_result_t result = {};

    pis_x86_ctx_t ctx = {
        .cpumode = PIS_X86_CPUMODE_64_BIT,
    };
    while (cur_offset < code_len) {
        pis_lift_result_reset(&result);

        TRACE("TRYING TO PARSE INSN AT OFFSET 0x%lx", (unsigned long) cur_offset);

        CHECK_RETHROW(
            pis_x86_lift(&ctx, code + cur_offset, code_len - cur_offset, cur_offset, &result)
        );

        TRACE("INSN AT OFFSET 0x%lx", (unsigned long) cur_offset);
        pis_lift_result_dump(&result);
        TRACE();

        cur_offset += result.machine_insn_len;
    }

cleanup:
    if (mapping != NULL && mapping != MAP_FAILED) {
        munmap(mapping, stat_buf.st_size);
    }
    CLEANUP_FD(fd);
    return err;
}
