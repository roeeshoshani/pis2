#include "ctx.h"
#include "distorm/include/distorm.h"

err_t pis_x86_lift(
    const pis_x86_ctx_t* ctx,
    const u8* machine_code,
    size_t machine_code_len,
    u64 machine_code_addr,
    pis_lift_result_t* result
) {
    err_t err = SUCCESS;
    _CodeInfo codeinfo = {
        .code = machine_code,
        .codeLen = machine_code_len,
        .codeOffset = 0,
        .dt = (_DecodeType) ctx->cpumode,
        .features = DF_NONE,
    };

    _DInst insn;
    unsigned int insn_count = 0;
    _DecodeResult decode_result = distorm_decompose(&codeinfo, &insn, 1, &insn_count);
    CHECK(decode_result == DECRES_SUCCESS || decode_result == DECRES_MEMORYERR);

    UNUSED(machine_code_addr);
    UNUSED(result);

cleanup:
    return err;
}
