#include "analysis_shellcodes.h"
#include "../lib/arch/mips/lift.h"
#include "../lib/arch/x86/lift.h"
#include "../lib/arch_def.h"
#include "../lib/cdfg.h"
#include "../lib/cfg.h"
#include "shellcodes.h"
#include "test_utils.h"

EACH_ANALYSIS_SHELLCODE(DEFINE_SHELLCODE, analysis);

typedef err_t (*analysis_verification_fn_t)(const cdfg_t* cdfg);

static err_t verify_analysis_arch(
    const pis_arch_def_t* arch,
    const shellcode_t* shellcode,
    analysis_verification_fn_t verification
) {
    err_t err = SUCCESS;

    size_t shellcode_len = shellcode->code_end - shellcode->code;

    cfg_builder_t cfg_builder = {};
    CHECK_RETHROW(cfg_build(&cfg_builder, arch, shellcode->code, shellcode_len, SHELLCODE_BASE_ADDR)
    );

    cdfg_builder_t cdfg_builder = {};
    CHECK_RETHROW(cdfg_build(&cdfg_builder, &cfg_builder.cfg));

    CHECK_RETHROW(cdfg_optimize(&cdfg_builder.cdfg));

    CHECK_RETHROW(verification(&cdfg_builder.cdfg));

cleanup:
    return err;
}

static err_t verify_analysis(
    const per_arch_shellcode_t* shellcode, analysis_verification_fn_t verification
) {
    err_t err = SUCCESS;

    CHECK_RETHROW(verify_analysis_arch(&pis_arch_def_x86_64, &shellcode->x86_64, verification));
    CHECK_RETHROW(verify_analysis_arch(&pis_arch_def_i686, &shellcode->i686, verification));
    CHECK_RETHROW(
        verify_analysis_arch(&pis_arch_def_mipsbe32r1, &shellcode->mipsbe32r1, verification)
    );
    CHECK_RETHROW(
        verify_analysis_arch(&pis_arch_def_mipsel32r1, &shellcode->mipsel32r1, verification)
    );

cleanup:
    return err;
}

static err_t verify_struct_size_analysis(const cdfg_t* cdfg) {
    err_t err = SUCCESS;

    UNUSED(cdfg);
    goto cleanup;

cleanup:
    return err;
}

DEFINE_TEST(test_analysis_struct_size) {
    err_t err = SUCCESS;

    CHECK_RETHROW(verify_analysis(&shellcode_struct_size, verify_struct_size_analysis));

cleanup:
    return err;
}
