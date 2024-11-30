#include "analysis_shellcodes.h"
#include "../lib/arch/mips/lift.h"
#include "../lib/arch/x86/lift.h"
#include "../lib/arch_def.h"
#include "../lib/cdfg.h"
#include "../lib/cdfg/query.h"
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
    CHECK_RETHROW_VERBOSE(
        cfg_build(&cfg_builder, arch, shellcode->code, shellcode_len, SHELLCODE_BASE_ADDR)
    );

    cdfg_builder_t cdfg_builder = {};
    CHECK_RETHROW_VERBOSE(cdfg_build(&cdfg_builder, &cfg_builder.cfg));

    CHECK_RETHROW_VERBOSE(cdfg_optimize(&cdfg_builder.cdfg));

    CHECK_RETHROW_VERBOSE(verification(&cdfg_builder.cdfg));

cleanup:
    return err;
}

static err_t verify_analysis(
    const per_arch_shellcode_t* shellcode, analysis_verification_fn_t verification
) {
    err_t err = SUCCESS;

    CHECK_RETHROW_VERBOSE(
        verify_analysis_arch(&pis_arch_def_x86_64, &shellcode->x86_64, verification)
    );
    CHECK_RETHROW_VERBOSE(verify_analysis_arch(&pis_arch_def_i686, &shellcode->i686, verification));
    CHECK_RETHROW_VERBOSE(
        verify_analysis_arch(&pis_arch_def_mipsbe32r1, &shellcode->mipsbe32r1, verification)
    );
    CHECK_RETHROW_VERBOSE(
        verify_analysis_arch(&pis_arch_def_mipsel32r1, &shellcode->mipsel32r1, verification)
    );

cleanup:
    return err;
}

static err_t verify_struct_size_analysis(const cdfg_t* cdfg) {
    err_t err = SUCCESS;

    bool found_struct_size = false;
    size_t struct_size = 0;

    for (size_t i = 0; i < cdfg->nodes_amount; i++) {
        cdfg_node_id_t node_id = {.id = i};
        const cdfg_node_t* node = &cdfg->node_storage[i];

        if (node->kind != CDFG_NODE_KIND_CALC) {
            continue;
        }

        if (node->content.calc.calculation != CDFG_CALCULATION_ADD) {
            continue;
        }

        // we expect one of the inputs of the add node to be the first parameter of the function.
        cdfg_binop_input_find_res_t add_node_find_res = {};
        CHECK_RETHROW(
            cdfg_find_binop_input(cdfg, node_id, cdfg_node_is_first_param, &add_node_find_res)
        );
        if (!add_node_find_res.found) {
            continue;
        }

        // we expect the other input of the add node to be a multiplication node.
        cdfg_node_id_t mul_node_id = add_node_find_res.other_input;
        const cdfg_node_t* mul_node = &cdfg->node_storage[mul_node_id.id];
        if (mul_node->kind != CDFG_NODE_KIND_CALC) {
            continue;
        }
        bool is_mul =
            (mul_node->content.calc.calculation == CDFG_CALCULATION_SIGNED_MUL ||
             mul_node->content.calc.calculation == CDFG_CALCULATION_UNSIGNED_MUL);
        if (!is_mul) {
            continue;
        }

        // we expect one of the inputs of the multiplication node to be an immediate
        cdfg_binop_input_find_res_t mul_node_find_res = {};
        CHECK_RETHROW(cdfg_find_binop_input(cdfg, node_id, cdfg_node_is_imm, &mul_node_find_res));
        if (!mul_node_find_res.found) {
            continue;
        }

        const cdfg_node_t* struct_size_node =
            &cdfg->node_storage[mul_node_find_res.matching_input.id];

        CHECK(!found_struct_size);
        struct_size = struct_size_node->content.imm.value;
        found_struct_size = true;
    }

    CHECK(found_struct_size);
    CHECK(struct_size == 1337);

cleanup:
    return err;
}

DEFINE_TEST(test_analysis_struct_size) {
    err_t err = SUCCESS;

    CHECK_RETHROW_VERBOSE(verify_analysis(&shellcode_struct_size, verify_struct_size_analysis));

cleanup:
    return err;
}
