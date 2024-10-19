#include "shellcodes.h"
#include "arch/x86/ctx.h"
#include "arch/x86/regs.h"
#include "emu.h"
#include "except.h"
#include "pis.h"
#include "test_utils.h"

#define INITIAL_STACK_POINTER_VALUE 0xf0000

EACH_SHELLCODE(DEFINE_SHELLCODE);

typedef struct {
    u64 arg1;
    u64 arg2;
    u64 arg3;
    u64 arg4;
} shellcode_args_t;

typedef err_t (*lift_fn_t)(u8* code, size_t code_len, u64 addr, pis_lift_result_t* result);
typedef err_t (*prepare_args_fn_t)(pis_emu_t* emu, const shellcode_args_t* args);

typedef struct {
    lift_fn_t lift;
    prepare_args_fn_t prepare_args;
    pis_endianness_t endianness;
    const pis_operand_t* return_value_operand;
    const pis_operand_t* stack_pointer_operand;
} arch_def_t;

static err_t lift_x86_64(u8* code, size_t code_len, u64 addr, pis_lift_result_t* result) {
    err_t err = SUCCESS;
    pis_x86_ctx_t ctx = {
        .cpumode = PIS_X86_CPUMODE_64_BIT,
    };
    CHECK_RETHROW(pis_x86_lift(&ctx, code, code_len, addr, result));
cleanup:
    return err;
}

static err_t prepare_args_x86_64(pis_emu_t* emu, const shellcode_args_t* args) {
    err_t err = SUCCESS;

    CHECK_RETHROW(pis_emu_write_operand(emu, &RDI, args->arg1));
    CHECK_RETHROW(pis_emu_write_operand(emu, &RSI, args->arg2));
    CHECK_RETHROW(pis_emu_write_operand(emu, &RDX, args->arg3));
    CHECK_RETHROW(pis_emu_write_operand(emu, &RCX, args->arg4));

cleanup:
    return err;
}

const arch_def_t arch_def_x86_64 = {
    .lift = lift_x86_64,
    .prepare_args = prepare_args_x86_64,
    .endianness = PIS_ENDIANNESS_LITTLE,
    .return_value_operand = &RAX,
    .stack_pointer_operand = &RSP};


static err_t
    run_arch_specific_shellcode(pis_emu_t* emu, const shellcode_t* shellcode, lift_fn_t lift_fn) {
    err_t err = SUCCESS;
    pis_lift_result_t result = {};

    size_t code_len = shellcode->code_end - shellcode->code;

    u64 cur_offset = 0;
    while (cur_offset < code_len) {
        pis_lift_result_reset(&result);

        CHECK_RETHROW(lift_fn(
            shellcode->code + cur_offset,
            code_len - cur_offset,
            SHELLCODE_BASE_ADDR + cur_offset,
            &result
        ));

        CHECK_RETHROW(pis_emu_run(emu, &result));

        cur_offset += result.machine_insn_len;
    }
cleanup:
    return err;
}

static err_t check_arch_specific_shellcode_result(
    const arch_def_t* arch,
    const shellcode_t* shellcode,
    const shellcode_args_t* args,
    u64 expected_return_value
) {
    err_t err = SUCCESS;

    pis_emu_init(&g_emu, arch->endianness);

    // initialize the stack pointer
    CHECK_RETHROW(
        pis_emu_write_operand(&g_emu, arch->stack_pointer_operand, INITIAL_STACK_POINTER_VALUE)
    );

    // prepare the arguments to the shellcode
    CHECK_RETHROW(arch->prepare_args(&g_emu, args));

    CHECK_RETHROW(run_arch_specific_shellcode(&g_emu, shellcode, arch->lift));

    u64 return_value = 0;
    CHECK_RETHROW(pis_emu_read_operand(&g_emu, arch->return_value_operand, &return_value));

    u64 truncated_expected_return_value =
        expected_return_value &
        pis_operand_size_max_unsigned_value(arch->return_value_operand->size);

    CHECK(return_value == truncated_expected_return_value);

cleanup:
    return err;
}

static err_t test_shellcode_result(
    const per_arch_shellcode_t* shellcode, const shellcode_args_t* args, u64 expected_result
) {
    err_t err = SUCCESS;

    CHECK_RETHROW(check_arch_specific_shellcode_result(
        &arch_def_x86_64,
        &shellcode->x86_64,
        args,
        expected_result
    ));

cleanup:
    return err;
}

DEFINE_TEST(test_shellcode_factorial) {
    err_t err = SUCCESS;
    CHECK_RETHROW(test_shellcode_result(&shellcode_factorial, &(shellcode_args_t) {.arg1 = 5}, 16));
cleanup:
    return err;
}
