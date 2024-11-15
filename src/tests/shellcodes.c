#include "shellcodes.h"
#include "../lib/arch/x86/lift.h"
#include "../lib/arch/x86/regs.h"
#include "../lib/emu.h"
#include "../lib/except.h"
#include "../lib/pis.h"
#include "../lib/utils.h"
#include "test_utils.h"

#define INITIAL_STACK_POINTER_VALUE 0x20000000
#define SHELLCODE_FINISH_ADDR 0x13371337
#define UNUSED_REG_MAGIC 0x73317331

EACH_SHELLCODE(DEFINE_SHELLCODE);

typedef struct {
    u64 arg1;
    u64 arg2;
    u64 arg3;
    u64 arg4;
} shellcode_args_t;

typedef err_t (*lift_fn_t)(pis_lift_args_t* args);
typedef err_t (*prepare_fn_t)(pis_emu_t* emu, const shellcode_args_t* args);

typedef struct {
    lift_fn_t lift;
    prepare_fn_t prepare;
    pis_endianness_t endianness;
    const pis_operand_t* result_operand;
} arch_def_t;

static err_t lift_x86_64(pis_lift_args_t* args) {
    err_t err = SUCCESS;
    CHECK_RETHROW_VERBOSE(pis_x86_lift(args, PIS_X86_CPUMODE_64_BIT));
cleanup:
    return err;
}

static err_t lift_i686(pis_lift_args_t* args) {
    err_t err = SUCCESS;
    CHECK_RETHROW_VERBOSE(pis_x86_lift(args, PIS_X86_CPUMODE_32_BIT));
cleanup:
    return err;
}

/// initialize registers that should be unused by the shellcode.
/// we need to initialize them since the shellcode may still sometimes read them, for example when
/// preserving register values.
/// we initialize them with magic values so that if the shellcode accidentally accesses them due to
/// a bug in the lifting logic, it will get garbage values, which will hopefully fail the tests.
static err_t init_unused_regs(pis_emu_t* emu, const pis_operand_t* regs[], size_t count) {
    err_t err = SUCCESS;
    for (size_t i = 0; i < count; i++) {
        CHECK_RETHROW_VERBOSE(pis_emu_write_operand(emu, regs[i], UNUSED_REG_MAGIC));
    }
cleanup:
    return err;
}

static err_t prepare_x86_64(pis_emu_t* emu, const shellcode_args_t* args) {
    err_t err = SUCCESS;

    u64 sp = INITIAL_STACK_POINTER_VALUE;

    // push the return address
    sp -= 8;
    CHECK_RETHROW_VERBOSE(pis_emu_write_mem_value(emu, sp, SHELLCODE_FINISH_ADDR, PIS_SIZE_8));

    CHECK_RETHROW_VERBOSE(pis_emu_write_operand(emu, &X86_RSP, sp));

    CHECK_RETHROW_VERBOSE(pis_emu_write_operand(emu, &X86_RDI, args->arg1));
    CHECK_RETHROW_VERBOSE(pis_emu_write_operand(emu, &X86_RSI, args->arg2));
    CHECK_RETHROW_VERBOSE(pis_emu_write_operand(emu, &X86_RDX, args->arg3));
    CHECK_RETHROW_VERBOSE(pis_emu_write_operand(emu, &X86_RCX, args->arg4));

    const pis_operand_t* unused_regs[] = {
        &X86_RAX,
        &X86_RBX,
        &X86_RBP,
        &X86_R8,
        &X86_R9,
        &X86_R10,
        &X86_R11,
        &X86_R12,
        &X86_R13,
        &X86_R14,
        &X86_R15,
    };
    CHECK_RETHROW_VERBOSE(init_unused_regs(emu, unused_regs, ARRAY_SIZE(unused_regs)));

cleanup:
    return err;
}

static err_t prepare_i686(pis_emu_t* emu, const shellcode_args_t* args) {
    err_t err = SUCCESS;

    u32 sp = INITIAL_STACK_POINTER_VALUE;

    // push all arguments
    sp -= 4;
    CHECK_RETHROW_VERBOSE(pis_emu_write_mem_value(emu, sp, args->arg4, PIS_SIZE_4));
    sp -= 4;
    CHECK_RETHROW_VERBOSE(pis_emu_write_mem_value(emu, sp, args->arg3, PIS_SIZE_4));
    sp -= 4;
    CHECK_RETHROW_VERBOSE(pis_emu_write_mem_value(emu, sp, args->arg2, PIS_SIZE_4));
    sp -= 4;
    CHECK_RETHROW_VERBOSE(pis_emu_write_mem_value(emu, sp, args->arg1, PIS_SIZE_4));

    // push the return address
    sp -= 4;
    CHECK_RETHROW_VERBOSE(pis_emu_write_mem_value(emu, sp, SHELLCODE_FINISH_ADDR, PIS_SIZE_4));

    // initialize the stack pointer
    CHECK_RETHROW_VERBOSE(pis_emu_write_operand(emu, &X86_ESP, sp));

    const pis_operand_t* unused_regs[] = {
        &X86_EAX,
        &X86_EBX,
        &X86_ECX,
        &X86_EDX,
        &X86_ESI,
        &X86_EDI,
        &X86_EBP,
    };
    CHECK_RETHROW_VERBOSE(init_unused_regs(emu, unused_regs, ARRAY_SIZE(unused_regs)));

cleanup:
    return err;
}

const arch_def_t arch_def_x86_64 = {
    .lift = lift_x86_64,
    .prepare = prepare_x86_64,
    .endianness = PIS_ENDIANNESS_LITTLE,
    .result_operand = &X86_RAX,
};

const arch_def_t arch_def_i686 = {
    .lift = lift_i686,
    .prepare = prepare_i686,
    .endianness = PIS_ENDIANNESS_LITTLE,
    .result_operand = &X86_EAX,
};

static err_t
    run_arch_specific_shellcode(pis_emu_t* emu, const shellcode_t* shellcode, lift_fn_t lift_fn) {
    err_t err = SUCCESS;

    size_t code_len = shellcode->code_end - shellcode->code;

    u64 cur_offset = 0;
    while (cur_offset < code_len) {
        pis_lift_args_t args = {
            .machine_code = CURSOR_INIT(shellcode->code + cur_offset, code_len - cur_offset),
            .machine_code_addr = SHELLCODE_BASE_ADDR + cur_offset,
        };
        CHECK_RETHROW_TRACE(
            lift_fn(&args),
            "failed to lift insn at offset 0x%lx in shellcode %s",
            cur_offset,
            shellcode->name
        );

        CHECK_RETHROW_TRACE(
            pis_emu_run(emu, &args.result),
            "failed to emulate insn at offset 0x%lx in shellcode %s",
            cur_offset,
            shellcode->name
        );

        if (emu->did_jump) {
            if (emu->jump_addr == SHELLCODE_FINISH_ADDR) {
                // shellcode finished running.
                break;
            } else {
                // convert the jump address to an offset inside the shellcode
                CHECK(emu->jump_addr >= SHELLCODE_BASE_ADDR);
                cur_offset = emu->jump_addr - SHELLCODE_BASE_ADDR;
            }
        } else {
            // advance to the next instruction
            cur_offset += args.result.machine_insn_len;
        }
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

    // preare for execution
    CHECK_RETHROW_VERBOSE(arch->prepare(&g_emu, args));

    // write the shellcode content to the emulator's memory. this will allow the shellcode to access
    // its embedded data.
    size_t code_len = shellcode->code_end - shellcode->code;
    for (size_t i = 0; i < code_len; i++) {
        CHECK_RETHROW_VERBOSE(
            pis_emu_write_mem_value(&g_emu, SHELLCODE_BASE_ADDR + i, shellcode->code[i], PIS_SIZE_1)
        );
    }

    CHECK_RETHROW_VERBOSE(run_arch_specific_shellcode(&g_emu, shellcode, arch->lift));

    u64 return_value = 0;
    CHECK_RETHROW_VERBOSE(pis_emu_read_operand(&g_emu, arch->result_operand, &return_value));

    u64 truncated_expected_return_value =
        expected_return_value & pis_size_max_unsigned_value(arch->result_operand->size);

    CHECK_TRACE(
        return_value == truncated_expected_return_value,
        "unexpected shellcode result, expected %lu, instead got %lu",
        truncated_expected_return_value,
        return_value
    );

cleanup:
    return err;
}

static err_t test_shellcode_result(
    const per_arch_shellcode_t* shellcode, const shellcode_args_t* args, u64 expected_result
) {
    err_t err = SUCCESS;

    CHECK_RETHROW_VERBOSE(check_arch_specific_shellcode_result(
        &arch_def_x86_64,
        &shellcode->x86_64,
        args,
        expected_result
    ));

    CHECK_RETHROW_VERBOSE(check_arch_specific_shellcode_result(
        &arch_def_i686,
        &shellcode->i686,
        args,
        expected_result
    ));

cleanup:
    return err;
}

static err_t test_factorial(u64 input, u64 expected_output) {
    err_t err = SUCCESS;
    CHECK_RETHROW_VERBOSE(test_shellcode_result(
        &shellcode_factorial,
        &(shellcode_args_t) {.arg1 = input},
        expected_output
    ));
cleanup:
    return err;
}

DEFINE_TEST(test_shellcode_factorial) {
    err_t err = SUCCESS;

    CHECK_RETHROW_VERBOSE(test_factorial(0, 1));
    CHECK_RETHROW_VERBOSE(test_factorial(2, 2));
    CHECK_RETHROW_VERBOSE(test_factorial(5, 120));
    CHECK_RETHROW_VERBOSE(test_factorial(10, 3628800));
    CHECK_RETHROW_VERBOSE(test_factorial(13, 6227020800));

cleanup:
    return err;
}

static err_t test_gcd(u64 a, u64 b, u64 expected_output) {
    err_t err = SUCCESS;
    CHECK_RETHROW_VERBOSE(test_shellcode_result(
        &shellcode_gcd,
        &(shellcode_args_t) {.arg1 = a, .arg2 = b},
        expected_output
    ));
cleanup:
    return err;
}

DEFINE_TEST(test_shellcode_gcd) {
    err_t err = SUCCESS;

    CHECK_RETHROW_VERBOSE(test_gcd(0, 0, 0));
    CHECK_RETHROW_VERBOSE(test_gcd(1, 1, 1));
    CHECK_RETHROW_VERBOSE(test_gcd(10, 14, 2));
    CHECK_RETHROW_VERBOSE(test_gcd(3046468425, 1954953000, 16291275));

cleanup:
    return err;
}

static err_t test_ackermann(u64 a, u64 b, u64 expected_output) {
    err_t err = SUCCESS;
    CHECK_RETHROW_VERBOSE(test_shellcode_result(
        &shellcode_ackermann,
        &(shellcode_args_t) {.arg1 = a, .arg2 = b},
        expected_output
    ));
cleanup:
    return err;
}

DEFINE_TEST(test_shellcode_ackermann) {
    err_t err = SUCCESS;

    CHECK_RETHROW_VERBOSE(test_ackermann(0, 0, 1));
    CHECK_RETHROW_VERBOSE(test_ackermann(0, 1, 2));
    CHECK_RETHROW_VERBOSE(test_ackermann(1, 1, 3));
    CHECK_RETHROW_VERBOSE(test_ackermann(2, 2, 7));
    CHECK_RETHROW_VERBOSE(test_ackermann(3, 2, 29));

cleanup:
    return err;
}

DEFINE_TEST(test_shellcode_json) {
    err_t err = SUCCESS;

    CHECK_RETHROW_VERBOSE(test_shellcode_result(&shellcode_json, &(shellcode_args_t) {}, 40));

cleanup:
    return err;
}

DEFINE_TEST(test_shellcode_regex) {
    err_t err = SUCCESS;

    CHECK_RETHROW_VERBOSE(test_shellcode_result(&shellcode_regex, &(shellcode_args_t) {}, 0));

cleanup:
    return err;
}

static err_t test_chacha20(
    u32 key_seed, u32 nonce_seed, u32 counter, u32 plaintext_seed, u32 expected_output
) {
    err_t err = SUCCESS;
    CHECK_RETHROW_VERBOSE(test_shellcode_result(
        &shellcode_chacha20,
        &(shellcode_args_t) {
            .arg1 = key_seed,
            .arg2 = nonce_seed,
            .arg3 = counter,
            .arg4 = plaintext_seed,
        },
        expected_output
    ));
cleanup:
    return err;
}

DEFINE_TEST(test_shellcode_chacha20) {
    err_t err = SUCCESS;

    CHECK_RETHROW_VERBOSE(test_chacha20(0x1234, 0x5678, 0xabcd, 0xcafe, 0xfdb));
    CHECK_RETHROW_VERBOSE(test_chacha20(0xf1f2f3f4, 0xf4f3f2f1, 0xf5f6f7f8, 0xf8f7f6f5, 0x10ec));
    CHECK_RETHROW_VERBOSE(test_chacha20(0xff558a62, 0x35457c21, 0xbae7b349, 0xec0aeebd, 0x114c));

cleanup:
    return err;
}
