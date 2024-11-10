#include "lift.h"
#include "insn_fields.h"

typedef err_t (*opcode_handler_t
)(pis_lift_args_t* args, const pis_mips_cpuinfo_t* cpuinfo, u32 insn);

static err_t opcode_handler_00(pis_lift_args_t* args, const pis_mips_cpuinfo_t* cpuinfo, u32 insn) {
    err_t err = SUCCESS;
cleanup:
    return err;
}

const opcode_handler_t opcode_handlers[MIPS_MAX_OPCODE_VALUE + 1] = {
    opcode_handler_00,
};

err_t pis_mips_lift(pis_lift_args_t* args, const pis_mips_cpuinfo_t* cpuinfo) {
    err_t err = SUCCESS;

    u32 insn = 0;
    CHECK_RETHROW(cursor_next_4(&args->machine_code, &insn, cpuinfo->endianness));

    u8 opcode = insn_field_opcode(insn);
    opcode_handler_t opcode_handler = opcode_handlers[opcode];
    CHECK_TRACE_CODE(
        opcode_handler != NULL,
        PIS_ERR_UNSUPPORTED_INSN,
        "unsupported opcode 0x%2x",
        opcode
    );

    CHECK_RETHROW(opcode_handler(args, cpuinfo, insn));

cleanup:
    return err;
}
