#include "../../cursor.h"
#include "../../except.h"
#include "../../lift_args.h"
#include "../../pis.h"
#include "../../types.h"
#include "cpuinfo.h"

typedef struct {
    pis_lift_args_t* args;
    const pis_mips_cpuinfo_t* cpuinfo;
    bool is_in_delay_slot;
    u32 insn;
} ctx_t;

