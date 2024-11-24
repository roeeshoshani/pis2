#include "cpumode.h"

/// returns the operand size corresponding to the given cpumode.
pis_size_t pis_x86_cpumode_get_operand_size(pis_x86_cpumode_t cpumode) {
    switch (cpumode) {
        case PIS_X86_CPUMODE_64_BIT:
            return PIS_SIZE_8;
        case PIS_X86_CPUMODE_32_BIT:
            return PIS_SIZE_4;
        default:
            // unreachable
            return PIS_SIZE_1;
    }
}
