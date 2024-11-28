#include "reg.h"
#include "space.h"
#include "trace.h"

void pis_reg_dump(pis_reg_t reg) {
    TRACE_NO_NEWLINE("REG");
    pis_region_dump(reg.region);
}

bool pis_reg_contains(pis_reg_t reg, pis_reg_t sub_reg) {
    return pis_region_contains(reg.region, sub_reg.region);
}

bool pis_regs_equal(pis_reg_t a, pis_reg_t b) {
    return pis_regions_equal(a.region, b.region);
}

bool pis_regs_intersect(pis_reg_t a, pis_reg_t b) {
    return pis_regions_intersect(a.region, b.region);
}

pis_op_t pis_reg_to_op(pis_reg_t reg) {
    return PIS_OPERAND_REG(reg.region.offset, reg.region.size);
}
