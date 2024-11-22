#include "cfg.h"

#include <string.h>

void pis_cfg_init(pis_cfg_t* cfg) {
    memset(cfg, 0, sizeof(*cfg));
}
