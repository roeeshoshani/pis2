#pragma once

#include "../../except.h"
#include "ctx.h"

/// checks if the instruction has a segment override prefix.
///
/// if the instruction has a segment override prefix, this function returns `true` and sets the
/// segment base output parameter to the correct segment base operand.
///
/// otherwise, if the instruction doesn't have a segment override prefix, returns `false` and the segment
/// base output parameter is unmodified.
bool insn_has_segment_override(ctx_t* ctx, pis_operand_t* segment_base);
