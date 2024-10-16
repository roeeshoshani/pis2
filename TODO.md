# TODO
notes about stuff that needs to be done.

- integration tests - emulate some large program and make sure that the output is correct.
- verify all flags logic against spec
- handle prefixes: REP* prefixes, LOCK prefix, segment override prefixes
- add tests for jmp and jcc instructions
- add a condition negate opcode instead of xoring with 1. this will look much cleaner once the entire thing becomes a graph.
- extract common code patterns into functions. examples:
  * the `XXX EAX, IMM` instructions.
- 2 functions with very similar names `fetch_sign_extended_imm_operand` and `fetch_and_sign_extend_imm`
