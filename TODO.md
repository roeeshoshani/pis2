# TODO
notes about stuff that needs to be done.

- verify all flags logic against spec
- handle prefixes: REP* prefixes, LOCK prefix, segment override prefixes
- add tests for jmp and jcc instructions
- add a condition negate opcode instead of xoring with 1. this will look much cleaner once the entire thing becomes a graph.
- extract common code patterns into functions, for example the `XXX EAX, IMM` instructions.
