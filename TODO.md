# TODO
notes about stuff that needs to be done.

- integration tests - emulate some large program and make sure that the output is correct.
- verify all flags logic against spec
- handle prefixes: REP* prefixes, LOCK prefix, segment override prefixes
- add tests for jmp and jcc instructions
- how do i deal with abstraction layers without implementing a million wrapper functions.
  for example look at `lift_ctx`'s wrappers around the `lift_result` functions.
