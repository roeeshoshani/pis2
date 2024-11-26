# TODO
notes about stuff that needs to be done.

- handle prefixes: REP* prefixes, LOCK prefix, segment override prefixes
- do i always run the delay slot insn in conditional branch? i remember some edge case with this... check it.
- in shellcode tests, test mips revisions other than revision 1.
  its endianness, and its return value register operand, or something like that.
- build phi and region nodes lazily. only build them if there is more than one predecessor.
- when building a new node, check if there is an existing node that is exactly equal to it, and if so, reuse it.
- in IF nodes, add a way to check which path is the true path and which is the false path.
- add stack data flow analysis
- in my ret value detection, i ignore the fact that the return value may have a specific size. same for all
  register accesses.
- optimize registers to use 16-bit offsets. this will make all structs much smaller.
