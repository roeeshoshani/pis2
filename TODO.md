# TODO
notes about stuff that needs to be done.

- do i always run the delay slot insn in conditional branch? i remember some edge case with this... check it.
- when building a new node, check if there is an existing node that is exactly equal to it, and if so, reuse it.
- in IF nodes, add a way to check which path is the true path and which is the false path.
- add stack data flow analysis
- handle inter-instruction jumps in CDFG. (for example REP).
- when building CDFG node, instead of storing the final state of each block, which is very expensive, make it slot based and allow erasing
  the state of blocks that we finished processing. additionally, change the building strategy such that we need to keep the minimal amount
  of such states at any given point in time. this will reduce memory usage quite a lot.
  for example, once we are done processing all successors of a block, we can forget its state.
  one example strategy would be to use an exploration queue like the CFG, and when we finish processing a block, first process its
  predecessors and their requirements, so that you can delete its state.
  don't make it too complicated to keep the code sane.
- don't use a unified item id type in cfg. use different types like i did in cdfg.
- make slot allocation re-use invalidated slots in all slot allocation code that i have written.
