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
- implement a bunch of new optimizations which will make the struct size test actually work.

  both optimizations will require a method to find looping phi nodes which are added a value in each iteration.
  this is very easy. just find a phi node whose output goes into an add node with an immediate, and the add's output goes into the
  phi node as an input, and the other phi node's input should be an immediate. this will give us two output value - the initial value
  and the increment value.

  now that we have the above primitive, implement a function which finds a phi loop node, and checks if its output is only used once,
  in a multiplication node. if that's the case, multiply the initial value and the increment and remove the multiply node.
  this is our first optimization.

  the second optimization will find phi nodes that are almot looping phi nodes and convert them to looping phi nodes.
  it will find phi nodes whose increment value is an immediate, but the initial value is not, and convert them to looping phi nodes
  with initial value 0, but take their output and add the original initial value to it to get the same value.

  then, the lifting should look the same for x86 and mips.
- handle data flow loops in the unused nodes detection.
