from pypcode import *

ctx = Context("x86:LE:64:default")

code = b'\x00\x00'

for op in ctx.translate(code).ops:
    print(PcodePrettyPrinter.fmt_op(op))
