from pypcode import *

ctx = Context("x86:LE:64:default")

code_str = '''
c1 c6 10
'''
code_hex = code_str.strip().replace(' ', '')
code = bytes.fromhex(code_hex)

for op in ctx.translate(code).ops:
    print(PcodePrettyPrinter.fmt_op(op))
