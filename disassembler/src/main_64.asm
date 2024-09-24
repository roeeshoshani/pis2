BITS 64

global main
main:
; add [rsp+2*r12], r8w
bla:
dd 0

mov [rel bla], eax
nop
shit:
dd 0
