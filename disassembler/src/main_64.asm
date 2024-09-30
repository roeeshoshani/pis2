BITS 64

global main
main:
add rax, 5
mov al, cl
mov rax, [rbx]
db 0x8b, 0xc8
sete al
sete [rax]
shit:
nop
