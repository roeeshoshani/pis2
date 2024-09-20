BITS 64

global main
main:
mov r8w, r9w
mov r12d, r14d
mov r13w, sp
mov esi, r15d
mov [rsi], r12
mov [r13+7], rbp
mov [r8-6], r9
mov [rax + 2], rcx
mov [r10+0x11223344], rbx
mov [rdx - 0x41424344], r11


MOV [RBP + 4*RBX + 0x05], R11
MOV [RBP + 4*RSI - 0x08], R11
MOV [RBP + 8*RDX], R11
