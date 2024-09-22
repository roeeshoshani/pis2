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

nop
nop

; r12 edge case
mov [rax + 4*r12], rbx

; SIB with no index edge case
mov [rsp], rdx

; no base edge case
mov [4*rdi], r8

; use rbp as base edge case - requires explicit displacement
mov [rbp + 2*r9], rsp

; use r13 as base edge case - requires explicit displacement
mov [r13 + 2*rcx], r14

; use extended registers
mov [r10 +8*r15 - 3], r12

; sign extension of 32-bit displacement
mov [rsi + 1*r8 - 0x12341234], r12
