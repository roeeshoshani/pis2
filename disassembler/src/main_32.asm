BITS 32
mov esi, ecx
mov [edx], edi
mov [0x12345678], esi
mov [ebx+3], eax
mov [edi-2], esp
mov [ebp+0x7f], edx
mov [eax + 0x11223344], ebp
mov [ebp - 0x41424344], ebx

mov [esi + eax], ebx
mov [esp], ecx

mov [0x12345678 + 4*edx], ebp

db 0x89, 0x2c, 0x25, 0x78, 0x56, 0x34, 0x12

mov [ebp + ebp*8 + 1], edi
mov [ebp + ebx*2 - 4], ecx
mov [ebp + eax + 0x11223344], esi
mov [ebp + 2*edx - 0x41424344], esp

mov [ecx + esi*8 + 1], edi
mov [eax + ebx*2 - 3], ebp
mov [esp + 4*ecx + 0x11223344], esp

nop
nop
nop

mov [bp + si + 0x1234], eax
mov [eax + ebx*2 - 3], ax
mov [bx + si + 0x1234], cx
