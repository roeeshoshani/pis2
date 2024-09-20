BITS 32
mov esi, ecx
mov [edx], edi
mov [0x12345678], esi
mov [ebx+3], eax
mov [edi-2], esp
mov [ebp+0x7f], edx
mov [eax + 0x11223344], ebp
mov [ebp - 0x41424344], ebx

mov [ebp + 2*ebp + 1], ebx
