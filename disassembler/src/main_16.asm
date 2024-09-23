BITS 16
mov [bx], cx
mov [bp+si], dx
mov [0x1234], di
mov [si + 5], ax
mov [bx + di - 1], bx
mov [bp + 0x7f], si
mov [bx + si + 0x1234], cx
mov [bp - 0x1234], dx
mov si, cx

nop
nop
nop

mov [bp + si + 0x1234], eax

mov [eax + ebx*2 - 3], ax
mov [eax + ebx*2 - 3], esp

add [bp + si - 1], cx
