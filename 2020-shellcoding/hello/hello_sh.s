 global _start

 section .text
_start:
    xor     rax, rax
    xor     rdi, rdi
    xor     rdx, rdx
    
    ;; Hello, World
    mov     eax, 0x646c726f
    push    rax
    mov     rax, 0x57202c6f6c6c6548
    push    rax
    xor     rax, rax

    ;; printf()
    mov     dil, 1
    mov     rsi, rsp
    mov     dl, 12
    mov     al, 1
    syscall
    
    ;; exit()
    xor     rdi, rdi
    mov     al, 60
    syscall
