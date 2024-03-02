global _start

section .text
_start:
    mov     rdi, 1          ; stdout
    mov     rsi, message    ; Hello, World
    mov     rdx, 12         ; byte count
    mov     rax, 1          ; write syscall
    syscall
    xor     rdi, rdi
    mov     rax, 60         ; exit syscall
    syscall
        
section .data
    message: db     "Hello, World"
