# 2019 Securityfest - Baby1

## Vulnerability

This was a standard ROP challenge with `system` function and `/bin/sh` already imported into the binary. Details were as expected:

```
[*] '/baby1'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE
```

Disassembly shows a buffer overflow vulnerability with `gets` at `0x0040071c`:
```
/ (fcn) sym.main 117
|   sym.main (int argc, char **argv, char **envp);
|           ; var int local_10h @ rbp-0x10
|           ; DATA XREF from entry0 (0x4005bd)
|           0x004006b3      55             push rbp
|           0x004006b4      4889e5         mov rbp, rsp
|           0x004006b7      4883ec10       sub rsp, 0x10
|           0x004006bb      488b055e1920.  mov rax, qword [obj.stdin__GLIBC_2.2.5] ; [0x602020:8]=0
|           0x004006c2      b900000000     mov ecx, 0
|           0x004006c7      ba02000000     mov edx, 2
|           0x004006cc      be00000000     mov esi, 0
|           0x004006d1      4889c7         mov rdi, rax
|           0x004006d4      e8b7feffff     call sym.imp.setvbuf        ; int setvbuf(FILE*stream, char *buf, int mode, size_t size)
|           0x004006d9      488b05301920.  mov rax, qword [obj.stdout__GLIBC_2.2.5] ; obj.__TMC_END ; [0x602010:8]=0
|           0x004006e0      b900000000     mov ecx, 0
|           0x004006e5      ba02000000     mov edx, 2
|           0x004006ea      be00000000     mov esi, 0
|           0x004006ef      4889c7         mov rdi, rax
|           0x004006f2      e899feffff     call sym.imp.setvbuf        ; int setvbuf(FILE*stream, char *buf, int mode, size_t size)
|           0x004006f7      b800000000     mov eax, 0
|           0x004006fc      e886ffffff     call sym.banner
|           0x00400701      bfc4104000     mov edi, str.input:         ; 0x4010c4 ; "input: "
|           0x00400706      b800000000     mov eax, 0
|           0x0040070b      e860feffff     call sym.imp.printf         ; int printf(const char *format)
|           0x00400710      488d45f0       lea rax, qword [local_10h]
|           0x00400714      4889c7         mov rdi, rax
|           0x00400717      b800000000     mov eax, 0
|           0x0040071c      e85ffeffff     call sym.imp.gets           ; char *gets(char *s)
|           0x00400721      b800000000     mov eax, 0
|           0x00400726      c9             leave
\           0x00400727      c3             ret
```

## ROP chain

Further inspection showed that the binary also had implemented a `win` function that called `system` with an argument:
```
/ (fcn) sym.win 27
|   sym.win (int arg1);
|           ; var int local_8h @ rbp-0x8
|           ; arg int arg1 @ rdi
|           0x00400698      55             push rbp
|           0x00400699      4889e5         mov rbp, rsp
|           0x0040069c      4883ec10       sub rsp, 0x10
|           0x004006a0      48897df8       mov qword [local_8h], rdi   ; arg1
|           0x004006a4      488b45f8       mov rax, qword [local_8h]
|           0x004006a8      4889c7         mov rdi, rax
|           0x004006ab      e8b0feffff     call sym.imp.system         ; int system(const char *string)
|           0x004006b0      90             nop
|           0x004006b1      c9             leave
\           0x004006b2      c3             ret
```

Only thing we need is the `/bin/sh` string:
```
[0x004005a0]> izz
[Strings]
Num Paddr      Vaddr      Len Size Section             Type  String
...
002 0x00000286 0x00400286   7   8 (.note.gnu.build_id) ascii /bin/sh
...
```

And a handy gadget:
```
0x0000000000400793 : pop rdi ; ret
```

Everything is here. Let's write the exploit.

At first I started with the intuitive way to exploit the binary:
- overflow via `gets`
- overwrite rip to point to `pop rdi` gadget
- pop `/bin/sh` to rdi making it the argument for `win` function
- chain `win` function next which executes `system("/bin/sh")`

Unfortunately, the exploit didn't work (?) and the binary threw segmentation fault. After a few retries, double checks and other similar variants I implemented the following exploit in the end:
- found an empty memory in the binary -> `0x00602028`
- overflow via `gets`
- overwrite rip to point to `pop rdi` gadget making my empty memory address the argument for `gets` function
- chain `gets` function next which prompts for input and stores it at my chosen memory
- chain `pop rdi` again to make sure that my chosen memory address becomes a first argument for `win` function
- chain `win` function next which executes `system("/bin/sh")`

This exploit gave me the shell. Solution to this challenge is `solve_2019_securityfest_baby1.py`.
