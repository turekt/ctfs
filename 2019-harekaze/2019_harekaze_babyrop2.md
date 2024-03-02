# 2019 Harekaze - Babyrop 2

## Vulnerability

Info shows NX true, no canary, ELF64 binary. There is also libc provided for this task.

```
$ rabin2 -I babyrop2
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

Let's run it:

```
$ ./babyrop2 
What's your name? aa
Welcome to the Pwn World again, aa!
```

Reacts the same as babyrop. The assembly shows the same buffer overflow on read function (0x100 read on 0x20 stack len):

```
sym.main (int argc, char **argv, char **envp);
|           ; var int local_20h @ rbp-0x20
|           ; var int local_4h @ rbp-0x4
|           ; arg int arg_20h @ rbp+0x20
|           ; DATA XREF from entry0 (0x40055d)
|                                                    ... snip ...
|           0x0040067a      bf58074000     mov edi, str.What_s_your_name ; 0x400758 ; "What's your name? "
|           0x0040067f      b800000000     mov eax, 0
|           0x00400684      e867feffff     call sym.imp.printf         ; int printf(const char *format)
|           0x00400689      488d45e0       lea rax, qword [local_20h]
|           0x0040068d      ba00010000     mov edx, 0x100              ; 256
|           0x00400692      4889c6         mov rsi, rax
|           0x00400695      bf00000000     mov edi, 0
|           0x0040069a      e861feffff     call sym.imp.read           ; ssize_t read(int fildes, void *buf, size_t nbyte)
|           0x0040069f      8945fc         mov dword [local_4h], eax
|           0x004006a2      8b45fc         mov eax, dword [local_4h]
|           0x004006a5      83e801         sub eax, 1
|           0x004006a8      4898           cdqe
|           0x004006aa      c64405e000     mov byte [rbp + rax - 0x20], 0
|           0x004006af      488d45e0       lea rax, qword [local_20h]
|           0x004006b3      4889c6         mov rsi, rax
|           0x004006b6      bf70074000     mov edi, str.Welcome_to_the_Pwn_World_again___s ; 0x400770 ; "Welcome to the Pwn World again, %s!\n"
|           0x004006bb      b800000000     mov eax, 0
|           0x004006c0      e82bfeffff     call sym.imp.printf         ; int printf(const char *format)
                                                    ... snip ...
```

The vulnerability is similar to babyrop but this time system is not imported and the /bin/sh string is missing. We will have to find another way to get a shell this time.

## Exploring libc

Since we have libc which is used by babyrop2 binary, we can easily calculate where the system function is located but need to get a reference function first. We can use any function which is coming from libc to locate the system function - it just has to be resolved by the linker. But how can we leak the address? The appropriate function for this would be printf. If we jump to printf and supply it with the address of the .got section that has resolved the reference function, we can disclose the reference function address and calculate where system function resides by adding/subtracting the offset between those two functions.

To successfully call printf, we will have to supply the printf format to rdi register and reference function .got section address to rsi register. This can be achieved with pop rdi and pop rsi gadgets. After this is done, we can jump to printf and read the location of read function.

After the read location is known we can calculate the offset to system and simply overwrite any .got section address with known system function address by calling the read function and writing that same address to a location of our choice. The same technique can be used for "/bin/sh" string only the string can be put anywhere where we like but since we want to limit the number of chains executed, we will write the /bin/sh string into the adjacent memory location to the overwritten .got section - this way we can spare one chain.

## The big picture - whole chain

The recipe for the whole chain is:
- pop format argument to rdi (printf 1st argument)
- pop read .got entry to rsi (printf 2nd argument)
- execute printf (leak the address of read)
- pop 0 to rdi (read 1st argument)
- pop read .got entry address to rsi (read 2nd argument)
- execute read (provide the system address along with "/bin/sh" so it gets written to the read .got entry and the adjacent memory address)
- pop adjacent memory address to rdi (system 1st argument)
- execute read (this will execute system because the .got entry was overwritten with system address)

The complete solution to this task is `solve_2019_harekaze_babyrop2.py`.
