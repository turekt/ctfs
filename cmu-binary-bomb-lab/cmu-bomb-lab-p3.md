# CMU Bomb lab - Phase 3

Phase 3 starts with an input which is checked:

```
0x00400f47      488d4c240c     lea rcx, qword [local_ch]
0x00400f4c      488d542408     lea rdx, qword [local_8h]
0x00400f51      becf254000     mov esi, 0x4025cf ; "%d %d"
0x00400f56      b800000000     mov eax, 0
0x00400f5b      e890fcffff     call sym.imp.__isoc99_sscanf
0x00400f60      83f801         cmp eax, 1
0x00400f63      7f05           jg 0x400f6a
0x00400f65      e8d0040000     call sym.explode_bomb
0x00400f6a      837c240807     cmp dword [local_8h], 7
```

The `0x4025cf` address which is loaded into `esi` contains the string `%d %d`. This is the first parameter to `sscanf` on `0x00400f5b` address and suggests that we need to input two numbers. Additionally, the numbers are loaded into `local_8h` (first number) and `local_ch` (second number). 

The first number is then checked if it is smaller or equal to 7, otherwise the bomb explodes.

When the condition is met, `local_8h` is loaded into `eax` and used in `jmp qword [rax*8 + 0x402470]` instruction.

Further disassembling of `0x402470` shows the following data:
```
- offset -   0 1  2 3  4 5  6 7  8 9  A B  C D  E F  0123456789ABCDEF
0x00402470  7c0f 4000 0000 0000 b90f 4000 0000 0000  |.@.......@.....
0x00402480  830f 4000 0000 0000 8a0f 4000 0000 0000  ..@.......@.....
0x00402490  910f 4000 0000 0000 980f 4000 0000 0000  ..@.......@.....
0x004024a0  9f0f 4000 0000 0000 a60f 4000 0000 0000  ..@.......@.....
```

Looking at these bytes as int64 reveals that these are addresses that are contained in the `phase_3 function` right after the `jmp` instruction (observe `0x400f7c` and other addresses):

```
0x00400f71      8b442408       mov eax, dword [local_8h] 
0x00400f75      ff24c5702440.  jmp qword [rax*8 + 0x402470]
0x00400f7c      b8cf000000     mov eax, 0xcf
0x00400f81      eb3b           jmp 0x400fbe
0x00400f83      b8c3020000     mov eax, 0x2c3
0x00400f88      eb34           jmp 0x400fbe
0x00400f8a      b800010000     mov eax, 0x100
0x00400f8f      eb2d           jmp 0x400fbe
0x00400f91      b885010000     mov eax, 0x185
0x00400f96      eb26           jmp 0x400fbe
0x00400f98      b8ce000000     mov eax, 0xce
0x00400f9d      eb1f           jmp 0x400fbe
0x00400f9f      b8aa020000     mov eax, 0x2aa
0x00400fa4      eb18           jmp 0x400fbe
0x00400fa6      b847010000     mov eax, 0x147
0x00400fab      eb11           jmp 0x400fbe
```

Meaning that we are looking at a switch-case. If we enter `0` as `local_8h`, the `jmp` will refer to `[0 * 8 + 0x402470] = 0x400f7c` which is the next instruction `mov eax, 0xcf`.

A jump to `0x400fbe` will take place and at that address a `cmp eax, dword [local_ch]` will occur. If `local_ch` is not the same as `eax`, the defusal will fail, meaning that the combination of `0 207` as input should defuse phase 3:

```
0 207 
Halfway there!
```

