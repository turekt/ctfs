# CMU Bomb lab - Phase 2

Second phase expects six numbers (revealed with `sym.read_six_numbers` function call at the beginning). Afterwards, a loop is initiated with the following body:

```
0x00400f17      8b43fc         mov eax, dword [rbx - 4] # load previous number
0x00400f1a      01c0           add eax, eax             # previous + previous
0x00400f1c      3903           cmp dword [rbx], eax     # cmp 2*prev with current
0x00400f1e      7405           je 0x400f25              # jump over if equal
0x00400f20      e815050000     call sym.explode_bomb
0x00400f25      4883c304       add rbx, 4               # i++
0x00400f29      4839eb         cmp rbx, rbp             # i == array_end ?
0x00400f2c      75e9           jne 0x400f17             # back to top if false
0x00400f2e      eb0c           jmp 0x400f3c             # continue if true
```

The key to an exploding bomb is at `0x00400f1c` where `[rbx]` and `eax` are being compared, and if they are equals, the `sym.explode_bomb` call is jumped over. At `0x00400f17` and `0x00400f1a`, `eax` register is being loaded by taking the previous value from where `rbx` points to, and its value is multiplied by 2 (`add eax, eax`).

To check where `rbx` is pointing to, refer to `0x00400f30`:

```
0x00400f30      488d5c2404     lea rbx, qword [local_4h]    # rsp + 0x04
0x00400f35      488d6c2418     lea rbp, qword [local_18h]   # rsp + 0x18
```

It is obvious that `rbx` will point to `rsp+0x4` which is the second element in our six numbers input, whereas `rbp` will point to `rsp+0x18` which is the memory location after the last element in our six numbers input (`0x18 = 24 = 4*6 = sizeof(int32)*6`).

With all of this information, it is clear that, in order to defuse, we need to specify an array of six numbers where the following number = 2\*previous, or more simply put: `i[n] = 2*i[n-1]`:

```
1 2 4 8 16 32
That's number 2.  Keep going!
```
