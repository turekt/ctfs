# CMU Bomb lab - Phase 4

Phase 4 starts the same as phase 3 - by expecting two numbers which are loaded in `local_8h` (first) and `local_ch` (second). After setting those two numbers, `local_8h` must be less or equals to `0xe` and then `func4` function is called with the following arguments: `local_8h`, `0`, `0xe`. So, the function call in C would look like: `func4(local_8h, 0, 14)`.

Before diving into `func4` function, if we check how the second input (`local_ch` variable) is used, there is a comparison at `0x00401051`:

```
0x00401051      837c240c00     cmp dword [local_ch], 0
0x00401056      7405           je 0x40105d
0x00401058      e8dd030000     call sym.explode_bomb
0x0040105d      4883c418       add rsp, 0x18
0x00401061      c3             ret
```

The above assembly indicates that `local_ch` needs to be set to `0` in order to jump over `sym.explode_bomb` function call, which resolves what the second number needs to be set to.

## func4 disassembly

Function `func4` is called at `0x00401048` and its return value is tested by the next instruction, requiring from us that the return value in `eax` is set to `0`:

```
0x00401048      e881ffffff     call sym.func4
0x0040104d      85c0           test eax, eax
0x0040104f      7507           jne 0x401058
0x00401051      837c240c00     cmp dword [local_ch], 0
0x00401056      7405           je 0x40105d
0x00401058      e8dd030000     call sym.explode_bomb
```

To deduce what the `local_8h` number needs to be for this, we look into `func4` function. The function is small and seems recursive. By observing carefully, it is obvious that recursive calls can be bypassed by conforming to two checks at `0x00400fe2` and `0x00400ff7`:

```
0x00400fe2      39f9           cmp ecx, edi
0x00400fe4      7e0c           jle 0x400ff2
0x00400fe6      8d51ff         lea edx, dword [rcx - 1]
0x00400fe9      e8e0ffffff     call sym.func4
0x00400fee      01c0           add eax, eax
0x00400ff0      eb15           jmp 0x401007
0x00400ff2      b800000000     mov eax, 0
0x00400ff7      39f9           cmp ecx, edi
0x00400ff9      7d0c           jge 0x401007
0x00400ffb      8d7101         lea esi, dword [rcx + 1]
0x00400ffe      e8cbffffff     call sym.func4
0x00401003      8d440001       lea eax, dword [rax + rax + 1]
0x00401007      4883c408       add rsp, 8
```

The first compare checks if `ecx` is less or equals to `edi` and the second compare checks if `ecx` is greater or equals to `edi`. Additionally, if first check is satisfied, `eax` will be set to value `0`, which solves the `eax` requirement we observed previously. If both checks are satisfied, no recursive calls will be made and `eax` will be set to `0`.

Now, keeping in mind that `edi` register is the first argument of the `func4` function (`local_8h` variable that we influence), let's move on to how `ecx` register value is calculated:

```
0x00400fd2      89d0           mov eax, edx
0x00400fd4      29f0           sub eax, esi
0x00400fd6      89c1           mov ecx, eax
0x00400fd8      c1e91f         shr ecx, 0x1f
0x00400fdb      01c8           add eax, ecx
0x00400fdd      d1f8           sar eax, 1
0x00400fdf      8d0c30         lea ecx, dword [rax + rsi]
```

The third function argument `edx = 14` is loaded into eax and subtracted by first argument `esi = 0`. This value is shifted right by `0x1f` and added to itself. Before being loaded into `ecx`, `eax` is shifted right (arithmetic) and address of `[rax + rsi]` is loaded into ecx.

Since we know all values, we can easily calculate `ecx` value: 

```
>>> edx=14              # 3rd arg to func4
>>> esi=0               # 2nd arg to func4
>>> eax=edx             # mov eax, edx
>>> eax-=esi            # sub eax, esi
>>> ecx=eax             # mov ecx, eax
>>> ecx=ecx>>0x1f       # shr ecx, 0x1f
>>> eax+=ecx            # add eax, ecx
>>> eax=eax>>1          # sar eax, 1
>>> ecx=eax+esi         # lea ecx, dword [rax + rsi]
>>> ecx, eax
(7, 7)
```

In correlation with comparison checks we have observed before `ecx` value analysis, the `local_8h` should be set to `7` in order to bypass recursive calls and set `eax` to 0, giving us success in phase 4:

```
7 0
So you got that one.  Try this one.
```

