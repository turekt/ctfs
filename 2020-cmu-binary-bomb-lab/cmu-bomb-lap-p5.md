# CMU Bomb lab - Phase 5

Phase 5 of the bomb lab is a bit different, this time we are need to input a string of length 6 (as shown in `main` and `sym.string_length` check in `phase_5` function). If we fast forward a bit into the end of `phase_5` function assembly, you will observe that, except for the string length check, there is a `sym.strings_not_equal` check that will detonate the bomb if strings are not equal:

```
0x004010ae      c644241600     mov byte [local_16h], 0
0x004010b3      be5e244000     mov esi, str.flyers
0x004010b8      488d7c2410     lea rdi, qword [local_10h]
0x004010bd      e876020000     call sym.strings_not_equal
0x004010c2      85c0           test eax, eax
0x004010c4      7413           je 0x4010d9
0x004010c6      e86f030000     call sym.explode_bomb
```

The check compares the string "flyers" with `local_10h` value which means that our input string needs to result to "flyers" after transformation.

For the transformation itself, this is the vital part:

```
0x00401067      4889fb         mov rbx, rdi
...             ...            ...
0x0040108b      0fb60c03       movzx ecx, byte [rbx + rax]
0x0040108f      880c24         mov byte [rsp], cl
0x00401092      488b1424       mov rdx, qword [rsp]
0x00401096      83e20f         and edx, 0xf
0x00401099      0fb692b02440.  movzx edx, byte [rdx + str.maduiersnfotvbylSo_you_think_you_can_stop_the_bomb_with_ctrl_c__do_you]
0x004010a0      88540410       mov byte [rsp + rax + 0x10], dl
0x004010a4      4883c001       add rax, 1
0x004010a8      4883f806       cmp rax, 6
0x004010ac      75dd           jne 0x40108b
```

Our string is loaded into `rbx` and its characters are loaded into `ecx` one by one. Each character is put on stack, loaded into `rdx` and _AND_'ed with `0xf`. The resulting number in `edx` is used as an index for the "maduiersnfotvbyl" string.

After finding the corresponding char, it is loaded to `[rsp + rax + 0x10]` meaning that the resulting string is being populated into `local_10h` variable which is afterwards loaded into `rdi` and used in `sym.strings_not_equal` call as observed earlier.

So, in order to deduce a string that will transform into "flyers", we need to be aware of what `and edx, 0xf` means. If a number is _AND_'ed with 0xf, this means that it is preserving the last 4 bits of a number or, more clearly, the last hex digit (everything else is zeroed out), for instance:

```
  edx = 0b10111111 (= 0xbe)
& 0xf = 0b00001110
------------------
  edx = 0b00001110 (= 0x0e)
```

Quick utilization of a python shell will give us what we need to supply as input:

```
>>> a = 'maduiersnfotvbyl'
>>> for i in 'flyers':
...     hex(a.find(i))
... 
'0x9'
'0xf'
'0xe'
'0x5'
'0x6'
'0x7'
>>> for i in 'flyers':
...     print(chr(0x50+a.find(i)), end='')
... 
Y_^UVW>>>
```

The `0x50` addition was a pick based on result being in a satisfying ASCII range. Given string `Y_^UVW` should defuse this stage:

```
Y_^UVW
Good work!  On to the next...
```
