# CMU Bomb lab - Secret phase

The secret phase activation is checked in the `phase_defused` function after all 6 phases have been successfully finished:

```
0x004015d8      833d81212000.  cmp dword obj.num_input_strings, 6
0x004015df      755e           jne 0x40163f
0x004015e1      4c8d442410     lea r8, qword [local_10h]
0x004015e6      488d4c240c     lea rcx, qword [local_ch]
0x004015eb      488d542408     lea rdx, qword [local_8h]
0x004015f0      be19264000     mov esi, str.d__d__s        ; 0x402619 ; "%d %d %s"
0x004015f5      bf70386000     mov edi, 0x603870
0x004015fa      e8f1f5ffff     call sym.imp.__isoc99_sscanf
0x004015ff      83f803         cmp eax, 3
0x00401602      7531           jne 0x401635
0x00401604      be22264000     mov esi, str.DrEvil
0x00401609      488d7c2410     lea rdi, qword [local_10h]
0x0040160e      e825fdffff     call sym.strings_not_equal
0x00401613      85c0           test eax, eax
0x00401615      751e           jne 0x401635
0x00401617      bff8244000     mov edi, str.Curses__you_ve_found_the_secret_phase
```

First the program checks if number of input strings is six. Afterwards, an input is loaded from `0x603870` which is parsed as `"%d %d %s"`, and the `%s` parts needs to be equal to `DrEvil`. To make all of this quicker we check this with gdb:

```
(gdb) x/s 0x603870
0x603870 <input_strings+240>:	"3 0"
```

If we can recall, this input string is the same as our input in phase 3. After adding `DrEvil` to the end of the phase 3 input, we unlock the secret phase:

```
$ ./bomb
Welcome to my fiendish little bomb. You have 6 phases with
which to blow yourself up. Have a nice day!
Border relations with Canada have never been better.
Phase 1 defused. How about the next one?
1 2 4 8 16 32
That's number 2.  Keep going!
0 207
Halfway there!
3 0 DrEvil
So you got that one.  Try this one.
Y_^UVW
Good work!  On to the next...
4 3 2 1 6 5
Curses, you've found the secret phase!
But finding it and solving it are quite different...
```

## Debugging the secret phase

Secret phase is rather small, but uses both recursion and structs. The end goal is that `eax` register contains value `2` in order to successfully defuse the bomb.

Let's first check how the structs are laid out:

```
(gdb) x/128wx 0x6030f0
0x6030f0 <n1>:	    0x00000024	0x00000000	0x00603110	0x00000000
0x603100 <n1+16>:	0x00603130	0x00000000	0x00000000	0x00000000
0x603110 <n21>:	    0x00000008	0x00000000	0x00603190	0x00000000
0x603120 <n21+16>:	0x00603150	0x00000000	0x00000000	0x00000000
0x603130 <n22>:	    0x00000032	0x00000000	0x00603170	0x00000000
0x603140 <n22+16>:	0x006031b0	0x00000000	0x00000000	0x00000000
0x603150 <n32>:	    0x00000016	0x00000000	0x00603270	0x00000000
0x603160 <n32+16>:	0x00603230	0x00000000	0x00000000	0x00000000
0x603170 <n33>:	    0x0000002d	0x00000000	0x006031d0	0x00000000
0x603180 <n33+16>:	0x00603290	0x00000000	0x00000000	0x00000000
0x603190 <n31>:	    0x00000006	0x00000000	0x006031f0	0x00000000
0x6031a0 <n31+16>:	0x00603250	0x00000000	0x00000000	0x00000000
0x6031b0 <n34>:	    0x0000006b	0x00000000	0x00603210	0x00000000
0x6031c0 <n34+16>:	0x006032b0	0x00000000	0x00000000	0x00000000
0x6031d0 <n45>:	    0x00000028	0x00000000	0x00000000	0x00000000
0x6031e0 <n45+16>:	0x00000000	0x00000000	0x00000000	0x00000000
0x6031f0 <n41>:	    0x00000001	0x00000000	0x00000000	0x00000000
0x603200 <n41+16>:	0x00000000	0x00000000	0x00000000	0x00000000
0x603210 <n47>:	    0x00000063	0x00000000	0x00000000	0x00000000
0x603220 <n47+16>:	0x00000000	0x00000000	0x00000000	0x00000000
0x603230 <n44>:	    0x00000023	0x00000000	0x00000000	0x00000000
0x603240 <n44+16>:	0x00000000	0x00000000	0x00000000	0x00000000
0x603250 <n42>:	    0x00000007	0x00000000	0x00000000	0x00000000
0x603260 <n42+16>:	0x00000000	0x00000000	0x00000000	0x00000000
0x603270 <n43>:	    0x00000014	0x00000000	0x00000000	0x00000000
0x603280 <n43+16>:	0x00000000	0x00000000	0x00000000	0x00000000
0x603290 <n46>:	    0x0000002f	0x00000000	0x00000000	0x00000000
0x6032a0 <n46+16>:	0x00000000	0x00000000	0x00000000	0x00000000
0x6032b0 <n48>:	    0x000003e9	0x00000000	0x00000000	0x00000000
0x6032c0 <n48+16>:	0x00000000	0x00000000	0x00000000	0x00000000
0x6032d0 <node1>:	0x0000014c	0x00000001	0x006032e0	0x00000000
0x6032e0 <node2>:	0x000000a8	0x00000002	0x00000000	0x00000000
```

If you look carefully at the pointers, you will observe that the structs are ordered into a binary tree and their structure is:

```
          ----n1----- 
         /           \
      n21             n22
     /   \           /   \
  n31     n32     n33     n34
 /  \    /   \   /   \   /   \
n41 n42 n43 n44 n45 n46 n47 n48
```

By looking at fun7 disassembly we have two positions where we can change the `eax` value, `0x0040121c` and `0x00401232`:

```
0x0040120d      8b17           mov edx, dword [rdi]
0x0040120f      39f2           cmp edx, esi
0x00401211      7e0d           jle 0x401220
0x00401213      488b7f08       mov rdi, qword [rdi + 8]
0x00401217      e8e8ffffff     call sym.fun7
0x0040121c      01c0           add eax, eax
0x0040121e      eb1d           jmp 0x40123d
0x00401220      b800000000     mov eax, 0
0x00401225      39f2           cmp edx, esi
0x00401227      7414           je 0x40123d
0x00401229      488b7f10       mov rdi, qword [rdi + 0x10]
0x0040122d      e8d2ffffff     call sym.fun7
0x00401232      8d440001       lea eax, dword [rax + rax + 1]
0x00401236      eb05           jmp 0x40123d
```

If we want to convert this to C, it would look similar to:

```c
if (*curr_node > esi) {
    eax = fun7(curr_node->left, esi);
    eax = 2*eax;
} else {
    eax = 0;
    if (*curr_node != esi) {
        eax = fun7(curr_node->right, esi);
        eax = 2*eax + 1
    }
}
```

Therefore, if we need `eax` to equal to `2`, we just need to get the following combination:

```
eax = 2*0+1 = 1 -> right
eax = 2*1   = 2 -> left
```

But, analysing the tree, this is not as trivial to get, since all moves will result in a number that is different from 2:

```
n31 = two moves left        = 0
n32 = one left + one right  = 1
n33 = one right + one left  = 1
n34 = two moves right       = 3
```

What we can do here is, since we will be satisfied with an additional left move at the start, we can add an additional calculation that should not influence `eax` in any way:

```
eax = 2*0   = 0 -> left
eax = 2*0+1 = 1 -> right
eax = 2*1   = 2 -> left
```

These facts lead us to a possible node - `n43`.

By using the `n43` node value (`0x14=20`), we will start to move left + right + left and when returning back from recursive calls, `eax` will be changed as specified above:

```
20
Wow! You've defused the secret stage!
Congratulations! You've defused the bomb!
```
