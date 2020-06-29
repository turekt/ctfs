# CMU Bomb lab - Phase 6

Phase 6 starts by reading six numbers which are loaded on the stack:

```
0x004010fc      4883ec50       sub rsp, 0x50                # prepare stack
0x00401100      4989e5         mov r13, rsp                 # r13 = rsp
0x00401103      4889e6         mov rsi, rsp
0x00401106      e851030000     call sym.read_six_numbers
0x0040110b      4989e6         mov r14, rsp                 # r14 = rsp

```

The stack pointer is copied into both `r13` and `r14` register. Since `phase_6` function is longer and has few checks, we will try to analyze it in parts.

## Part 1 - nested loop

Right after reading six numbers we have two loops which are nested, indicated by counter in `r12` and `ebx` registers:

```
0x0040110e      41bc00000000   mov r12d, 0                  # i = 0
0x00401114      4c89ed         mov rbp, r13                 # rbp = r13 = rsp
0x00401117      418b4500       mov eax, dword [r13]         # eax = *r13, first value
0x0040111b      83e801         sub eax, 1                   # eax--
0x0040111e      83f805         cmp eax, 5                   # eax <= 5 ?
0x00401121      7605           jbe 0x401128                 # jump over if true
0x00401123      e812030000     call sym.explode_bomb        # if eax > 5, explode
0x00401128      4183c401       add r12d, 1                  # i++
0x0040112c      4183fc06       cmp r12d, 6                  # i == 6?
0x00401130      7421           je 0x401153                  # jump over whole block if true
0x00401132      4489e3         mov ebx, r12d                # else ebx = i
0x00401135      4863c3         movsxd rax, ebx              # rax = ebx, sort of
0x00401138      8b0484         mov eax, dword [rsp + rax*4] # eax = numbers[i]
0x0040113b      394500         cmp dword [rbp], eax         # *rbp != numbers[i] ?
0x0040113e      7505           jne 0x401145                 # if not, jump over
0x00401140      e8f5020000     call sym.explode_bomb
0x00401145      83c301         add ebx, 1                   # ebx++
0x00401148      83fb05         cmp ebx, 5                   # ebx <= 5 ?
0x0040114b      7ee8           jle 0x401135                 # jump back if true
0x0040114d      4983c504       add r13, 4                   # else move r13 to next number
0x00401151      ebc1           jmp 0x401114                 # back to beginning of loop
```

The part between `0x00401117` and `0x00401121` checks if the current value pointed by `r13` is less or equal to 5 after 1 is subtracted, meaning that our numbers should not be bigger than 6. Afterwards, we have two registers that are used as pointers: `rbp` that is pointing to one of the six numbers and `ebx` that is pointing to every number that comes after the one that `rbp` is pointing to (as shown by `mov ebx, r12d` at `0x00401132` and `add ebx, 1` at `0x00401145`).

These loops would loosely translate to the following in C:
```
for (i = 0; i < 5; i++) {
    if (numbers[i]-1 > 5) {
        sym.explode_bomb()
    }
    for (j = i; j <= 5; j++) {
        if (numbers[i] == numbers[j]) {
            sym.explode_bomb()
        }
    }
}
```

Meaning that the first part checks if every number is less or equals to 6 and every position holds a unique number.

## Part 2 - input transformation

Our six number input is located at `[rsp]` and each number takes up 4 bytes (int32). This means that our input spans from `[rsp]` until `[rsp + 6*4] = [rsp + 24] = [rsp + 0x18]`. The second part of the assembly works with location starting from `[rsp + 0x18]`, which is adjacent to our six number input:

```
0x00401153      488d742418     lea rsi, qword [local_18h]   # rsi = *(rsp+0x18)
0x00401158      4c89f0         mov rax, r14                 # rax = r14 = rsp
0x0040115b      b907000000     mov ecx, 7                   # ecx = 7
0x00401160      89ca           mov edx, ecx                 # edx = ecx = 7
0x00401162      2b10           sub edx, dword [rax]         # edx -= numbers[rax]
0x00401164      8910           mov dword [rax], edx         # numbers[rax] = edx
0x00401166      4883c004       add rax, 4                   # rax++
0x0040116a      4839f0         cmp rax, rsi                 # rax != rsi
0x0040116d      75f1           jne 0x401160                 # jump backwards if true
0x0040116f      be00000000     mov esi, 0                   # esi = 0
0x00401174      eb21           jmp 0x401197                 # continue to next part
```

First, `rsi` loads `rsp + 0x18` which is basically the end of our six number input array. Afterwards our six numbers are rotated inside a loop where `rax` is the counter (copies value from `r14` which contains the stack pointer as observed at the beginning of `phase_6` function). Every number is used in subtraction at `0x00401162` meaning that the array is being transformed with the following formula: `numbers[i] = 7 - numbers[i]`.

## Part 3 - array of structs

Based on the previous conversion, instructions from `0x00401176` until `0x004011ab` are working with structs. As this gets overly complicated in the assembly, the dynamic analysis gives us a better overview of what this part does. Setting up a breakpoint at the end of this section will show the following in memory:

```
(gdb) x/12i $rip
=> 0x4011ab <phase_6+183>:	mov    rbx,QWORD PTR [rsp+0x20]
   0x4011b0 <phase_6+188>:	lea    rax,[rsp+0x28]
   0x4011b5 <phase_6+193>:	lea    rsi,[rsp+0x50]
   0x4011ba <phase_6+198>:	mov    rcx,rbx
   0x4011bd <phase_6+201>:	mov    rdx,QWORD PTR [rax]
   0x4011c0 <phase_6+204>:	mov    QWORD PTR [rcx+0x8],rdx
   0x4011c4 <phase_6+208>:	add    rax,0x8
   0x4011c8 <phase_6+212>:	cmp    rax,rsi
   0x4011cb <phase_6+215>:	je     0x4011d2 <phase_6+222>
   0x4011cd <phase_6+217>:	mov    rcx,rdx
   0x4011d0 <phase_6+220>:	jmp    0x4011bd <phase_6+201>
   0x4011d2 <phase_6+222>:	mov    QWORD PTR [rdx+0x8],0x0
(gdb) x/24wx $rsp
0x7fffffffde80:	0x00000001	0x00000006	0x00000005	0x00000004
0x7fffffffde90:	0x00000003	0x00000002	0x00000000	0x00000000
0x7fffffffdea0:	0x006032d0	0x00000000	0x00603320	0x00000000
0x7fffffffdeb0:	0x00603310	0x00000000	0x00603300	0x00000000
0x7fffffffdec0:	0x006032f0	0x00000000	0x006032e0	0x00000000
0x7fffffffded0:	0xffffdfe8	0x00007fff	0x00402210	0x00000000
(gdb) x/24wx 0x006032d0
0x6032d0 <node1>:	0x0000014c	0x00000001	0x006032e0	0x00000000
0x6032e0 <node2>:	0x000000a8	0x00000002	0x006032f0	0x00000000
0x6032f0 <node3>:	0x0000039c	0x00000003	0x00603300	0x00000000
0x603300 <node4>:	0x000002b3	0x00000004	0x00603310	0x00000000
0x603310 <node5>:	0x000001dd	0x00000005	0x00603320	0x00000000
0x603320 <node6>:	0x000001bb	0x00000006	0x00000000	0x00000000
```

As seen on stack, after our input at `0x7fffffffde80`, there are six pointers starting from `0x7fffffffdea0`.
The pointers point to 6 structs which obviously contain two int32 values and one int64 value. For example `node1`:

```
0x6032d0 <node1>:	0x0000014c	0x00000001	0x006032e0	0x00000000
```

we see the first int32 to be `0x14c`, second `0x01` and int64 value `0x6032e0`. The int64 value is a pointer to the next node, and, for the int32 values, the first value is unknown, but the second seems to be just an index.

## Part 4 - structs and numbers link

At a later stage, up until `0x004011da`, the structs are rearranged as per our six number input:

```
(gdb) x/24wx $rsp
0x7fffffffdea0:	0x00000003	0x00000004	0x00000005	0x00000006
0x7fffffffdeb0:	0x00000001	0x00000002	0x00000000	0x00000000
0x7fffffffdec0:	0x006032f0	0x00000000	0x00603300	0x00000000
0x7fffffffded0:	0x00603310	0x00000000	0x00603320	0x00000000
0x7fffffffdee0:	0x006032d0	0x00000000	0x006032e0	0x00000000
0x7fffffffdef0:	0x00000000	0x00000000	0x00402210	0x00000000
(gdb) x/24wx 0x006032f0
0x6032f0 <node3>:	0x0000039c	0x00000003	0x00603300	0x00000000
0x603300 <node4>:	0x000002b3	0x00000004	0x00603310	0x00000000
0x603310 <node5>:	0x000001dd	0x00000005	0x00603320	0x00000000
0x603320 <node6>:	0x000001bb	0x00000006	0x006032d0	0x00000000
0x603330:	0x00000000	0x00000000	0x00000000	0x00000000
0x603340 <host_table>:	0x00402629	0x00000000	0x00402643	0x00000000
```

With all of this knowledge, we dig deeper into the assembly which comes after `0x004011da` and this comparison was raising my spider sense:

```
0x004011df      488b4308       mov rax, qword [rbx + 8]
0x004011e3      8b00           mov eax, dword [rax]
0x004011e5      3903           cmp dword [rbx], eax
0x004011e7      7d05           jge 0x4011ee
0x004011e9      e84c020000     call sym.explode_bomb
0x004011ee      488b5b08       mov rbx, qword [rbx + 8]
0x004011f2      83ed01         sub ebp, 1
0x004011f5      75e8           jne 0x4011df
0x004011f7      4883c450       add rsp, 0x50
```

This part of the assembly checks if the first int32 value is greater or equal than the previous struct and the arrangement of struct nodes is mandated by our six number input.
This means that we need to provide with a six number input that will rearrange the struct nodes so that their first int32 value is descending.

To recap:

```
0x6032d0 <node1>:	0x0000014c
0x6032e0 <node2>:	0x000000a8
0x6032f0 <node3>:	0x0000039c
0x603300 <node4>:	0x000002b3
0x603310 <node5>:	0x000001dd
0x603320 <node6>:	0x000001bb
```

So, our six input number should be `3 4 5 6 1 2`, *but* we should not forget the number conversion that is done prior to the comparison, so we need to put our six numbers into the following formula: `ni = 7 - n` in order to get the right input: `4 3 2 1 6 5`.

```
4 3 2 1 6 5
Congratulations! You've defused the bomb!
```
