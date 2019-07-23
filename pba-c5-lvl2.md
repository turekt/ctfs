# Practical Binary Analysis - Chapter 5

## lvl2

When running the challenge we see that hex bytes are written to stdout:

```
binary@binary-VirtualBox:~/code/chapter5/challenge2$ ./lvl2
a5
binary@binary-VirtualBox:~/code/chapter5/challenge2$ ./lvl2
88
binary@binary-VirtualBox:~/code/chapter5/challenge2$ ./lvl2
74
binary@binary-VirtualBox:~/code/chapter5/challenge2$ ./lvl2
a5
binary@binary-VirtualBox:~/code/chapter5/challenge2$ ./lvl2
4f
```

I noticed the `srand` and `rand` calls made in the binary when inspecting via `objdump`, and therefore still wanted to look into the binary before writing the actual script which collects the bytes. 

I ran `gdb -q lvl2` and I entered the section in code which seemed critical:

```
(gdb) x/12i $rip
=> 0x400517:	cdq    
   0x400518:	shr    edx,0x1c
   0x40051b:	add    eax,edx
   0x40051d:	and    eax,0xf
   0x400520:	sub    eax,edx
   0x400522:	cdqe   
   0x400524:	mov    rdi,QWORD PTR [rax*8+0x601060]
   0x40052c:	call   0x4004a0 <puts@plt>
   0x400531:	xor    eax,eax
   0x400533:	add    rsp,0x8
   0x400537:	ret    
   0x400538:	nop    DWORD PTR [rax+rax*1+0x0]
```

The part of the code seems to manipulate the eax register which is then used as an index for the array that starts at `0x601060` as seen by `mov rdi,QWORD PTR [rax*8+0x601060]`.

Let's examine that address:

```
(gdb) x/24x 0x601060
0x601060:	0x004006c4	0x00000000	0x004006c7	0x00000000
0x601070:	0x004006ca	0x00000000	0x004006cd	0x00000000
0x601080:	0x004006d0	0x00000000	0x004006d3	0x00000000
0x601090:	0x004006d6	0x00000000	0x004006d9	0x00000000
0x6010a0:	0x004006dc	0x00000000	0x004006df	0x00000000
0x6010b0:	0x004006e2	0x00000000	0x004006e5	0x00000000
```

Look further:

```
(gdb) x/24x 0x004006c4
0x4006c4:	0x34003330	0x34630066	0x00366600	0x33003561
0x4006d4:	0x32660036	0x00666200	0x66003437	0x36640038
0x4006e4:	0x00336400	0x36003138	0x66640063	0x00383800
0x4006f4:	0x3b031b01	0x00000030	0x00000005	0xfffffd9c
0x400704:	0x0000007c	0xfffffe0c	0x000000a4	0xfffffe4c
0x400714:	0x0000004c	0xffffff4c	0x000000bc	0xffffffbc
``` 

Now these bytes look more like ASCII characters. If we examine them as strings:

```
(gdb) x/s 0x004006c4
0x4006c4:	"03"
(gdb) x/16s 0x004006c4
0x4006c4:	"03"
0x4006c7:	"4f"
0x4006ca:	"c4"
0x4006cd:	"f6"
0x4006d0:	"a5"
0x4006d3:	"36"
0x4006d6:	"f2"
0x4006d9:	"bf"
0x4006dc:	"74"
0x4006df:	"f8"
0x4006e2:	"d6"
0x4006e5:	"d3"
0x4006e8:	"81"
0x4006eb:	"6c"
0x4006ee:	"df"
0x4006f1:	"88"
```

Simple attempt on the `oracle` will show that this is it:

```
$ ./oracle 034fc4f6a536f2bf74f8d6d3816cdf88
+~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~+
| Level 2 completed, unlocked lvl3         |
+~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~+
Run oracle with -h to show a hint
```
