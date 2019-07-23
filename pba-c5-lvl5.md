# Practical Binary Analysis - Chapter 5

## lvl5

There was not much to see in the lvl5 execution:

```
binary@binary-VirtualBox:~/code/chapter5$ ./lvl5
nothing to see here
binary@binary-VirtualBox:~/code/chapter5$ ./lvl5 aaaaaa
nothing to see here
binary@binary-VirtualBox:~/code/chapter5$ ltrace ./lvl5 aaaaaa
__libc_start_main(0x400500, 2, 0x7ffdcfdd1428, 0x4006f0 <unfinished ...>
puts("nothing to see here"nothing to see here
)                                          = 20
+++ exited (status 1) +++
```

I moved to the `objdump -d -z -M intel lvl5` approach:

```
  400520:	31 ed                	xor    ebp,ebp
  400522:	49 89 d1             	mov    r9,rdx
  400525:	5e                   	pop    rsi
  400526:	48 89 e2             	mov    rdx,rsp
  400529:	48 83 e4 f0          	and    rsp,0xfffffffffffffff0
  40052d:	50                   	push   rax
  40052e:	54                   	push   rsp
  40052f:	49 c7 c0 60 07 40 00 	mov    r8,0x400760
  400536:	48 c7 c1 f0 06 40 00 	mov    rcx,0x4006f0
  40053d:	48 c7 c7 00 05 40 00 	mov    rdi,0x400500
  400544:	e8 87 ff ff ff       	call   4004d0 <__libc_start_main@plt>
  400549:	f4                   	hlt    
  40054a:	66 0f 1f 44 00 00    	nop    WORD PTR [rax+rax*1+0x0]
  400550:	b8 4f 10 60 00       	mov    eax,0x60104f
  400555:	55                   	push   rbp
  400556:	48 2d 48 10 60 00    	sub    rax,0x601048
  40055c:	48 83 f8 0e          	cmp    rax,0xe
  400560:	48 89 e5             	mov    rbp,rsp
  400563:	76 1b                	jbe    400580 <__printf_chk@plt+0xa0>
  400565:	b8 00 00 00 00       	mov    eax,0x0
  40056a:	48 85 c0             	test   rax,rax
  40056d:	74 11                	je     400580 <__printf_chk@plt+0xa0>
  40056f:	5d                   	pop    rbp
  400570:	bf 48 10 60 00       	mov    edi,0x601048
  400575:	ff e0                	jmp    rax
  400577:	66 0f 1f 84 00 00 00 	nop    WORD PTR [rax+rax*1+0x0]
  40057e:	00 00 
  400580:	5d                   	pop    rbp
  400581:	c3                   	ret    
```

The `mov rdi, 0x400500` suggests the main function:

```
  400500:	48 83 ec 08          	sub    rsp,0x8
  400504:	bf 97 07 40 00       	mov    edi,0x400797
  400509:	e8 a2 ff ff ff       	call   4004b0 <puts@plt>
  40050e:	b8 01 00 00 00       	mov    eax,0x1
  400513:	48 83 c4 08          	add    rsp,0x8
  400517:	c3                   	ret    
```

The main function does nothing except printing to stdout. But a quick scroll showed interesting instructions:

```
...
  400638:	48 89 44 24 28       	mov    QWORD PTR [rsp+0x28],rax
  40063d:	31 c0                	xor    eax,eax
  40063f:	48 b8 10 60 21 33 15 	movabs rax,0x6223331533216010
  400646:	33 23 62 
  400649:	c6 44 24 20 00       	mov    BYTE PTR [rsp+0x20],0x0
  40064e:	48 89 04 24          	mov    QWORD PTR [rsp],rax
  400652:	48 b8 45 65 76 34 41 	movabs rax,0x6675364134766545
  400659:	36 75 66 
  40065c:	48 89 44 24 08       	mov    QWORD PTR [rsp+0x8],rax
  400661:	48 b8 17 67 75 64 10 	movabs rax,0x6570331064756717
  400668:	33 70 65 
  40066b:	48 89 44 24 10       	mov    QWORD PTR [rsp+0x10],rax
  400670:	48 b8 18 35 76 62 11 	movabs rax,0x6671671162763518
...
```

The hex that is moved to rax looks like ASCII. I thought that this was the flag at first so I did:

```
>>> unhexlify('622333153321601066753641347665456671671162763518')
b'b#3\x153!`\x10fu6A4veEfqg\x11bv5\x18'
```

But not all of the bytes are actual ASCII, so my guess would be it is some kind of encryption or encoding, so best bet would be to change the "main" function to another address.

I first blindly looked for the `push rbp; mov rbp, rsp` instructions and found one at `0x40060a`. When I patched the binary, the binary segfaulted, so I looked once more in detail and observed:

```
...
  40060a:	55                   	push   rbp
  40060b:	48 89 e5             	mov    rbp,rsp
  40060e:	ff d0                	call   rax
  400610:	5d                   	pop    rbp
  400611:	e9 7a ff ff ff       	jmp    400590 <__printf_chk@plt+0xb0>
  400616:	66 2e 0f 1f 84 00 00 	nop    WORD PTR cs:[rax+rax*1+0x0]
  40061d:	00 00 00 
  400620:	53                   	push   rbx
  400621:	be 74 07 40 00       	mov    esi,0x400774
  400626:	bf 01 00 00 00       	mov    edi,0x1
  40062b:	48 83 ec 30          	sub    rsp,0x30
  40062f:	64 48 8b 04 25 28 00 	mov    rax,QWORD PTR fs:0x28
  400636:	00 00 
  400638:	48 89 44 24 28       	mov    QWORD PTR [rsp+0x28],rax
  40063d:	31 c0                	xor    eax,eax
  40063f:	48 b8 10 60 21 33 15 	movabs rax,0x6223331533216010
...
```

The `0x40060e` address had a `call rax` instruction and my assumption was that this instruction was the reason because of the segfault. Next step was to try with few instruction that come afterwards and would make sense as a starting point - the `0x400620`. After the patch:

```
binary@binary-VirtualBox:~/code/chapter5/challenge5$ ./lvl5 
key = 0x00400620
decrypted flag = 0fa355cbec64a05f7a5d050e836b1a1f
binary@binary-VirtualBox:~/code/chapter5/challenge5$ cd ..
binary@binary-VirtualBox:~/code/chapter5$ ./oracle 0fa355cbec64a05f7a5d050e836b1a1f
+~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~+
| Level 5 completed, unlocked lvl6         |
+~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~+
Run oracle with -h to show a hint
```
