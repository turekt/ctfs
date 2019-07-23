# Practical Binary Analysis - Chapter 5

## lvl6

Challenge lvl6 provides some output when ran:

```
binary@binary-VirtualBox:~/code/chapter5/challenge6$ ./lvl6
2 3 5 7 11 13 17 19 23 29 31 37 41 43 47 53 59 61 67 71 73 79 83 89 97 

binary@binary-VirtualBox:~/code/chapter5/challenge6$ ltrace ./lvl6
__libc_start_main(0x4005f0, 1, 0x7ffe21ce5838, 0x400890 <unfinished ...>
__printf_chk(1, 0x400947, 2, 100)                                    = 2
__printf_chk(1, 0x400947, 3, 0x7ffffffe)                             = 2
__printf_chk(1, 0x400947, 5, 0x7ffffffe)                             = 2
__printf_chk(1, 0x400947, 7, 0x7ffffffe)                             = 2
__printf_chk(1, 0x400947, 11, 0x7ffffffe)                            = 3
__printf_chk(1, 0x400947, 13, 0x7ffffffd)                            = 3
__printf_chk(1, 0x400947, 17, 0x7ffffffd)                            = 3
__printf_chk(1, 0x400947, 19, 0x7ffffffd)                            = 3
__printf_chk(1, 0x400947, 23, 0x7ffffffd)                            = 3
__printf_chk(1, 0x400947, 29, 0x7ffffffd)                            = 3
__printf_chk(1, 0x400947, 31, 0x7ffffffd)                            = 3
__printf_chk(1, 0x400947, 37, 0x7ffffffd)                            = 3
__printf_chk(1, 0x400947, 41, 0x7ffffffd)                            = 3
__printf_chk(1, 0x400947, 43, 0x7ffffffd)                            = 3
__printf_chk(1, 0x400947, 47, 0x7ffffffd)                            = 3
__printf_chk(1, 0x400947, 53, 0x7ffffffd)                            = 3
__printf_chk(1, 0x400947, 59, 0x7ffffffd)                            = 3
__printf_chk(1, 0x400947, 61, 0x7ffffffd)                            = 3
__printf_chk(1, 0x400947, 67, 0x7ffffffd)                            = 3
__printf_chk(1, 0x400947, 71, 0x7ffffffd)                            = 3
__printf_chk(1, 0x400947, 73, 0x7ffffffd)                            = 3
__printf_chk(1, 0x400947, 79, 0x7ffffffd)                            = 3
__printf_chk(1, 0x400947, 83, 0x7ffffffd)                            = 3
__printf_chk(1, 0x400947, 89, 0x7ffffffd)                            = 3
__printf_chk(1, 0x400947, 97, 0x7ffffffd)                            = 3
putchar(10, 3, 0, 0x7ffffffd2 3 5 7 11 13 17 19 23 29 31 37 41 43 47 53 59 61 67 71 73 79 83 89 97 
)                                        = 10
+++ exited (status 0) +++

binary@binary-VirtualBox:~/code/chapter5/challenge6$ ltrace ./lvl6 aaaaa
__libc_start_main(0x4005f0, 2, 0x7ffc89bf0b28, 0x400890 <unfinished ...>
strcmp("aaaaa", "get_data_addr")                                     = -6
__printf_chk(1, 0x400947, 2, 100)                                    = 2
__printf_chk(1, 0x400947, 3, 0x7ffffffe)                             = 2
__printf_chk(1, 0x400947, 5, 0x7ffffffe)                             = 2
__printf_chk(1, 0x400947, 7, 0x7ffffffe)                             = 2
__printf_chk(1, 0x400947, 11, 0x7ffffffe)                            = 3
__printf_chk(1, 0x400947, 13, 0x7ffffffd)                            = 3
__printf_chk(1, 0x400947, 17, 0x7ffffffd)                            = 3
__printf_chk(1, 0x400947, 19, 0x7ffffffd)                            = 3
__printf_chk(1, 0x400947, 23, 0x7ffffffd)                            = 3
__printf_chk(1, 0x400947, 29, 0x7ffffffd)                            = 3
__printf_chk(1, 0x400947, 31, 0x7ffffffd)                            = 3
__printf_chk(1, 0x400947, 37, 0x7ffffffd)                            = 3
__printf_chk(1, 0x400947, 41, 0x7ffffffd)                            = 3
__printf_chk(1, 0x400947, 43, 0x7ffffffd)                            = 3
__printf_chk(1, 0x400947, 47, 0x7ffffffd)                            = 3
__printf_chk(1, 0x400947, 53, 0x7ffffffd)                            = 3
__printf_chk(1, 0x400947, 59, 0x7ffffffd)                            = 3
__printf_chk(1, 0x400947, 61, 0x7ffffffd)                            = 3
__printf_chk(1, 0x400947, 67, 0x7ffffffd)                            = 3
__printf_chk(1, 0x400947, 71, 0x7ffffffd)                            = 3
__printf_chk(1, 0x400947, 73, 0x7ffffffd)                            = 3
__printf_chk(1, 0x400947, 79, 0x7ffffffd)                            = 3
__printf_chk(1, 0x400947, 83, 0x7ffffffd)                            = 3
__printf_chk(1, 0x400947, 89, 0x7ffffffd)                            = 3
__printf_chk(1, 0x400947, 97, 0x7ffffffd)                            = 3
putchar(10, 3, 0, 0x7ffffffd2 3 5 7 11 13 17 19 23 29 31 37 41 43 47 53 59 61 67 71 73 79 83 89 97 
)                                        = 10
+++ exited (status 0) +++

binary@binary-VirtualBox:~/code/chapter5/challenge6$ ltrace ./lvl6 get_data_addr
__libc_start_main(0x4005f0, 2, 0x7ffcf283c018, 0x400890 <unfinished ...>
strcmp("get_data_addr", "get_data_addr")                             = 0
__sprintf_chk(0x7ffcf283bb10, 1, 1024, 0x400937)                     = 8
setenv("DATA_ADDR", "0x4006c1", 1)                                   = 0
__printf_chk(1, 0x400947, 2, 100)                                    = 2
__printf_chk(1, 0x400947, 3, 0x7ffffffe)                             = 2
__printf_chk(1, 0x400947, 5, 0x7ffffffe)                             = 2
__printf_chk(1, 0x400947, 7, 0x7ffffffe)                             = 2
__printf_chk(1, 0x400947, 11, 0x7ffffffe)                            = 3
__printf_chk(1, 0x400947, 13, 0x7ffffffd)                            = 3
__printf_chk(1, 0x400947, 17, 0x7ffffffd)                            = 3
__printf_chk(1, 0x400947, 19, 0x7ffffffd)                            = 3
__printf_chk(1, 0x400947, 23, 0x7ffffffd)                            = 3
__printf_chk(1, 0x400947, 29, 0x7ffffffd)                            = 3
__printf_chk(1, 0x400947, 31, 0x7ffffffd)                            = 3
__printf_chk(1, 0x400947, 37, 0x7ffffffd)                            = 3
__printf_chk(1, 0x400947, 41, 0x7ffffffd)                            = 3
__printf_chk(1, 0x400947, 43, 0x7ffffffd)                            = 3
__printf_chk(1, 0x400947, 47, 0x7ffffffd)                            = 3
__printf_chk(1, 0x400947, 53, 0x7ffffffd)                            = 3
__printf_chk(1, 0x400947, 59, 0x7ffffffd)                            = 3
__printf_chk(1, 0x400947, 61, 0x7ffffffd)                            = 3
__printf_chk(1, 0x400947, 67, 0x7ffffffd)                            = 3
__printf_chk(1, 0x400947, 71, 0x7ffffffd)                            = 3
__printf_chk(1, 0x400947, 73, 0x7ffffffd)                            = 3
__printf_chk(1, 0x400947, 79, 0x7ffffffd)                            = 3
__printf_chk(1, 0x400947, 83, 0x7ffffffd)                            = 3
__printf_chk(1, 0x400947, 89, 0x7ffffffd)                            = 3
__printf_chk(1, 0x400947, 97, 0x7ffffffd)                            = 3
putchar(10, 3, 0, 0x7ffffffd2 3 5 7 11 13 17 19 23 29 31 37 41 43 47 53 59 61 67 71 73 79 83 89 97 
)                                        = 10
+++ exited (status 0) +++
```

I reversed the binary with the `objdump` to get more on how this program functions. I identified the main function which starts at `0x4005f0`. While looking the binary with `objdump` I noticed the following:

```
...
  4006a8:	75 e8                	jne    400692 <__sprintf_chk@plt+0xc2>
  4006aa:	85 ff                	test   edi,edi
  4006ac:	74 0a                	je     4006b8 <__sprintf_chk@plt+0xe8>
  4006ae:	83 ff 63             	cmp    edi,0x63
  4006b1:	7f 05                	jg     4006b8 <__sprintf_chk@plt+0xe8>
  4006b3:	41 89 f9             	mov    r9d,edi
  4006b6:	eb b4                	jmp    40066c <__sprintf_chk@plt+0x9c>
  4006b8:	8b 44 24 24          	mov    eax,DWORD PTR [rsp+0x24]
  4006bc:	83 f8 00             	cmp    eax,0x0
  4006bf:	74 10                	je     4006d1 <__sprintf_chk@plt+0x101>
  4006c1:	2e 29 c6             	cs sub esi,eax
  4006c4:	4a 0f 03 a6 ee 2a 30 	rex.WX lsl rsp,WORD PTR [rsi+0x7f302aee]
  4006cb:	7f 
  4006cc:	ec                   	in     al,dx
  4006cd:	c8 c3 ff 42          	enter  0xffc3,0x42
  4006d1:	48 8d ac 24 90 01 00 	lea    rbp,[rsp+0x190]
  4006d8:	00 
  4006d9:	eb 0e                	jmp    4006e9 <__sprintf_chk@plt+0x119>
  4006db:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]
  4006e0:	48 83 c3 04          	add    rbx,0x4
  4006e4:	48 39 dd             	cmp    rbp,rbx
  4006e7:	74 20                	je     400709 <__sprintf_chk@plt+0x139>
  4006e9:	8b 13                	mov    edx,DWORD PTR [rbx]
...
```

The `je 4006d1` instruction at `0x4006bf` was jumping over the next several bytes to `0x4006d1`. Combining this with the fact that the instructions that were jumped over were quite odd, I was 100% certain that bytes from `0x4006c1` to `0x4006d1` was data. When I isolated the bytes, I noticed that the string was hex with 16 bytes length - the same as the flag.

`2e29c64a0f03a6ee2a307fecc8c3ff42`

Trying the hexstring as the flag didn't work:

```
$ ./oracle 2e29c64a0f03a6ee2a307fecc8c3ff42
Invalid flag: 2e29c64a0f03a6ee2a307fecc8c3ff42
```

Long story short: I spent extremely large amount of time trying to find the flag, I fully reversed the binary and could not find anything in the logic to get something else except for the flag I've already tried (yes, examining `0x4006c1` address that was set with `setenv` had the same bytes as the ones I've identified earlier). After trying out everything I could think of, I decided to lookup a writeup for this level and found out that *this hexstring was the actual flag*. Only thing that prevented me from successful submit was that I didn't auto update the provided VM with the instructions that were stated on the book's homepage.

After updating I tried again:

```
$ ./oracle 2e29c64a0f03a6ee2a307fecc8c3ff42
+~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~+
| Level 6 completed, unlocked lvl7         |
+~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~+
Run oracle with -h to show a hint
```
