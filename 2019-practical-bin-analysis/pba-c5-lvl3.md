# Practical Binary Analysis - Chapter 5

## lvl3

In order to repair the ELF file, I used the ELF specification and hexedit to fix the bytes. Bytes in the header were straightforward to fix:

```
binary@binary-VirtualBox:~/code/chapter5/challenge3$ xxd lvl3.orig | head -n 10
00000000: 7f45 4c46 0201 010b 0000 0000 0000 0000  .ELF............
00000010: 0200 3400 0100 0000 d005 4000 0000 0000  ..4.......@.....
00000020: dead beef 0000 0000 8011 0000 0000 0000  ................
00000030: 0000 0000 4000 3800 0900 4000 1d00 1c00  ....@.8...@.....
00000040: 0600 0000 0500 0000 4000 0000 0000 0000  ........@.......
00000050: 4000 4000 0000 0000 4000 4000 0000 0000  @.@.....@.@.....
00000060: f801 0000 0000 0000 f801 0000 0000 0000  ................
00000070: 0800 0000 0000 0000 0300 0000 0400 0000  ................
00000080: 3802 0000 0000 0000 3802 4000 0000 0000  8.......8.@.....
00000090: 3802 4000 0000 0000 1c00 0000 0000 0000  8.@.............
binary@binary-VirtualBox:~/code/chapter5/challenge3$ xxd lvl3 | head -n 10
00000000: 7f45 4c46 0201 0100 0000 0000 0000 0000  .ELF............
00000010: 0200 3e00 0100 0000 d005 4000 0000 0000  ..>.......@.....
00000020: 4000 0000 0000 0000 8011 0000 0000 0000  @...............
00000030: 0000 0000 4000 3800 0900 4000 1d00 1c00  ....@.8...@.....
00000040: 0600 0000 0500 0000 4000 0000 0000 0000  ........@.......
00000050: 4000 4000 0000 0000 4000 4000 0000 0000  @.@.....@.@.....
00000060: f801 0000 0000 0000 f801 0000 0000 0000  ................
00000070: 0800 0000 0000 0000 0300 0000 0400 0000  ................
00000080: 3802 0000 0000 0000 3802 4000 0000 0000  8.......8.@.....
00000090: 3802 4000 0000 0000 1c00 0000 0000 0000  8.@.............
```

The bytes that needed fixing were:
- byte at 0x07 (e\_ident\[EI\_OSABI\]): from 0x0b (Novell Modesto) to 0x00 (System V)
- byte at 0x12 (e\_machine): from 0x34 (invalid) to 0x3e (x86-64)
- 4 bytes at 0x20 (e\_shoff): from 0xefbeadde to 0x00000040
  - section header starts after the header, and the header length in x86-64 is 0x40 (64) bytes

I ran the binary and got:

```
binary@binary-VirtualBox:~/code/chapter5$ ./challenge3/lvl3
0e2ada7381d04d4d2ed31be82b121aa3  ./challenge3/lvl3
binary@binary-VirtualBox:~/code/chapter5$ ./oracle 0e2ada7381d04d4d2ed31be82b121aa3
Invalid flag: 0e2ada7381d04d4d2ed31be82b121aa3
```

WHAT? That only means that something else is broken. I searched for quite some time, comparing the specification with the binary bytes in details, but I was still missing something. It was time for a hint:

```
$ ./oracle 034fc4f6a536f2bf74f8d6d3816cdf88 -h
Fix four broken things
```

Well, we've only fixed three. I continued my search and eventually saw the section listing:

```
binary@binary-VirtualBox:~/code/chapter5/challenge3$ readelf -S lvl3_1 
There are 29 section headers, starting at offset 0x1180:

Section Headers:
  [Nr] Name              Type             Address           Offset
       Size              EntSize          Flags  Link  Info  Align
  [ 0]                   NULL             0000000000000000  00000000
       0000000000000000  0000000000000000           0     0     0
  [ 1] .interp           PROGBITS         0000000000400238  00000238
       000000000000001c  0000000000000000   A       0     0     1
  [ 2] .note.ABI-tag     NOTE             0000000000400254  00000254
       0000000000000020  0000000000000000   A       0     0     4
  [ 3] .note.gnu.build-i NOTE             0000000000400274  00000274
       0000000000000024  0000000000000000   A       0     0     4
  [ 4] .gnu.hash         GNU_HASH         0000000000400298  00000298
       000000000000001c  0000000000000000   A       5     0     8
  [ 5] .dynsym           DYNSYM           00000000004002b8  000002b8
       00000000000000a8  0000000000000018   A       6     1     8
  [ 6] .dynstr           STRTAB           0000000000400360  00000360
       0000000000000081  0000000000000000   A       0     0     1
  [ 7] .gnu.version      VERSYM           00000000004003e2  000003e2
       000000000000000e  0000000000000002   A       5     0     2
  [ 8] .gnu.version_r    VERNEED          00000000004003f0  000003f0
       0000000000000040  0000000000000000   A       6     1     8
  [ 9] .rela.dyn         RELA             0000000000400430  00000430
       0000000000000018  0000000000000018   A       5     0     8
  [10] .rela.plt         RELA             0000000000400448  00000448
       0000000000000078  0000000000000018  AI       5    24     8
  [11] .init             PROGBITS         00000000004004c0  000004c0
       000000000000001a  0000000000000000  AX       0     0     4
  [12] .plt              PROGBITS         00000000004004e0  000004e0
       0000000000000060  0000000000000010  AX       0     0     16
  [13] .plt.got          PROGBITS         0000000000400540  00000540
       0000000000000008  0000000000000000  AX       0     0     8
  [14] .text             NOBITS           0000000000400550  00000550  <-- NOBITS
       00000000000001f2  0000000000000000  AX       0     0     16
  [15] .fini             PROGBITS         0000000000400744  00000744
       0000000000000009  0000000000000000  AX       0     0     4
  [16] .rodata           PROGBITS         0000000000400750  00000750
       000000000000000c  0000000000000000   A       0     0     4
  [17] .eh_frame_hdr     PROGBITS         000000000040075c  0000075c
       0000000000000034  0000000000000000   A       0     0     4
  [18] .eh_frame         PROGBITS         0000000000400790  00000790
       0000000000000104  0000000000000000   A       0     0     8
  [19] .init_array       INIT_ARRAY       0000000000600e10  00000e10
       0000000000000008  0000000000000000  WA       0     0     8
  [20] .fini_array       FINI_ARRAY       0000000000600e18  00000e18
       0000000000000008  0000000000000000  WA       0     0     8
  [21] .jcr              PROGBITS         0000000000600e20  00000e20
       0000000000000008  0000000000000000  WA       0     0     8
  [22] .dynamic          DYNAMIC          0000000000600e28  00000e28
       00000000000001d0  0000000000000010  WA       6     0     8
  [23] .got              PROGBITS         0000000000600ff8  00000ff8
       0000000000000008  0000000000000008  WA       0     0     8
  [24] .got.plt          PROGBITS         0000000000601000  00001000
       0000000000000040  0000000000000008  WA       0     0     8
  [25] .data             PROGBITS         0000000000601040  00001040
       0000000000000010  0000000000000000  WA       0     0     8
  [26] .bss              NOBITS           0000000000601050  00001050
       0000000000000008  0000000000000000  WA       0     0     1
  [27] .comment          PROGBITS         0000000000000000  00001050
       0000000000000034  0000000000000001  MS       0     0     1
  [28] .shstrtab         STRTAB           0000000000000000  00001084
       00000000000000fc  0000000000000000           0     0     1
Key to Flags:
  W (write), A (alloc), X (execute), M (merge), S (strings), l (large)
  I (info), L (link order), G (group), T (TLS), E (exclude), x (unknown)
  O (extra OS processing required) o (OS specific), p (processor specific)
```

The `.text` section was set to `NOBITS` which is unusual. I fixed the `NOBITS` type to `PROGBITS` with hexedit and tried again:

```
binary@binary-VirtualBox:~/code/chapter5$ ./challenge3/lvl3_1 
3a5c381e40d2fffd95ba4452a0fb4a40  ./challenge3/lvl3_1
binary@binary-VirtualBox:~/code/chapter5$ ./oracle 3a5c381e40d2fffd95ba4452a0fb4a40
+~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~+
| Level 3 completed, unlocked lvl4         |
+~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~+
Run oracle with -h to show a hint
```
