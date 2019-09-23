# CSAW 365 - TablEZ (RE)

## Binary run

Running the binary shows a classic reverse engineering challenge:

```
$ ./tablez 
Please enter the flag:
asqw
WRONG
```

## Disassembly of the main function

Main function reads the user input and executes a loop. A call to `get_tbl_entry` function at `0x0000098f` is made inside the loop:

```
|           0x0000095d      e8aefdffff     call sym.imp.strlen         ; size_t strlen(const char *s)
|           0x00000962      48898538ffff.  mov qword [local_c8h], rax
|           0x00000969      48c78530ffff.  mov qword [local_d0h], 0
|       ,=< 0x00000974      eb3b           jmp 0x9b1
|       |      ; JMP XREF from 0x000009bf (main)
|      .--> 0x00000976      488d9570ffff.  lea rdx, qword [local_90h]
|      :|   0x0000097d      488b8530ffff.  mov rax, qword [local_d0h]
|      :|   0x00000984      4801d0         add rax, rdx               
|      :|   0x00000987      0fb600         movzx eax, byte [rax]
|      :|   0x0000098a      0fbec0         movsx eax, al
|      :|   0x0000098d      89c7           mov edi, eax
|      :|   0x0000098f      e8b6feffff     call sym.get_tbl_entry       ; <-- call to get_tbl_entry
|      :|   0x00000994      89c1           mov ecx, eax
|      :|   0x00000996      488d9570ffff.  lea rdx, qword [local_90h]
|      :|   0x0000099d      488b8530ffff.  mov rax, qword [local_d0h]
|      :|   0x000009a4      4801d0         add rax, rdx              
|      :|   0x000009a7      8808           mov byte [rax], cl
|      :|   0x000009a9      48838530ffff.  add qword [local_d0h], 1
|      :|      ; JMP XREF from 0x00000974 (main)
|      :`-> 0x000009b1      488b8530ffff.  mov rax, qword [local_d0h]
|      :    0x000009b8      483b8538ffff.  cmp rax, qword [local_c8h]
|      `==< 0x000009bf      72b5           jb 0x976
```

Parameter which is passed to the `get_tbl_entry` function is the current character of the user's input as seen by:

```
48c78530ffff.  mov qword [local_d0h], 0      ; i = 0
eb3b           jmp 0x9b1
488d9570ffff.  lea rdx, qword [local_90h]    ; load address of input to rdx
488b8530ffff.  mov rax, qword [local_d0h]    ; rax is now the same as i
4801d0         add rax, rdx                  ; rax value is added to the loaded address in rdx
                                             ; resolving as input[i]
0fb600         movzx eax, byte [rax]         ; move with zero extension
0fbec0         movsx eax, al                 ; move with sign extension
                                             ; eax is now char at i
89c7           mov edi, eax                  ; load that character as parameter
e8b6feffff     call sym.get_tbl_entry
```

Before digging deeper into the `get_tbl_entry` it was important to deduce what comes afterwards:

```
|           0x000009c1      4883bd38ffff.  cmp qword [local_c8h], 0x25 ; <-- length check is here
|       ,=< 0x000009c9      7413           je 0x9de
|       |   0x000009cb      488d3d090100.  lea rdi, qword str.WRONG    ; 0xadb ; "WRONG" ; const char * s
|       |   0x000009d2      e829fdffff     call sym.imp.puts           ; int puts(const char *s)
|       |   0x000009d7      b801000000     mov eax, 1
|      ,==< 0x000009dc      eb46           jmp 0xa24
|      ||      ; JMP XREF from 0x000009c9 (main)
|      |`-> 0x000009de      488d8d40ffff.  lea rcx, qword [local_c0h]  ; <-- second check starts here
|      |    0x000009e5      488d8570ffff.  lea rax, qword [local_90h]
|      |    0x000009ec      ba26000000     mov edx, 0x26               ; '&' ; size_t n
|      |    0x000009f1      4889ce         mov rsi, rcx                ; const char * s2
|      |    0x000009f4      4889c7         mov rdi, rax                ; const char * s1
|      |    0x000009f7      e8f4fcffff     call sym.imp.strncmp        ; <-- compare strings
|      |    0x000009fc      85c0           test eax, eax
|      |,=< 0x000009fe      7513           jne 0xa13
|      ||   0x00000a00      488d3dda0000.  lea rdi, qword str.CORRECT__3 ; 0xae1 ; "CORRECT <3" ; const char * s
|      ||   0x00000a07      e8f4fcffff     call sym.imp.puts           ; int puts(const char *s)
|      ||   0x00000a0c      b800000000     mov eax, 0
|     ,===< 0x00000a11      eb11           jmp 0xa24
|     |||      ; JMP XREF from 0x000009fe (main)
|     ||`-> 0x00000a13      488d3dc10000.  lea rdi, qword str.WRONG    ; 0xadb ; "WRONG" ; const char * s
|     ||    0x00000a1a      e8e1fcffff     call sym.imp.puts           ; int puts(const char *s)
|     ||    0x00000a1f      b801000000     mov eax, 1
```

There is a check for length at `0x000009c1` - length should be `0x25` (37). If length check succeeds our input is compared to `local_c0h` which is something loaded when the program starts:

```
48b827b3739d.  movabs rax, -0x4e18ee0a628c4cd9
48bab3be99b3.  movabs rdx, 0x30f4f9f9b399beb3
48898540ffff.  mov qword [local_c0h], rax         ; <-- local_c0h loaded here
48899548ffff.  mov qword [local_b8h], rdx
48b81b719973.  movabs rax, -0x4e669adc8c668ee5
48ba651111be.  movabs rdx, -0x6d866dc41eeee9b
48898550ffff.  mov qword [local_b0h], rax
48899558ffff.  mov qword [local_a8h], rdx
c78560ffffff.  mov dword [local_a0h], 0x65059923
66c78564ffff.  mov word [local_9ch], 0xce
```

I've extracted the `local_c0h` content from the binary via gdb:

```
27b3739df511e7b1b3be99b3f9f9f4301b719973236599b1651111be239927f92399056500
```

## Disassembly of the get_tbl_entry function

The function is small and rather straightforward. The most important part is the loop:

```
|           0x00000850      8845ec         mov byte [local_14h], al     ; our character
|           0x00000853      48c745f80000.  mov qword [local_8h], 0      ; i = 0
|       ,=< 0x0000085b      eb32           jmp 0x88f
|       |      ; JMP XREF from 0x00000897 (sym.get_tbl_entry)
|      .--> 0x0000085d      488b45f8       mov rax, qword [local_8h]    ; rax = i
|      :|   0x00000861      488d1400       lea rdx, qword [rax + rax]   ; rdx = 2*rax (or 2*i)
|      :|   0x00000865      488d05140a20.  lea rax, qword obj.trans_tbl ; rax points to table
|      :|   0x0000086c      0fb60402       movzx eax, byte [rdx + rax]  ; move rax pointer to 2*i and store to eax
|      :|   0x00000870      3845ec         cmp byte [local_14h], al     ; if our character is not the same as the one pointed to
|     ,===< 0x00000873      7515           jne 0x88a                    ; then i++ and start over, else continue below
|     |:|   0x00000875      488b45f8       mov rax, qword [local_8h]    ; rax = i
|     |:|   0x00000879      488d1400       lea rdx, qword [rax + rax]   ; rdx = 2*rax (or 2*i)
|     |:|   0x0000087d      488d05fd0920.  lea rax, qword [0x00201281]  ; rax points to table pointer + 1
|     |:|   0x00000884      0fb60402       movzx eax, byte [rdx + rax]  ; load (table_pointer + 1) + (2*i) to eax
|    ,====< 0x00000888      eb14           jmp 0x89e                    ; exit
|    ||:|      ; JMP XREF from 0x00000873 (sym.get_tbl_entry)
|    |`---> 0x0000088a      488345f801     add qword [local_8h], 1      ; i++
```

This disassembly would mean that the function searches for our character in the table until it is found and converts it to the next byte after our character inside the table. I moved with the extraction of the table and got:

```
0x9b02bb01	0x6c04c403	0x2e064a05	0x45082207
0xb80a3309	0x060cd50b	0xbc0e0a0d	0x7910fa0f
0xe1122411	0xbf14b213	0xad162c15	0x60188617
0xb61aa419	0x591cd81b	0x411e871d	0x7720941f
0x4f22f021	0x6124cb23	0xc0262525	0x2a289727
0x082a5c29	0x9f2cc92b	0x4e2e432d	0xf930cf2f
0x6f323e31	0xe7346533	0x3936c535	0xef38b737
0xc83ad039	0xaa3c2f3b	0x473ec73d	0x81403c3f
0x49423241	0xa644d343	0x2b469645	0x40485847
0x9c4af149	0x1a4cee4b	0xc64e5b4d	0x8050d64f
0x6d522d51	0x3d549a53	0x9356a755	0xe0588457
0x3b5a1259	0x095cb95b	0xba5e695d	0x4860995f
0xb1627361	0x82647c63	0x2766be65	0xfb689d67
0x7e6a6769	0xb36cf46b	0xc26e056d	0x1b705f6f
0x23725471	0x11747173	0xd2763075	0x6878a577
0x3f7a9e79	0x7a7cf57b	0x0b7ece7d	0x85800c7f
0x6382de81	0x8e845e83	0xfe86bd85	0xda886a87
0x888a2689	0xac8ce88b	0x628e038d	0xf690a88f
0x7592f791	0xc3946b93	0x51964695	0x8f98e697
0x769a2899	0x919c5a9b	0x1f9eec9d	0x52a0449f
0xfca201a1	0x3aa48ba3	0xa3a6a1a5	0x10a816a7
0x50aa14a9	0x95accaab	0x4bae92ad	0x0eb035af
0x20b2b5b1	0x5db41db3	0xe2b6c1b5	0x0fb86eb7
0x90baedb9	0xd9bcd4bb	0xddbe42bd	0x57c098bf
0x19c237c1	0x56c478c3	0x74c6afc5	0x04c8d1c7
0x55ca29c9	0x4ccce5cb	0xf2cea0cd	0xdbd089cf
0x38d2e4d1	0xead483d3	0x07d617d5	0x8cd8dcd7
0xb4da8ad9	0xe9dc7bdb	0xebdeffdd	0x0de015df
0xa2e202e1	0x34e4f3e3	0x18e6cce5	0x13e8f8e7
0x7fea8de9	0x21ecaeeb	0xcdeee3ed	0x70f04def
0xfdf253f1	0x72f4abf3	0x1cf664f5	0xa9f866f7
0x1efab0f9	0xdffcd7fb	0x7dfe36fd	0x000031ff
```

When observing the table it is obvious that it's a key-value pair where the key is the first byte and value is second. Table is looked at as two byte pairs (also keep in mind of little endian).

First few mappings translate to:

```
0x01 <-> 0xbb
0x02 <-> 0x9b
0x03 <-> 0xc4
0x04 <-> 0x6c
...
```

Quick test confirms the above statements since the first letter of the flag ('f') maps to the first byte of our target input (`0x66 <-> 0x27`). Quick python scripting and we can get the flag:

```
from binascii import unhexlify

// blocks contains table 4-byte blocks without 0x prefix
blocks = ['9b02bb01', '6c04c403', '2e064a05', ...]
target = '27b3739df511e7b1b3be99b3f9f9f4301b719973236599b1651111be239927f92399056500'

mapping = {}
for i in blocks:
    mapping[i[4:6]] = i[6:]
    mapping[i[:2]] = i[2:4]

flag = ''
for i in [target[i:i+2] for i in range(0, len(target), 2)]:
    flag += mapping[i]
    
print(unhexlify(flag))

>>> b'flag{t4ble_l00kups_ar3_b3tter_f0r_m3\x00'
```

Not perfect, but did the job. :)
