# Practical Binary Analysis - Chapter 5

## lvl7

This time, the file was not an ELF binary:

```
binary@binary-VirtualBox:~/code/chapter5/challenge7$ ./lvl7 
bash: ./lvl7: cannot execute binary file: Exec format error
binary@binary-VirtualBox:~/code/chapter5/challenge7$ file lvl7
lvl7: gzip compressed data, last modified: Sat Dec  1 17:30:15 2018, from Unix
```

Archive contained a `stage1` binary with another archive that was password protected. The binary was unresponsive and ltrace showed no useful info.

Moved onto `objdump` and `gdb` and while reversing I saw another interesting part of the code:

```
  4003e0:	ba a4 05 40 00       	mov    edx,0x4005a4
  4003e5:	0f 1f 00             	nop    DWORD PTR [rax]
  4003e8:	0f be 02             	movsx  eax,BYTE PTR [rdx]
  4003eb:	83 f8 30             	cmp    eax,0x30
  4003ee:	7c 12                	jl     400402 <__libc_start_main@plt+0x42>
  4003f0:	83 f8 5a             	cmp    eax,0x5a
  4003f3:	7f 0d                	jg     400402 <__libc_start_main@plt+0x42>
  4003f5:	eb 09                	jmp    400400 <__libc_start_main@plt+0x40>
  4003f7:	64 75 6d             	fs jne 400467 <__libc_start_main@plt+0xa7>
  4003fa:	70 20                	jo     40041c <__libc_start_main@plt+0x5c>
  4003fc:	65 63 78 00          	movsxd edi,DWORD PTR gs:[rax+0x0]
  400400:	89 c1                	mov    ecx,eax
```

After eax is checked if it is in range from `0x30` to `0x5a`, there is a `jmp 400400` which jumps over 5 bytes starting from `0x4003f7`. Again, taking into account how odd the instructions look at that address, this must be data:

```
>>> unhexlify('64756d702065637800')
b'dump ecx\x00'
```

I guess that this is a hint that would be seen via `strings` output. I just did a quick check:

```
binary@binary-VirtualBox:~/code/chapter5/challenge7$ strings stage1
/lib64/ld-linux-x86-64.so.2
libc.so.6
__libc_start_main
__gmon_start__
GLIBC_2.2.5
	dump ecx                    <--- yep, here it is
UH-0
AWAVA
AUATL
[]A\A]A^A_
 S)TA
E2 KE
;*3$"
GCC: (Ubuntu 5.4.0-6ubuntu1~16.04.9) 5.4.0 20160609
...
```

So, I did as advised, ran `gdb`, set a hook on an instruction that was inside the loop and extracted the bytes that were in ecx by printing every byte that was in ecx at every iteration.

Result was as expected:

```
unhexlify('5354414745324b4559')
b'STAGE2KEY'
```

I extracted the stage two with the dumped key and got an interesting output from the second binary:

```
#include <stdio.h>
#include <string.h>
#include <vector>
#include <algorithm>

int main()
{
std::vector<char> hex;
char q[] = "#include <stdio.h>\n#include <string.h>\n#include <vector>\n#include <algorithm>\n\nint main()\n{\nstd::vector<char> hex;\nchar q[] = \"%s\";\nint i, _0F;\nchar c, qc[4096];\n\nfor(i = 0; i < 32; i++) for(c = '0'; c <= '9'; c++) hex.push_back(c);\nfor(i = 0; i < 32; i++) for(c = 'A'; c <= 'F'; c++) hex.push_back(c);\nstd::srand(55);\nstd::random_shuffle(hex.begin(), hex.end());\n\n_0F = 0;\nfor(i = 0; i < strlen(q); i++)\n{\nif(q[i] == 0xa)\n{\nqc[_0F++] = 0x5c;\nqc[_0F] = 'n';\n}\nelse if(q[i] == 0x22)\n{\nqc[_0F++] = 0x5c;\nqc[_0F] = 0x22;\n}\nelse if(!strncmp(&q[i], \"0F\", 2) && (q[i-1] == '_' || i == 545))\n{\nchar buf[3];\nbuf[0] = q[i];\nbuf[1] = q[i+1];\nbuf[2] = 0;\nunsigned j = strtoul(buf, NULL, 16);\nqc[_0F++] = q[i++] = hex[j];\nqc[_0F] = q[i] = hex[j+1];\n}\nelse qc[_0F] = q[i];\n_0F++;\n}\nqc[_0F] = 0;\n\nprintf(q, qc);\n\nreturn 0;\n}\n";
int i, _0F;
char c, qc[4096];

for(i = 0; i < 32; i++) for(c = '0'; c <= '9'; c++) hex.push_back(c);
for(i = 0; i < 32; i++) for(c = 'A'; c <= 'F'; c++) hex.push_back(c);
std::srand(55);
std::random_shuffle(hex.begin(), hex.end());

_0F = 0;
for(i = 0; i < strlen(q); i++)
{
if(q[i] == 0xa)
{
qc[_0F++] = 0x5c;
qc[_0F] = 'n';
}
else if(q[i] == 0x22)
{
qc[_0F++] = 0x5c;
qc[_0F] = 0x22;
}
else if(!strncmp(&q[i], "0F", 2) && (q[i-1] == '_' || i == 545))
{
char buf[3];
buf[0] = q[i];
buf[1] = q[i+1];
buf[2] = 0;
unsigned j = strtoul(buf, NULL, 16);
qc[_0F++] = q[i++] = hex[j];
qc[_0F] = q[i] = hex[j+1];
}
else qc[_0F] = q[i];
_0F++;
}
qc[_0F] = 0;

printf(q, qc);

return 0;
}
```

After meddling with the inner script and looking into the logic, I noticed that the "0F" byte is changing. My guess was that continuous compiling and execution of the provided source will eventually give all flag bytes, so I wrote a quick and dirty script:

```
for i in `seq 1 16`; do
  sed '42q;d' code.cc
  g++ code.cc
  ./a.out > code.cc
done
```

Quick find and replace + lowercasing:

```
binary@binary-VirtualBox:~/code/chapter5$ ./oracle 0f25e512a7763eefb7696b3aeda1f964
+~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~+
| Level 7 completed, unlocked lvl8         |
+~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~+
Run oracle with -h to show a hint
```
