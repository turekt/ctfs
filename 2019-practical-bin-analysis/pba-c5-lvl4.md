# Practical Binary Analysis - Chapter 5

## lvl4

This level was pretty straightforward and requires no explanation:

```
binary@binary-VirtualBox:~/code/chapter5/challenge4$ file lvl4
lvl4: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=f8785d89a1f11e7b413c08c6176ad1ed7b95ca08, stripped
binary@binary-VirtualBox:~/code/chapter5/challenge4$ ./lvl4
binary@binary-VirtualBox:~/code/chapter5/challenge4$ ltrace ./lvl4
__libc_start_main(0x4004a0, 1, 0x7ffe0fcf2e08, 0x400650 <unfinished ...>
setenv("FLAG", "656cf8aecb76113a4dece1688c61d0e7"..., 1)             = 0
+++ exited (status 0) +++
binary@binary-VirtualBox:~/code/chapter5/challenge4$ cd ..
binary@binary-VirtualBox:~/code/chapter5$ ./oracle 656cf8aecb76113a4dece1688c61d0e7
+~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~+
| Level 4 completed, unlocked lvl5         |
+~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~+
Run oracle with -h to show a hint
```
