# Egghunter x64 shellcode

Listing:
- `egghunter.s` - Egghunter x64 shellcode

## Usage

Use `make egghunter [PROJECT=${PROJECT}]`. If no `PROJECT` specified, uses "Hello, World" shellcode.

Egghunter shellcode can be used in accordance with other compatible Makefile targets. Examples:
```
make shellcode PROJECT=egghunter
make disasm PROJECT=egghunter
...
```

## Testing

First terminal:
```
$ make egghunter PROJECT=bind
...
$ out/egghunter
Egghunter length: 46
Shellcode length: 124

```

Second terminal:
```
$ sudo lsof -i -P | grep egghunter
egghunter 8408          ubuntu    3u  IPv4 104744      0t0  TCP *:4444 (LISTEN)
$ nc localhost 4444
id
uid=999(ubuntu) gid=999(ubuntu) groups=999(ubuntu),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),119(lpadmin),130(lxd),131(sambashare)
```
