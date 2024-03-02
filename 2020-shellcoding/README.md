# Shellcoding

`PROJECT` listing:
- `hello` - Hello, World x64
- `bind` - TCP bind shell x64
- `reverse` - TCP reverse shell x64
- `decoder` - Single-byte-XOR decoder x64

## Building via Makefile

Possible `Makefile` targets:
- `c` - compile C code
- `asm` - assemble
- `shellcode` - print shellcode to terminal
- `disasm` - disassemble shellcode
- `skeleton` - run shellcode inside skeleton
- `egghunter` - run shellcode via egghunter
- `encoder` - compiles encoder source file
- `decoder` - generates `decoder_sh.s` file containing shellcode

When specifying target, use the `PROJECT` variable to compile specific project.

### Usage examples

Lines starting with `#` specify how to compile without `make`.

TCP bind C code compilation:
```
# gcc -o bind bind.c
make c PROJECT=bind
```

Assembling:
```
# nasm -felf64 bind.s && ld -o bind bind.o
make asm PROJECT=bind
```

Convert assembly to shellcode:
```
# nasm -felf64 bind_sh.s && ld -o bind bind_sh.o
# objcopy -O binary bind shellcode
# hexdump -v -e '"\\x" 1/1 "%02x"' shellcode
make shellcode PROJECT=bind
```

Disassemble shellcode:
```
# ndisasm -b64 shellcode
make disasm PROJECT=bind
```

Test shellcode via skeleton:
```
# Replace SHELLCODE placeholder in skeleton.c with printed shellcode
# gcc -no-pie -fno-stack-protector -z execstack -x c -o skeleton skeleton.c
make skeleton PROJECT=bind
```

Test shellcode via egghunter skeleton:
```
# Replace EGGHUNTER placeholder in eggskeleton.c with printed egghunter
# Replace SHELLCODE placeholder in eggskeleton.c with printed shellcode
# gcc -no-pie -fno-stack-protector -z execstack -x c -o egghunter eggskeleton.c
make shellcode PROJECT=egghunter
make egghunter PROJECT=bind
```

Add encoding layer to shellcode:
```
make shellcode PROJECT=hello
# Replace ENCODED placeholder in decoder.s with printed encoded shellcode
make decoder
# Replace SHELLCODER placeholder in skeleton.c with decoder shellcode
make skeleton PROJECT=decoder
```

Results are stored in `out` folder if `Makefile` is used (specify `OUT` variable to `make` to change folder name).
