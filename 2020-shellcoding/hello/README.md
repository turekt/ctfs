# Hello world x64 shellcode

Listing:
- `hello.c` - hello world C code
- `hello.s` - asm rewrite of C code
- `hello_sh.s` - adapted asm for shellcode

## Usage

Use `make (target) PROJECT=hello`.

## Running

```
$ make skeleton PROJECT=hello
...
$ out/skeleton 
Shellcode Length:  48
Hello, World$
```
