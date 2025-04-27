# 2025 HTB Cyber Apocalypse - Crypto Hourcle

Problem:
```
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import os, string, random, re

KEY = os.urandom(32)

password = ''.join([random.choice(string.ascii_letters+string.digits) for _ in range(20)])

def encrypt_creds(user):
    padded = pad((user + password).encode(), 16)
    IV = os.urandom(16)
    cipher = AES.new(KEY, AES.MODE_CBC, iv=IV)
    ciphertext = cipher.decrypt(padded)
    return ciphertext

def admin_login(pwd):
    return pwd == password


def show_menu():
    return input('''
=========================================
||                                     ||
||   🏰 Eldoria's Shadow Keep 🏰       ||
||                                     ||
||  [1] Seal Your Name in the Archives ||
||  [2] Enter the Forbidden Sanctum    ||
||  [3] Depart from the Realm          ||
||                                     ||
=========================================

Choose your path, traveler :: ''')

def main():
    while True:
        ch = show_menu()
        print()
        if ch == '1':
            username = input('[+] Speak thy name, so it may be sealed in the archives :: ')
            pattern = re.compile(r"^\w{16,}$")
            if not pattern.match(username):
                print('[-] The ancient scribes only accept proper names-no forbidden symbols allowed.')
                continue
            encrypted_creds = encrypt_creds(username)
            print(f'[+] Thy credentials have been sealed in the encrypted scrolls: {encrypted_creds.hex()}')
        elif ch == '2':
            pwd = input('[+] Whisper the sacred incantation to enter the Forbidden Sanctum :: ')
            if admin_login(pwd):
                print(f"[+] The gates open before you, Keeper of Secrets! {open('flag.txt').read()}")
                exit()
            else:
                print('[-] You salt not pass!')
        elif ch == '3':
            print('[+] Thou turnest away from the shadows and fade into the mist...')
            exit()
        else:
            print('[-] The oracle does not understand thy words.')

if __name__ == '__main__':
    main()
```

Solution to leak the password (guessing the password char by char through bruteforce and block matching):
```
from pwn import *
from binascii import hexlify, unhexlify

import string

BLOCK1 = b"0"*16

def xor(var, key):
    return bytes(a ^ b for a, b in zip(var, key))

r = remote("localhost", 4444)
password = b""
for i in range(16):
    pos = 15 - i
    for j in string.ascii_letters+string.digits:
        r.recvuntil(b":: ")
        r.sendline(b"1")
        r.recvuntil(b":: ")
        # TODO fixme
        block_input_1 = b"0"*pos + password + j.encode()
        block_input_2 = b"0"*pos
        payload = BLOCK1 + block_input_1 + block_input_2
        r.sendline(payload)
#        print(f"PAYLOAD: {payload}")
        r.recvuntil(b"scrolls: ")
        hexstring = r.readline().strip()
#        print(f"HEXSTRING: {hexstring[:32]} {hexstring[32:64]} {hexstring[64:]}")

        hexbytes = unhexlify(hexstring)
        b1, b2, b3 = hexbytes[:16], hexbytes[16:32], hexbytes[32:48]
        r2 = xor(b2, BLOCK1)
        r3 = xor(b3, block_input_1)
        if r2 == r3:
            password += j.encode()
            print(f"password: {password}")

for i in range(4):
    pos = 15 - i
    for j in string.ascii_letters+string.digits:
        r.recvuntil(b":: ")
        r.sendline(b"1")
        r.recvuntil(b":: ")
        block_input_1 = b"0"*pos + password[:16-pos]
        block_input_2 = password[16-pos:] + j.encode()
        block_input_3 = b"0"*pos
        payload = BLOCK1 + block_input_1 + block_input_2 + block_input_3
#        print(payload)
        r.sendline(payload)
        r.recvuntil(b"scrolls: ")
        hexstring = r.readline().strip()

        hexbytes = unhexlify(hexstring)
        b1, b2, b3, b4, b5 = hexbytes[:16], hexbytes[16:32], hexbytes[32:48], hexbytes[48:64], hexbytes[64:80]
#        print(f"{hexlify(b1)}, {hexlify(b2)}, {hexlify(b3)}, hexlify{b4}")
        r3 = xor(b3, block_input_1)
        r4 = xor(b5, block_input_1)
        if r3 == r4:
            password += j.encode()
            print(f"password: {password}")

print(f"FIESTA: {password}")
r.interactive()
```


```
$ python3 xpl.py 
[+] Opening connection to 94.237.57.114 on port 43554: Done
password: b'a'
password: b'aZ'
password: b'aZ9'
password: b'aZ9V'
password: b'aZ9VK'
password: b'aZ9VKM'
password: b'aZ9VKM1'
password: b'aZ9VKM1P'
password: b'aZ9VKM1Pg'
password: b'aZ9VKM1PgS'
password: b'aZ9VKM1PgSl'
password: b'aZ9VKM1PgSlQ'
password: b'aZ9VKM1PgSlQe'
password: b'aZ9VKM1PgSlQeX'
password: b'aZ9VKM1PgSlQeXg'
password: b'aZ9VKM1PgSlQeXgX'
password: b'aZ9VKM1PgSlQeXgXc'
password: b'aZ9VKM1PgSlQeXgXct'
password: b'aZ9VKM1PgSlQeXgXcts'
password: b'aZ9VKM1PgSlQeXgXctsd'
FIESTA: b'aZ9VKM1PgSlQeXgXctsd'
[*] Switching to interactive mode

=========================================
||                                     ||
||   ? Eldoria's Shadow Keep ?       ||
||                                     ||
||  [1] Seal Your Name in the Archives ||
||  [2] Enter the Forbidden Sanctum    ||
||  [3] Depart from the Realm          ||
||                                     ||
=========================================

Choose your path, traveler :: $ 2

[+] Whisper the sacred incantation to enter the Forbidden Sanctum :: $ aZ9VKM1PgSlQeXgXctsd
[+] The gates open before you, Keeper of Secrets! HTB{encrypting_with_CBC_decryption_is_as_insecure_as_ECB___they_also_both_fail_the_penguin_test_2139bcb18efeba7e325a5e8ffc1fdc7a}
[*] Got EOF while reading in interactive
$  
```
