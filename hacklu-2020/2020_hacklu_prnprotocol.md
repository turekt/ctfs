# 2020 Hack.lu CTF - P*rn protocol

This misc challenge was straightforward. The PDF document provided in the challenge described the protocol.

The protocol notes payload types and payload description that specifies payload as:

```
Payload length (1 byte) | Payload type (1 byte) | Payload data
```

The payload length is the first byte that takes into account both the type and data. Payload type is the second byte. Six payload types are specified in a separate table. Payload data is specified in Payload type details.

Task was to communicate with the server via the protocol to get the flag. The server sends the message first and provides with a Message ID (type `0x01`) and Identifier payload (type `0x02`). 

We respond back with the same Message ID and Identifier payload and add the Member ID (type `0x03`) required request (data code `0x02`). The request will result in a response that contains our username and password which we use in the next request by sending the server a Login (type `0x04`) request (data code `0x01`). After successful login, we send a simple Flag (type `0x05`) payload request (data code `0x01`) that prints out the flag.

I just followed the protocol description and written out the requests via a python script that got us the flag:

```python
from pwn import *

def get_msg_id(i):
    return b"\x02\x01" + bytes([i])

r = remote('flu.xxx', 2005)
_msgid = 0
resp = r.recv()
print(resp)
msg_id_1 = get_msg_id(_msgid)
identf_1 = b"\x11\x02" + resp[5:21]
mem_id_1 = b"\x02\x03\x02"
data = msg_id_1 + identf_1 + mem_id_1
print("DATA: {}".format(data))
r.send(data)
resp = r.recv()
print(resp)
_msgid += 1

userpass = resp.split(b"\x07\x03\x03")[1]
user, passw = userpass.split(b"\x07\x03\x04")
loginreq = b"\x02\x04\x01"
data = get_msg_id(_msgid) + identf_1 + loginreq
print("LOGINREQ: {}".format(data))
r.send(data)
print(r.recv())

print("USER: {}".format(user))
r.sendline(user)
print(r.recv())
print("PASS: {}".format(passw))
r.sendline(passw)
print(r.recv())

_msgid += 1
data = get_msg_id(_msgid) + identf_1 + b"\x02\x05\x01"
print("FLAGREQ: {}".format(data))
r.send(data)
print(r.recv())
```

It's not the best code, but good enough for getting the flag.
