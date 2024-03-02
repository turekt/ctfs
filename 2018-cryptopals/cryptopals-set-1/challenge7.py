from base64 import b64decode
from Crypto.Cipher import AES

key = "YELLOW SUBMARINE"

with open('7.txt') as fp:
    contents = b64decode(fp.read())
    
aes = AES.new(key, AES.MODE_ECB)
print(aes.decrypt(contents))
