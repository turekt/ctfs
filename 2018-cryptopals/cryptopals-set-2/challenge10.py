from Crypto.Cipher import AES
from itertools import cycle
from base64 import b64decode

import challenge9

BLOCK_SIZE = 16

def ecb_encrypt(plaintext, key):
    """
    
    :param plaintext: plain text to decrypt
    :param key:       key used for encryption
    :return:          cipher text as bytes
    """
    plaintext = challenge9.pad(plaintext, BLOCK_SIZE)
    return AES.new(key, AES.MODE_ECB).encrypt(plaintext)
    
def ecb_decrypt(ciphertext, key):
    """
    
    :param ciphertext: cipher text to decrypt
    :param key:        key used for encryption
    :return:           plain text as bytes
    """
    return AES.new(key, AES.MODE_ECB).decrypt(ciphertext)

def cbc_encrypt(plaintext, key, iv):
    """
    
    :param plaintext: plain text to decrypt
    :param key:       key used for encryption
    :param iv:        initialization vector
    :return:          cipher text as bytes
    """
    plaintext = challenge9.pad(plaintext, BLOCK_SIZE)
    ciphertext = bytearray()
    
    for i in range(0, len(plaintext), BLOCK_SIZE):
        block = plaintext[i: i + BLOCK_SIZE]
        _bytes = ecb_encrypt(xor(block, iv), key)
        iv = _bytes
        ciphertext += _bytes
        
    return bytes(ciphertext)
    
def cbc_decrypt(ciphertext, key, iv):
    """
    
    :param ciphertext: cipher text to decrypt
    :param key:        key used for encryption
    :param iv:         initialization vector
    :return:           plain text as bytes
    """
    plaintext = bytearray()
    
    for i in range(0, len(ciphertext), BLOCK_SIZE):
        block = ciphertext[i: i + BLOCK_SIZE]
        _bytes = xor(ecb_decrypt(block, key), iv)
        iv = block
        plaintext += _bytes
        
    return bytes(plaintext)

def xor(bytes1, bytes2):
    """
    
    :param b1: array of bytes 1
    :param b2: array of bytes 2
    :return:   xor-ed arrays as array of bytes
    """
    bytes1, bytes2 = (bytes2, bytes1) if len(bytes1) < len(bytes2) else (bytes1, bytes2)
    return bytes([b1 ^ b2 for b1, b2 in zip(bytes1, cycle(bytes2))])
    
if __name__ == "__main__":
    key = b"YELLOW SUBMARINE"
    plaintext = b'This is a test for encrypt/decrypt.'
    iv = b'\x00' * BLOCK_SIZE
    ciphertext = cbc_encrypt(plaintext, key, iv)
    plain2 = cbc_decrypt(ciphertext, key, iv)

    assert plain2.startswith(plaintext)
    
    with open('10.txt') as fp:
        contents = b64decode(fp.read())
        
    print(cbc_decrypt(contents, key, iv))
