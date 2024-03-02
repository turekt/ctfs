from base64 import b64decode
from os import urandom
from string import printable

import challenge10
import challenge11

def encryption_oracle(plaintext, unknown, key):
    """
    
    :param plaintext: plain text to encrypt as bytes
    :param unknown:   unknown string padded to plain text
    :param key:       encryption key
    :return:          ECB or CBC encrypted plain text as bytes (50/50 chance)
    """
    return challenge10.ecb_encrypt(plaintext + unknown, key)
    
def determine_block_size(unknown, key):
    """
    
    :param unknown: unknown text appended to known plaintext
    :param key:     encryption key
    :return:        block size, if multiple possibilities takes the largest size
    """
    block_sizes = [8, 16, 24, 32]
    s = ord('A')
    
    for i in range(1, 100):
        ciphertext = encryption_oracle(bytes([s] * i), unknown, key)
        cipherlen = len(ciphertext)
        
        remove_sizes = []
        for size in block_sizes:
            if cipherlen % size:
                remove_sizes.append(size)
                
        for size in remove_sizes:
            block_sizes.remove(size)
                
        if len(block_sizes) == 1:
            print("Possible block size: {}".format(block_sizes[0]))
            return block_sizes[0]
            
    print("Multiple block sizes left: {} taking {}".format(block_sizes, block_sizes[-1]))
    return block_sizes[-1]
    
    
def determine_mode(unknown, key):
    """
    
    :param unknown: unknown text appended to known plaintext
    :param key:     encryption key
    :return:        2 if CBC, 1 if ECB
    """
    ciphertext = encryption_oracle(b'XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX', unknown, key)
    mode = challenge11.ecb_or_cbc(ciphertext)
    print("MODE: {}".format("CBC" if mode == 2 else "ECB"))
    return mode
    
def break_crypto(size, unknown, key, modifier=10):
    """
    
    :param size:    block size
    :param unknown: unknown text appended to known plaintext
    :param key:     encryption key
    :return:        2 if CBC, 1 if ECB
    """
    full_size = size * modifier
    payload = 'A' * (full_size)
    
    for i in range(1, full_size):
        control = b'A' * (full_size - i)
        controltext = encryption_oracle(control, unknown, key)
        
        for j in printable:
            payload = payload[:-1] + j
            ciphertext = encryption_oracle(str.encode(payload), unknown, key)
            
            if ciphertext[(full_size - size): full_size] == controltext[(full_size - size): full_size]:
                payload = payload[1:] + 'A'
                break
                
    print(payload)
    return payload
    
if __name__ == '__main__':
    unknown = b64decode("""Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK""")
    key = b'\xeb\xa2|\x1a;\x1ba\x9a_\xe5\x13\xd5\xde\xb8\xfd\x7f'
    
    block_size = determine_block_size(unknown, key)
    mode = determine_mode(unknown, key)
    break_crypto(block_size, unknown, key)
    
