from os import urandom
from random import randint
from itertools import zip_longest, combinations, product

import challenge10

BLOCK_SIZE = 16

def to_blocks(text, block_size):
    """
    
    :param text:       text to split
    :param block_size: block size
    :return:           array with blocks made from text with block_size length
    """
    return [text[i: i + block_size] for i in range(0, len(text), block_size)]

def encryption_oracle(plaintext, iv):
    """
    
    :param plaintext: plain text to encrypt as bytes
    :param iv:        initialization vector
    :return:          tuple where index 0 is cipher mode and index 1 is ECB or CBC encrypted 
                      plain text as bytes (50/50 chance)
    """
    padsize = randint(5, 10)
    plaintext = urandom(padsize) + plaintext + urandom(padsize)
    
    if randint(0, 1):
        return (2, challenge10.cbc_encrypt(plaintext, urandom(BLOCK_SIZE), iv))
    else:
        return (1, challenge10.ecb_encrypt(plaintext, urandom(BLOCK_SIZE)))
        
def ecb_or_cbc(ciphertext):
    """
    
    :param ciphertext: cipher text from which to recognize cipher mode as bytes
    :return:           2 if CBC, 1 if ECB (compliant with AES.MODE_ECB and AES.MODE_CBC)
    """
    # split into blocks of 16 B
    blocks = [ciphertext[i: i + BLOCK_SIZE] for i in range(0, len(ciphertext), BLOCK_SIZE)]
    
    # sum the number of same bytes in the blocks
    matches = sum([sum([1 if i == j else 0 for i, j in product(b1, b2)]) for b1, b2 in combinations(blocks, 2)])
    return 2 if matches < BLOCK_SIZE else 1
    
if __name__ == "__main__":
    max_tries = 100
    global_hit = 0
    
    for h in range(max_tries):
        hit = 0
        
        for i in range(max_tries):
            # around 50% accuracy with total random data
            plaintext = urandom(randint(10, 100))
            # around 99.97% accuracy with specifically crafted data
            # plaintext = b"XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
            
            ciphertext = encryption_oracle(plaintext, b'\x00' * 16)
            mode = ecb_or_cbc(ciphertext[1])
            
            if mode == ciphertext[0]:
                hit += 1
                
        print("Hit rate: {}%".format(hit / max_tries * 100))
        global_hit += hit
        
    print("Average hit rate: {}%".format(global_hit / (max_tries ** 2) * 100))
