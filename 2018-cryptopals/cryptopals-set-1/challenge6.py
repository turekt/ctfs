from base64 import b64decode
from binascii import hexlify
from itertools import zip_longest, combinations

import challenge3
import challenge2

def hamming_distance(s1, s2):
    """
    
    :param s1: string as str or bytes
    :param s2: string as str or bytes
    :return:   hamming distance between two strings
    """
    s1 = hexlify(str.encode(s1) if type(s1) == str else s1)
    s2 = hexlify(str.encode(s2) if type(s2) == str else s2)
    return bin(int(s1, 16) ^ int(s2, 16)).count('1')
    
def determine_keysize(ciphertext):
    """
    
    :param ciphertext: ciphertext as bytes
    :return:           probable key size
    """
    smallest = (float("inf"), '')
    
    # for each keysize...
    for keysize in range(2, 40):
        # split
        # 1. first_part, second_part = ciphertext[:keysize], ciphertext[keysize:]
        parts = [ciphertext[i: i+keysize] for i in range(0, len(ciphertext), keysize)]
        # calculate edit distance
        # 1. edit_distance = hamming_distance(first_part, second_part) / keysize
        edit_distance = 0.000
        
        for p in combinations(parts, 2):
            edit_distance += hamming_distance(p[0], p[1])
            
        edit_distance /= len(parts)
        
        if edit_distance < smallest[0]:
            # smallest edit distance is probably the key
            smallest = (edit_distance, keysize)
    
    return smallest
    
def determine_key(keysize, ciphertext):
    """
    
    :param keysize:    probable key size
    :param ciphertext: ciphertext as bytes
    :return:           key as bytes
    """
    # split and transpose
    transposed_blocks = [bytes([ciphertext[j] for j in range(i, len(ciphertext), keysize)]) for i in range(keysize)]
    key = bytearray()
    
    for block in transposed_blocks:
        h = challenge3.hit(block)
        key.append(h[2])
        
    key = bytes(key)
    return key
    
def break_repkey_xor(ciphertext):
    """
    
    :param ciphertext: ciphertext as bytes encrypted with repeating key xor
    :return:           decrypted ciphertext as bytes      
    """
    smallest = determine_keysize(ciphertext)
    keysize = smallest[1]
    
    key = determine_key(keysize, ciphertext)
    return challenge2.xor(ciphertext, key), key
        
if __name__ == "__main__":
    assert hamming_distance('this is a test', 'wokka wokka!!!') == 37

    with open('6.txt') as fp:
        contents = b64decode(fp.read())
        print(break_repkey_xor(contents))
