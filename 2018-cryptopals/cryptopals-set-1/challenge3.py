from binascii import unhexlify, hexlify
from itertools import cycle

import challenge2

FREQUENCY_TABLE = {
    ord('e'): 12.702,
    ord('t'): 9.056,
    ord('a'): 8.167,
    ord('o'): 7.507,
    ord('i'): 6.966,
    ord('n'): 6.749,
    ord(' '): 6.500,
    ord('s'): 6.327,
    ord('h'): 6.094,
    ord('r'): 5.987,
    ord('d'): 4.253,
    ord('l'): 4.025,
    ord('c'): 2.782,
    ord('u'): 2.758,
    ord('m'): 2.406,
    ord('w'): 2.360,
    ord('f'): 2.228,
    ord('g'): 2.015,
    ord('y'): 1.974,
    ord('p'): 1.929,
    ord('b'): 1.492,
    ord('v'): 0.978,
    ord('k'): 0.772,
    ord('j'): 0.153,
    ord('x'): 0.150,
    ord('q'): 0.095,
    ord('z'): 0.074
}

def etaoin_shrdlu(plaintext):
    """
    
    :param plaintext: plaintext as array of bytes
    :return:          sum of frequency table points
    """
    return sum([FREQUENCY_TABLE[c] if c in FREQUENCY_TABLE else 0.000 for c in plaintext])
    
def hit(linebytes):
    """
    
    :param linebytes: hex string to brute force
    :return:          best brute force hit
    """
    best = (0.000, b'', b'')           # (score, text, key)
    for i in range(255):
        xord = challenge2.xor(linebytes, [i])
        score = etaoin_shrdlu(xord)
        
        if best[0] < score:
            best = (score, xord, i)
            
    return best
    
if __name__ == "__main__":
    hexstring = unhexlify('1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736')
    print(hit(hexstring))
