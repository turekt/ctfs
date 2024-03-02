from Crypto.Cipher import AES
from binascii import unhexlify
from itertools import zip_longest, combinations

block_size = 16
best = (0, None)

with open('8.txt') as fp:
    for hexline in fp:
        hexline = hexline.replace('\n', '')
        line = unhexlify(hexline)
        # split into blocks of 16 B
        blocks = [line[i: i + block_size] for i in range(0, len(line), block_size)]
        
        # sum the number of same bytes in the blocks
        matches = sum([sum([1 if a == b else 0 for a, b in combinations(ith, 2)]) for ith in zip_longest(*blocks)])
        if matches > best[0]:
            best = (matches, hexline)
        
print(best)
