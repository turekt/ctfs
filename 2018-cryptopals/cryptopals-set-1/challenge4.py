from binascii import unhexlify, hexlify
from itertools import cycle

import challenge3
import challenge2

if __name__ == "__main__":
    with open('4.txt') as fp:
        hits = [challenge3.hit(unhexlify(line.replace('\n', ''))) for line in fp]
        print(sorted(hits, key=lambda k: k[0])[-1])
