from base64 import b64decode
from os import urandom
from random import randint
from string import printable

import challenge12


    
if __name__ == '__main__':
    unknown = b64decode("""Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK""")
    key = b'\xeb\xa2|\x1a;\x1ba\x9a_\xe5\x13\xd5\xde\xb8\xfd\x7f'
    # TODO append random prefix
    
    block_size = challenge12.determine_block_size(unknown, key)
    mode = challenge12.determine_mode(unknown, key)
    # TODO get size of random prefix and break as in 12
    challenge12.break_crypto(block_size, unknown, key)
    
