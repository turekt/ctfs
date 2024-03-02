from binascii import hexlify
from itertools import cycle

import challenge2
    
important_work = b"""Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"""
key = b'ICE'
should_come_to = '0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f'
assert hexlify(challenge2.xor(important_work, key)).decode() == should_come_to
