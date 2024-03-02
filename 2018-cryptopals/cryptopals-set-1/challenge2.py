from binascii import unhexlify, hexlify
from itertools import cycle

def xor(bytes1, bytes2):
    """
    
    :param b1: array of bytes 1
    :param b2: array of bytes 2
    :return:   xor-ed arrays as array of bytes
    """
    bytes1, bytes2 = (bytes2, bytes1) if len(bytes1) < len(bytes2) else (bytes1, bytes2)
    return bytes([b1 ^ b2 for b1, b2 in zip(bytes1, cycle(bytes2))])
    
if __name__ == "__main__":
    the_string = unhexlify('1c0111001f010100061a024b53535009181c')
    xored_against = unhexlify('686974207468652062756c6c277320657965')
    should_produce = '746865206b696420646f6e277420706c6179'

    assert hexlify(xor(the_string, xored_against)).decode() == should_produce
