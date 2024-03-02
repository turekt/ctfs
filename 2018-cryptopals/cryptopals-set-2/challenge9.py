def pad_size(_bytes, size):
    """
    
    :param _bytes: byte array to pad
    :param size:   size of the block
    :return:       padding size
    """
    blen = len(_bytes)
    mod = blen % size
    return size - mod if mod else 0

def pad(_bytes, size):
    """
    
    :param _bytes: byte array to pad
    :param size:   size of the block
    :return:       padded byte array
    """
    padlen = pad_size(_bytes, size)
    return _bytes + bytes([padlen for i in range(padlen)])
    
if __name__ == "__main__":
    s = b'YELLOW SUBMARINE'
    assert pad(s, 20) == b'YELLOW SUBMARINE\x04\x04\x04\x04'
    assert pad(s, 18) == b'YELLOW SUBMARINE\x02\x02'
    assert pad(s, 5) == b'YELLOW SUBMARINE\x04\x04\x04\x04'
