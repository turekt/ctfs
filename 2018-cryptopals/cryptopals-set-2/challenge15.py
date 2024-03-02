def pkcs7_padding(text, size):
    """
    
    :param text: text with padding as bytes
    :param size: block size
    :return:     text without padding, throws ValueError
    """        
    pad = text[-1]
    if any(text[-i] != pad for i in range(1, pad + 1)):
        raise ValueError('PKCS#7 padding not valid')
        
    return text[:-pad]
    
def assert_test(a1, a2, exception_thrown=False):
    """
    
    :param a1:               provided bytes
    :param a2:               expected bytes
    :param exception_thrown: True if exception is expected, False otherwise
    """
    try:
        test = pkcs7_padding(a1, 16) == a2
    except ValueError:
        test = exception_thrown
        
    assert test
    
    
if __name__ == '__main__':
    assert_test(b'ICE ICE BABY\x04\x04\x04\x04', b'ICE ICE BABY')
    assert_test(b'ICE ICE BABY\x05\x05\x05\x05', None, True)
    assert_test(b'ICE ICE BABY\x01\x02\x03\x04', None, True)
    assert_test(b'ICE ICE BABY WAT', None, True)
    assert_test(b'ICE ICE BABY WAT\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10', b'ICE ICE BABY WAT')
