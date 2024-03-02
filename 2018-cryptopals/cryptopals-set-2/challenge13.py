import re

import challenge10
import challenge11

def kv_parsing(kvstr):
    """
    """
    return {i: j for i, j in re.findall('([^=&]+)=([^=&]+)', kvstr)}
    
def kv_encoding(kvdict):
    """
    """
    return '&'.join(["{}={}".format(i, j) for i, j in kvdict.items()])
    
def profile_for(mail):
    """
    """
    return kv_encoding({'email': mail, 'uid': 10, 'role': 'user'})
    
def encrypt_profile(mail, key):
    """
    """
    return challenge10.ecb_encrypt(str.encode(profile_for(mail)), key)
    
def decrypt_profile(text, key):
    """
    """
    return kv_parsing(challenge10.ecb_decrypt(text, key).decode())
    
def ecb_cut_and_paste(block_size, key):
    """
    """
    round1 = encrypt_profile("aaaaaaaaaaaaa", key)
    round2 = encrypt_profile(b'aaaaaaaaaaadmin\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b'.decode(), key)
    
    block1 = challenge11.to_blocks(round1, block_size)
    block2 = challenge11.to_blocks(round2, block_size)
    
    payload = block1[0] + block1[1] + block2[1]
    return decrypt_profile(payload, key)
    
if __name__ == "__main__":    
    key = b'm+\xfb`\x1d/~\xb9b\xe7\xd3\xf8,\xdcX\xbc'
    block_size = len(key)
    
    # email=aaaaaaaaaa | aaaauid=10&role= | user
    # email=aaaaaaaaaa | admin\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b | uid=10&role=user|
    #                                       \
    # email=aaaaaaaaaa | aaaauid=10&role= | admin\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b
    p = ecb_cut_and_paste(block_size, key)
    assert p['role'].startswith('admin')
