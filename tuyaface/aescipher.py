import base64
from Crypto.Cipher import AES  

def encrypt(key, raw, use_base64=True):
    
    cipher = AES.new(
        key.encode('latin1'), 
        mode=AES.MODE_ECB
    )
    crypted_text = cipher.encrypt(_pad(raw))
   
    if use_base64:
        return base64.b64encode(crypted_text)
    return crypted_text


def decrypt(key, enc, use_base64=True):
    
    if use_base64:
        enc = base64.b64decode(enc)
   
    cipher = AES.new(
        key.encode('latin1'), 
        mode=AES.MODE_ECB
    )
    raw = cipher.decrypt(enc)
    return _unpad(raw).decode('utf-8')
    
 
def _pad(s):
    # self.bs = 32  # 32 work fines for ON, does not work for OFF. Padding different compared to js version https://github.com/codetheweb/tuyapi/
    bs = 16
    padnum = bs - len(s) % bs
    return s + padnum * chr(padnum).encode()


def _unpad(s):
    return s[:-ord(s[len(s)-1:])]