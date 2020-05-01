
import base64
try:
    import Cryptodome
    from Cryptodome.Cipher import AES  # PyCrypto
except ImportError:
    Cryptodome = AES = None
    import pyaes  # https://github.com/ricmoo/pyaes


def encrypt(key, raw, use_base64=True):
    
    key = key.encode('latin1')

    if Cryptodome:
        raw = _pad(raw)
        cipher = AES.new(key, mode=AES.MODE_ECB)
        crypted_text = cipher.encrypt(raw)
    else:
        _ = _pad(raw)
        cipher = pyaes.blockfeeder.Encrypter(
            pyaes.AESModeOfOperationECB(key))  # no IV, auto pads to 16
        crypted_text = cipher.feed(raw)
        crypted_text += cipher.feed()  # flush final block
    #print('crypted_text (%d) %r' % (len(crypted_text), crypted_text))
    if use_base64:
        return base64.b64encode(crypted_text)
    return crypted_text


def decrypt(key, enc, use_base64=True):

    key = key.encode('latin1')
    
    if use_base64:
        enc = base64.b64decode(enc)
    # print('enc (%d) %r %s ->%s<-' % (len(enc), enc, type(self.key), self.key))
    
    if Cryptodome:
        cipher = AES.new(key, AES.MODE_ECB)
        raw = cipher.decrypt(enc)
        return _unpad(raw).decode('utf-8')
    
    cipher = pyaes.blockfeeder.Decrypter(
        pyaes.AESModeOfOperationECB(key))  # no IV, auto pads to 16
    plain_text = cipher.feed(enc)      
    return plain_text + cipher.feed() # flush final block


def _pad(s):
    # self.bs = 32  # 32 work fines for ON, does not work for OFF. Padding different compared to js version https://github.com/codetheweb/tuyapi/
    bs = 16
    padnum = bs - len(s) % bs
    return s + padnum * chr(padnum).encode()


def _unpad(s):
    return s[:-ord(s[len(s)-1:])]