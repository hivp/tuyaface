"""Helpers for AES crypto."""
import base64
from Cryptodome.Cipher import AES


def encrypt(key, raw, use_base64=True):
    """Encrypt and optionally base64-encode."""
    crypted_text = _cipher(key).encrypt(_pad(raw))

    if use_base64:
        return base64.b64encode(crypted_text)
    return crypted_text


def decrypt(key, enc, use_base64=True):
    """Optionally base64-decode and decrypt."""
    decoded = enc
    if use_base64:
        decoded = base64.b64decode(enc)

    raw = _cipher(key).decrypt(decoded)
    return _unpad(raw).decode("utf-8")


def _cipher(key):
    return AES.new(key.encode("latin1"), mode=AES.MODE_ECB)


def _pad(s):
    # self.bs = 32  # 32 work fines for ON, does not work for OFF. Padding different compared to js version https://github.com/codetheweb/tuyapi/
    bs = 16
    padnum = bs - len(s) % bs
    return s + padnum * chr(padnum).encode()


def _unpad(s):
    return s[: -ord(s[len(s) - 1 :])]
