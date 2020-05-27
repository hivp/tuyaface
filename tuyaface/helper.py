"""Helpers."""


def bytes2hex(data: bytes, pretty: bool = False):
    """Render hexstring from bytes."""
    space = ""
    if pretty:
        space = " "

    return "".join("%02X%s" % (x, space) for x in data)


def hex2bytes(data: str):
    """Parse hexstring to bytes."""
    return bytes.fromhex(data)
