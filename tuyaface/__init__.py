"""Functionality for communicating with a Tuya device."""
import time
import socket
import json
from bitstring import BitArray
import binascii
from hashlib import md5
import logging

from . import aescipher
from .const import CMD_TYPE
from .helper import hex2bytes

logger = logging.getLogger(__name__)


def _generate_json_data(device_id: str, command: int, data: dict) -> str:
    """
    Fill the data structure for the command with the given values.

    return: json str
    """

    payload_dict = {
        CMD_TYPE.CONTROL: {"devId": "", "uid": "", "t": ""},
        CMD_TYPE.STATUS: {"gwId": "", "devId": ""},
        CMD_TYPE.HEART_BEAT: {},
        CMD_TYPE.DP_QUERY: {"gwId": "", "devId": "", "uid": "", "t": ""},
        CMD_TYPE.CONTROL_NEW: {"devId": "", "uid": "", "t": ""},
        CMD_TYPE.DP_QUERY_NEW: {"devId": "", "uid": "", "t": ""},
    }

    json_data = payload_dict.get(command, {})

    if "gwId" in json_data:
        json_data["gwId"] = device_id
    if "devId" in json_data:
        json_data["devId"] = device_id
    if "uid" in json_data:
        json_data["uid"] = device_id  # still use id, no seperate uid
    if "t" in json_data:
        json_data["t"] = str(int(time.time()))

    if command == CMD_TYPE.CONTROL_NEW:
        json_data["dps"] = {"1": None, "2": None, "3": None}
    if data is not None:
        json_data["dps"] = data

    return json.dumps(json_data)


def _generate_payload(
    device: dict, command: int, data: dict = None, request_cnt: int = 0
):
    """
    Generate the payload to send.

    Args:
        device: Device attributes
        request_cnt: request sequence number
        command: The type of command.
            This is one of the entries from payload_dict
        data: The data to be send.
            This is what will be passed via the 'dps' entry
    """

    # TODO: don't overwrite variables
    payload_json = (
        _generate_json_data(device["deviceid"], command, data)
        .replace(" ", "")
        .encode("utf-8")
    )

    header_payload_hb = b""
    payload_hb = payload_json

    if device["protocol"] == "3.1":

        if command == CMD_TYPE.CONTROL:
            payload_crypt = aescipher.encrypt(device["localkey"], payload_json)
            premd5string = (
                b"data=" + payload_crypt + b"||lpv=" + b"3.1||" + device["localkey"]
            )
            m = md5()
            m.update(premd5string)
            hexdigest = m.hexdigest()

            header_payload_hb = b"3.1" + hexdigest[8:][:16].encode("latin1")
            payload_hb = header_payload_hb + payload_crypt

    elif device["protocol"] == "3.3":

        if command != CMD_TYPE.DP_QUERY:
            # add the 3.3 header
            header_payload_hb = b"3.3" + b"\0\0\0\0\0\0\0\0\0\0\0\0"

        payload_crypt = aescipher.encrypt(device["localkey"], payload_json, False)
        payload_hb = header_payload_hb + payload_crypt
    else:
        raise Exception("Unknown protocol %s." % (device["protocol"]))

    return _stitch_payload(payload_hb, request_cnt, command)


def _stitch_payload(payload_hb: bytes, request_cnt: int, command: int):
    """Join the payload request parts together."""

    command_hb = command.to_bytes(4, byteorder="big")
    request_cnt_hb = request_cnt.to_bytes(4, byteorder="big")

    payload_hb = payload_hb + hex2bytes("000000000000aa55")

    payload_hb_len_hs = len(payload_hb).to_bytes(4, byteorder="big")

    header_hb = hex2bytes("000055aa") + request_cnt_hb + command_hb + payload_hb_len_hs
    buffer_hb = header_hb + payload_hb

    # calc the CRC of everything except where the CRC goes and the suffix
    hex_crc = format(binascii.crc32(buffer_hb[:-8]) & 0xFFFFFFFF, "08X")
    return buffer_hb[:-8] + hex2bytes(hex_crc) + buffer_hb[-4:]


def _process_raw_reply(device: dict, raw_reply: bytes) -> str:
    """
    Split the raw reply(s) into chuncks and decrypts it.

    returns json str or str (error)
    """

    # TODO: don't overwrite variables
    for s in BitArray(raw_reply).split("0x000055aa", bytealigned=True):
        sbytes = s.tobytes()
        payload = None

        # Skip invalid messages
        if len(sbytes) < 28 or not s.endswith("0x0000aa55"):
            continue

        # Parse header
        seq = int.from_bytes(sbytes[4:8], byteorder="big")
        cmd = int.from_bytes(sbytes[8:12], byteorder="big")
        size = int.from_bytes(sbytes[12:16], byteorder="big")
        return_code = int.from_bytes(sbytes[16:20], byteorder="big")
        has_return_code = (return_code & 0xFFFFFF00) == 0
        crc = int.from_bytes(sbytes[-8:-4], byteorder="big")

        # Check CRC
        if crc != binascii.crc32(sbytes[:-8]):
            continue

        if device["protocol"] == "3.1":

            data = sbytes[20:-8]
            if sbytes[20:21] == b"{":
                if not isinstance(data, str):
                    payload = data.decode()
            elif sbytes[20:23] == b"3.1":
                logger.info("we've got a 3.1 reply, code untested")
                data = data[3:]  # remove version header
                # remove (what I'm guessing, but not confirmed is) 16-bytes of MD5 hexdigest of payload
                data = data[16:]
                payload = aescipher.decrypt(device["localkey"], data)

        elif device["protocol"] == "3.3":
            if size > 12:
                data = sbytes[20 : 8 + size]
                if cmd == CMD_TYPE.STATUS:
                    data = data[15:]
                payload = aescipher.decrypt(device["localkey"], data, False)

        msg = {"cmd": cmd, "seq": seq, "data": payload}
        if has_return_code:
            msg["rc"] = return_code
        logger.debug(
            "(%s) received msg (seq %s): [%x:%s] rc: [%s] payload: [%s]",
            device["ip"],
            msg["seq"],
            msg["cmd"],
            CMD_TYPE(msg["cmd"]).name,
            return_code if has_return_code else "-",
            msg.get("data", ""),
        )
        yield msg


def _select_status_reply(replies: list) -> dict:
    """
    Find the first valid status reply.

    returns dict
    """

    filtered_replies = list(
        filter(lambda x: x["data"] and x["cmd"] == CMD_TYPE.STATUS, replies)
    )
    if len(filtered_replies) == 0:
        return None
    return filtered_replies[0]


def _select_command_reply(
    device: dict, replies: list, command: int, seq: int = None
) -> dict:
    """
    Find a valid command reply.

    returns dict
    """

    status_reply = _select_status_reply(replies)
    if status_reply:
        device["tuyaface"]["status"] = status_reply

    filtered_replies = list(filter(lambda x: x["cmd"] == command, replies))
    if seq is not None:
        filtered_replies = list(filter(lambda x: x["seq"] == seq, filtered_replies))
    if len(filtered_replies) == 0:
        return None
    if len(filtered_replies) > 1:
        logger.info(
            "Got multiple replies %s for request [%x:%s]",
            filtered_replies,
            command,
            CMD_TYPE(command).name,
        )
    return filtered_replies[0]


def _set_properties(device: dict):
    """Set default tuyaface properties."""

    device.setdefault(
        "tuyaface",
        {
            "sequence_nr": 0,
            "connection": None,
            "availability": False,
            "pref_status_cmd": device.get("pref_status_cmd", CMD_TYPE.DP_QUERY),
            "status": None,
        },
    )


def _status(device: dict, expect_reply: int = 1, recurse_cnt: int = 0) -> tuple:
    """
    Send current status request to the tuya device and waits for status update.

    returns (dict, list(dict))
    """

    _set_properties(device)
    cmd = device["tuyaface"]["pref_status_cmd"]

    request_cnt = _send_request(device, cmd, None)

    replies = []
    new_replies = [None]
    request_reply = None
    status_reply = None

    # There might already be data waiting in the socket, e.g. a heartbeat reply, continue reading until
    # the expected response has been received or there is a timeout
    # If status is triggered by DP_QUERY, the status is in a DP_QUERY message
    # If status is triggered by CONTROL_NEW, the status is a STATUS message
    while new_replies and (
        not request_reply or (cmd == CMD_TYPE.CONTROL_NEW and not status_reply)
    ):
        new_replies = list(reply for reply in _receive_replies(device, 1))
        replies = replies + new_replies
        request_reply = _select_command_reply(device, replies, cmd, request_cnt)
        status_reply = _select_status_reply(replies)

    # If there is valid reply to CMD_TYPE.DP_QUERY, use it as status reply
    if (
        cmd == CMD_TYPE.DP_QUERY
        and request_reply
        and request_reply["data"]
        and request_reply["data"] != "json obj data unvalid"
    ):
        status_reply = request_reply

    if not status_reply and recurse_cnt < 3 and device["tuyaface"]["availability"]:
        if request_reply and request_reply["data"] == "json obj data unvalid":
            # some devices (ie LSC Bulbs) only offer partial status with CONTROL_NEW instead of DP_QUERY
            device["tuyaface"]["pref_status_cmd"] = CMD_TYPE.CONTROL_NEW
        status_reply, new_replies = _status(device, 2, recurse_cnt + 1)
        replies = replies + new_replies

    return (status_reply, replies)


def status(device: dict) -> dict:
    """
    Request status of the tuya device.

    returns dict
    """

    # TODO: validate/sanitize request
    reply, _ = _status(device)
    if not reply:
        reply = {"data": "{}"}
    logger.debug("(%s) reply: '%s'", device["ip"], reply)
    device["tuyaface"]["status"] = reply["data"]
    return json.loads(reply["data"])


def _set_status(device: dict, dps: dict) -> tuple:
    """
    Send state update request to the tuya device and waits response.

    returns (dict, list(dict))
    """
    _set_properties(device)

    # TODO: validate/sanitize request
    tmp = {str(k): v for k, v in dps.items()}
    request_cnt = _send_request(device, CMD_TYPE.CONTROL, tmp)

    replies = []
    new_replies = [None]
    request_reply = None

    # There might already be data waiting in the socket, e.g. a heartbeat reply, continue reading until
    # the expected response has been received or there is a timeout
    while new_replies and not request_reply:
        new_replies = list(reply for reply in _receive_replies(device, 1))
        replies = replies + new_replies
        request_reply = _select_command_reply(
            device, replies, CMD_TYPE.CONTROL, request_cnt
        )

    return (request_reply, replies)


def set_status(device: dict, dps: dict) -> bool:
    """
    Send state update request to the tuya device and waits for response.

    returns bool
    """

    reply, _ = _set_status(device, dps)

    logger.debug("(%s) reply: %s", device["ip"], reply)
    if not reply or ("rc" in reply and reply["rc"] != 0):
        return False
    return True


def set_state(device: dict, value, idx: int = 1) -> bool:
    """
    Send status update request for one dps value to the tuya device.

    returns bool
    """
    if not isinstance(value, (bool, float, int, str)):
        raise ValueError(f"Type {type(value)} not acceptable")

    return set_status(device, {idx: value})


def _connect(device: dict, timeout: int = 2):
    """
    Connect to the tuya device.

    returns connection object
    """

    connection = None

    logger.info("(%s) Connecting to %s", device["ip"], device["ip"])
    try:
        connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        connection.settimeout(timeout)
        connection.connect((device["ip"], 6668))
        device["tuyaface"]["connection"] = connection
        device["tuyaface"]["availability"] = True
        return connection
    except Exception as ex:
        logger.warning(
            "(%s) Failed to connect to %s. Retry in %d seconds",
            device["ip"],
            device["ip"],
            1,
        )
        raise ex


def _receive_replies(device: dict, max_receive_cnt):
    if max_receive_cnt <= 0:
        return

    connection = device["tuyaface"]["connection"]

    try:
        data = connection.recv(4096)
        # logger.debug("(%s) read from socket: '%s'", device["ip"], ''.join(format(x, '02x') for x in data))

        for reply in _process_raw_reply(device, data):
            yield reply
    except socket.timeout:
        device["tuyaface"]["availability"] = False
    except Exception as ex:
        raise ex

    yield from _receive_replies(device, max_receive_cnt - 1)


def _send_request(device: dict, command: int = CMD_TYPE.DP_QUERY, payload: dict = None):
    """
    Connect to the tuya device and send a request.

    returns request counter of the sent request
    """

    connection = device["tuyaface"]["connection"]
    if not connection:
        _connect(device)
        connection = device["tuyaface"]["connection"]

    request_cnt = device["tuyaface"].get("sequence_nr", 0)
    if "sequence_nr" in device["tuyaface"]:
        device["tuyaface"]["sequence_nr"] = request_cnt + 1

    request = _generate_payload(device, command, payload, request_cnt)
    logger.debug(
        "(%s) sending msg (seq %s): [%x:%s] payload: [%s]",
        device["ip"],
        request_cnt,
        command,
        CMD_TYPE(command).name,
        payload,
    )
    # logger.debug("(%s) write to socket: '%s'", device["ip"], ''.join(format(x, '02x') for x in request))
    try:
        connection.send(request)
    except Exception as ex:
        raise ex

    return request_cnt
