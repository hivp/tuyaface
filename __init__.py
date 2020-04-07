version_tuple = (1, 0, 3)
version = version_string = __version__ = '%d.%d.%d' % version_tuple
__author__ = 'tradeface'

import time
import socket
import json
from bitstring import BitArray
import binascii

from tuya import aescipher
from tuya.helper import *

UDP = 0
AP_CONFIG = 1
ACTIVE = 2
BIND = 3
RENAME_GW = 4
RENAME_DEVICE = 5
UNBIND = 6
CONTROL = 7
STATUS = 8
HEART_BEAT = 9
DP_QUERY = 10
QUERY_WIFI = 11
TOKEN_BIND = 12
CONTROL_NEW = 13
ENABLE_WIFI = 14
DP_QUERY_NEW = 16
SCENE_EXECUTE = 17
UDP_NEW = 19
AP_CONFIG_NEW = 20
LAN_GW_ACTIVE = 240
LAN_SUB_DEV_REQUEST = 241
LAN_DELETE_SUB_DEV = 242
LAN_REPORT_SUB_DEV = 243
LAN_SCENE = 244
LAN_PUBLISH_CLOUD_CONFIG = 245
LAN_PUBLISH_APP_CONFIG = 246
LAN_EXPORT_APP_CONFIG = 247
LAN_PUBLISH_SCENE_PANEL = 248
LAN_REMOVE_GW = 249
LAN_CHECK_GW_UPDATE = 250
LAN_GW_UPDATE = 251
LAN_SET_GW_CHANNEL = 252

   
def _generate_json_data(device_id: str, command_hs: str, data: dict):

    """
    Fill the data structure for the command with the given values
    """

    payload_dict = {        
    
        "07": {"devId": "", "uid": "", "t": ""}, 
        "08": {"gwId": "", "devId": ""},
        "09": {},
        "0A": {"gwId": "", "devId": "", "uid": "", "t": ""},  
        "0D": {"devId": "", "uid": "", "t": ""}, 
        "10": {"devId": "", "uid": "", "t": ""},          
    }

    json_data = payload_dict[command_hs]

    if 'gwId' in json_data:
        json_data['gwId'] = device_id
    if 'devId' in json_data:
        json_data['devId'] = device_id
    if 'uid' in json_data:
        json_data['uid'] = device_id  # still use id, no seperate uid
    if 't' in json_data:
        json_data['t'] = str(int(time.time()))

    if command_hs == '0D':
        json_data['dps'] = {"1": None, "2": None, "3": None}
    if data is not None:
        json_data['dps'] = data

    return json.dumps(json_data)  


def _generate_payload(device: dict, request_cnt: int, command: int, data: dict=None):
    """
    Generate the payload to send.

    Args:
        command(str): The type of command.
            This is one of the entries from payload_dict
        data(dict, optional): The data to be send.
            This is what will be passed via the 'dps' entry
    """

    request_cnt_hs = "{0:0{1}X}".format(request_cnt, 4)
    command_hs = "{0:0{1}X}".format(command,2)       
    
    payload_json = _generate_json_data(
        device['deviceid'], command_hs, data
    ).replace(' ', '').encode('utf-8')

    header_payload = b''
    if device['protocol'] == '3.1':
        
        if command == CONTROL:
            payload_json = aescipher.encrypt(device['localkey'], payload_json)
            preMd5String = b'data=' + payload_json + b'||lpv=' +  b'3.1||' + device['localkey']
            m = md5()
            m.update(preMd5String)
            hexdigest = m.hexdigest()
            payload_bytes = b'3.1' + hexdigest[8:][:16].encode('latin1') + payload_json

    elif device['protocol'] == '3.3':   

        if command != DP_QUERY:
            # add the 3.3 header
            header_payload = b'3.3' +  b"\0\0\0\0\0\0\0\0\0\0\0\0"

        payload_bytes = header_payload + aescipher.encrypt(device['localkey'], payload_json, False)
    else:
        return
    
        
    payload_hb = payload_bytes + hex2bytes("000000000000aa55")

    assert len(payload_hb) <= 0xff
    # TODO this assumes a single byte 0-255 (0x00-0xff)
    payload_hb_len_hs = '%x' % len(payload_hb)    
    
    header_hs = '000055aa' + request_cnt_hs +  '0000000000' + command_hs + '000000' + payload_hb_len_hs
    buffer = hex2bytes( header_hs ) + payload_hb

    # calc the CRC of everything except where the CRC goes and the suffix
    hex_crc = format(binascii.crc32(buffer[:-8]) & 0xffffffff, '08X')
    return buffer[:-8] + hex2bytes(hex_crc) + buffer[-4:]   


def _process_raw_reply(device: dict, raw_reply: bytes):       
   
    a = BitArray(raw_reply)    
    
    for s in a.split('0x000055aa', bytealigned=True):
        sbytes = s.tobytes()
        cmd = int.from_bytes(sbytes[11:12], byteorder='little')
        
        if cmd in [STATUS, DP_QUERY, DP_QUERY_NEW]:
            
            data = sbytes[20:8+int.from_bytes(sbytes[15:16], byteorder='little')]
            if cmd == STATUS:
                data = data[15:]
            yield aescipher.decrypt(device['localkey'], data, False)
    

def _select_reply(replies: list, reply:str = None):
    #TODO: use filter
    if not replies:
        return reply

    if replies[0] != 'json obj data unvalid':        
        return _select_reply(replies[1:], replies[0])
    return _select_reply(replies[1:], reply)


def _status(device: dict, cmd: int = DP_QUERY, expect_reply: int = 1, recurse_cnt: int = 0):    
    
    replies = list(reply for reply in send_request(device, cmd, None, expect_reply))  
        
    reply = _select_reply(replies)
    if reply == None and recurse_cnt < 5:    
        reply = _status(device, CONTROL_NEW, 2, recurse_cnt + 1)
    return reply


def status(device: dict):
    
    reply = _status(device)    
    if reply == None:
        return reply
    return json.loads(reply)


def set_status(device: dict, dps: int, value: bool):

    replies = list(reply for reply in send_request(device, CONTROL, {str(dps): value}, 2)) 
    
    reply = _select_reply(replies)
    if reply == None:
        return reply
    return json.loads(reply)

def _connect(device: dict, timeout:int = 5):

    connection = None

    try:
        connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        connection.settimeout(timeout)
        connection.connect((device['ip'], 6668))        
    except Exception as e:
        print('Failed to connect to %s. Retry in %d seconds' % (device['ip'], 1)) 
        connection = None    
        raise e   

    return connection  

def send_request(device, command: int = DP_QUERY, payload: dict = None, max_receive_cnt: int = 1, connection = None):
    
    if max_receive_cnt <= 0:
        return        

    
    if not connection:
        connection = _connect(device)           

    if command >= 0:        
        request = _generate_payload(device, 0, command, payload)
        try:
            connection.send(request)                  
        except Exception as e:
            raise e

    try:
        data = connection.recv(4096)  
            
        for reply in _process_raw_reply(device, data):            
            yield reply
    except socket.timeout as e:
        pass    
    except Exception as e:
        # print('Exception', device['ip'], e)   
        raise e    
    yield from send_request(device, -1, None, max_receive_cnt-1, connection)