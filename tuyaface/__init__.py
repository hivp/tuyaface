import time
import socket
import json
from bitstring import BitArray
import binascii
from hashlib import md5
import logging

from tuyaface import aescipher
from tuyaface import const as tf
from tuyaface.helper import *

logger = logging.getLogger(__name__)

   
def _generate_json_data(device_id: str, command: int, data: dict):

    """
    Fill the data structure for the command with the given values
    return: json str
    """

    payload_dict = {        
    
        tf.CONTROL: {"devId": "", "uid": "", "t": ""}, 
        tf.STATUS: {"gwId": "", "devId": ""},
        tf.HEART_BEAT: {},
        tf.DP_QUERY: {"gwId": "", "devId": "", "uid": "", "t": ""},  
        tf.CONTROL_NEW: {"devId": "", "uid": "", "t": ""}, 
        tf.DP_QUERY_NEW: {"devId": "", "uid": "", "t": ""},          
    }

    json_data = {}
    if command in payload_dict:
        json_data = payload_dict[command]

    if 'gwId' in json_data:
        json_data['gwId'] = device_id
    if 'devId' in json_data:
        json_data['devId'] = device_id
    if 'uid' in json_data:
        json_data['uid'] = device_id  # still use id, no seperate uid
    if 't' in json_data:
        json_data['t'] = str(int(time.time()))

    if command == tf.CONTROL_NEW:
        json_data['dps'] = {"1": None, "2": None, "3": None}
    if data is not None:
        json_data['dps'] = data

    return json.dumps(json_data)  


def _generate_payload(device: dict, request_cnt: int, command: int, data: dict=None):
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

    #TODO: don't overwrite variables
    payload_json = _generate_json_data(
        device['deviceid'], 
        command, 
        data
    ).replace(' ', '').encode('utf-8')
    
    header_payload_hb = b''
    payload_hb = payload_json

    if device['protocol'] == '3.1':
        
        if command == tf.CONTROL:
            payload_crypt = aescipher.encrypt(device['localkey'], payload_json)
            preMd5String = b'data=' + payload_crypt + b'||lpv=' +  b'3.1||' + device['localkey']
            m = md5()
            m.update(preMd5String)
            hexdigest = m.hexdigest()

            header_payload_hb = b'3.1' + hexdigest[8:][:16].encode('latin1')
            payload_hb =  header_payload_hb + payload_crypt

    elif device['protocol'] == '3.3':   
        
        if command != tf.DP_QUERY:
            # add the 3.3 header
            header_payload_hb = b'3.3' +  b"\0\0\0\0\0\0\0\0\0\0\0\0"

        payload_crypt = aescipher.encrypt(device['localkey'], payload_json, False)
        payload_hb = header_payload_hb + payload_crypt
    else:                 
        raise Exception('Unknown protocol %s.' % (device['protocol']))            

    return _stitch_payload(payload_hb, request_cnt, command)

    
def _stitch_payload(payload_hb: bytes, request_cnt: int, command: int):    
    """
    Joins the payload request parts together
    """

    command_hs = "{0:0{1}X}".format(command, 2)
    request_cnt_hs = "{0:0{1}X}".format(request_cnt, 4)    

    payload_hb = payload_hb + hex2bytes("000000000000aa55")

    assert len(payload_hb) <= 0xff
    # TODO this assumes a single byte 0-255 (0x00-0xff)
    payload_hb_len_hs = '%x' % len(payload_hb)    
    
    header_hb = hex2bytes('000055aa' + request_cnt_hs +  '0000000000' + command_hs + '000000' + payload_hb_len_hs)
    buffer_hb = header_hb + payload_hb

    # calc the CRC of everything except where the CRC goes and the suffix
    hex_crc = format(binascii.crc32(buffer_hb[:-8]) & 0xffffffff, '08X')
    return buffer_hb[:-8] + hex2bytes(hex_crc) + buffer_hb[-4:]   


def _process_raw_reply(device: dict, raw_reply: bytes):          
    """
    Splits the raw reply(s) into chuncks and decrypts it.
    returns json str or str (error)
    """

    a = BitArray(raw_reply)  

    #TODO: don't overwrite variables
    for s in a.split('0x000055aa', bytealigned=True):
        sbytes = s.tobytes()
        cmd = int.from_bytes(sbytes[11:12], byteorder='big')
        
        if device['protocol'] == '3.1':
            
            data = sbytes[20:-8]
            if sbytes[20:21] == b'{':   

                if not isinstance(data, str):
                    data = data.decode()
                yield data

            elif sbytes[20:23] == b'3.1':

                logger.info('we\'ve got a 3.1 reply, code untested')                   
                data = data[3:]  # remove version header
                data = data[16:]  # remove (what I'm guessing, but not confirmed is) 16-bytes of MD5 hexdigest of payload
                yield aescipher.decrypt(device['localkey'], data)

        elif device['protocol'] == '3.3':

            if cmd in [tf.STATUS, tf.DP_QUERY, tf.DP_QUERY_NEW]:
                
                data = sbytes[20:8+int.from_bytes(sbytes[14:16], byteorder='big')]
                if cmd == tf.STATUS:
                    data = data[15:]
                yield aescipher.decrypt(device['localkey'], data, False)
    

def _select_reply(replies: list):
    """
    Find the first valid reply
    returns json str
    """

    filtered_replies = list(filter(lambda x: x != 'json obj data unvalid', replies))
    if len(filtered_replies) == 0:        
        return '{}'
    return filtered_replies[0]


def _status(device: dict, cmd: int = tf.DP_QUERY, expect_reply: int = 1, recurse_cnt: int = 0):    
    """
    Sends current status request to the tuya device
    returns json str
    """

    replies = list(reply for reply in send_request(device, cmd, None, expect_reply)) 

    reply = _select_reply(replies)   
    if not reply and recurse_cnt < 3:
        # some devices (ie LSC Bulbs) only offer partial status with CONTROL_NEW instead of DP_QUERY
        reply = _status(device, tf.CONTROL_NEW, 2, recurse_cnt + 1)    
    return reply


def status(device: dict):
    """
    Requests status of the tuya device
    returns dict
    """

    #TODO: validate/sanitize request
    reply = _status(device)
    logger.debug("reply: %s", reply) 
    return json.loads(reply)


def set_status(device: dict, dps: dict):
    """
    Sends status update request to the tuya device
    returns dict
    """

    #TODO: validate/sanitize request
    tmp = { str(k):v for k,v in dps.items() }
    replies = list(reply for reply in send_request(device, tf.CONTROL, tmp, 2)) 
    
    reply = _select_reply(replies)
    logger.debug("reply: %s", reply)       
    return json.loads(reply)


def set_state(device: dict, value: bool, idx: int = 1):
    """
    Sends status update request for one dps value to the tuya device
    returns dict
    """

    # turn a device on / off
    return set_status(device,{idx: value})


def _connect(device: dict, timeout:int = 2):

    """
    connects to the tuya device
    returns connection object
    """

    connection = None

    logger.info('Connecting to %s' % device['ip'])
    try:
        connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        connection.settimeout(timeout)
        connection.connect((device['ip'], 6668)) 
        return connection       
    except Exception as e:
        logger.warning('Failed to connect to %s. Retry in %d seconds' % (device['ip'], 1))         
        raise e       


def send_request(device: dict, command: int = tf.DP_QUERY, payload: dict = None, max_receive_cnt: int = 1, connection = None):
    """
    Connects to the tuya device and sends the request
    returns json str or str (error)
    """

    if max_receive_cnt <= 0:
        return        

    if not connection:
        connection = _connect(device)           

    if command >= 0: 
        try:   
            #TODO: solve sequence number always 0; doesn't seem to be a problem at the moment  
            request = _generate_payload(device, 0, command, payload)
        except Exception as e:
            logger.warning(e)
            raise e
        
        logger.debug("sending command: [%s] payload: [%s]" % (command,payload))
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
        raise e    
    yield from send_request(device, -1, None, max_receive_cnt-1, connection)
