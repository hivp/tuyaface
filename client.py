
import time
import socket
import json
from bitstring import BitArray
import binascii

from tuya.aescipher import AESCipher
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
   
def _generate_json_data(device_id: str, commandByte: str, data: dict):

    payload_dict = {        
    
        "07": {"devId": "", "uid": "", "t": ""}, 
        "08": {"gwId": "", "devId": ""},
        "09": {},
        "0A": {"gwId": "", "devId": "", "uid": "", "t": ""},  
        "0D": {"devId": "", "uid": "", "t": ""}, 
        "10": {"devId": "", "uid": "", "t": ""},          
    }

    json_data = payload_dict[commandByte]

    if 'gwId' in json_data:
        json_data['gwId'] = device_id
    if 'devId' in json_data:
        json_data['devId'] = device_id
    if 'uid' in json_data:
        json_data['uid'] = device_id  # still use id, no seperate uid
    if 't' in json_data:
        json_data['t'] = str(int(time.time()))

    if commandByte == '0D':
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
        commandByte = bin2hex(command.to_bytes(1, byteorder='big'))
        
        json_payload = _generate_json_data(device['id'], commandByte, data)
        json_payload = json_payload.replace(' ', '')
        json_payload = json_payload.encode('utf-8')


        if device['protocol'] == '3.3':
            # expect to connect and then disconnect to set new
            cipher = AESCipher(_encode_localkey(device['localkey']))
            json_payload = cipher.encrypt(json_payload, False)
            cipher = None
            if command != DP_QUERY:
                # add the 3.3 header
                json_payload = b'3.3' + \
                    b"\0\0\0\0\0\0\0\0\0\0\0\0" + json_payload   

        postfix_payload = hex2bin(bin2hex(json_payload) + "000000000000aa55")

        assert len(postfix_payload) <= 0xff
        # TODO this assumes a single byte 0-255 (0x00-0xff)
        postfix_payload_hex_len = '%x' % len(postfix_payload)    
        
        
        buffer = hex2bin( '000055aa' + 
                        bin2hex(request_cnt.to_bytes(2, byteorder='big')) + 
                        '0000000000' + commandByte + '000000' +
                        postfix_payload_hex_len) + postfix_payload

        # calc the CRC of everything except where the CRC goes and the suffix
        hex_crc = format(binascii.crc32(buffer[:-8]) & 0xffffffff, '08X')
        return buffer[:-8] + hex2bin(hex_crc) + buffer[-4:]   


def _encode_localkey(localkey: str):

    return localkey.encode('latin1')


def _process_raw_reply(device: dict, raw_reply: bytes):       
   
    a = BitArray(raw_reply)       
 
    localkey = _encode_localkey(device['localkey'])
    
    for s in a.split('0x55aa', bytealigned=True):
        sbytes = s.tobytes()
        
        if sbytes[:2] == b'\x55\xaa':
            # count = int.from_bytes(sbytes[3:4], byteorder='little')
            cmd = int.from_bytes(sbytes[9:10], byteorder='little')
            
            if cmd in [STATUS, DP_QUERY, DP_QUERY_NEW]:
                cipher = AESCipher(localkey)      
                data = sbytes[18:6+int.from_bytes(sbytes[13:14], byteorder='little')]
                if cmd == STATUS:
                    data = data[15:]
                yield cipher.decrypt(data, False)
    

def _select_reply(replies: list, reply:str = None):

    if not replies:
        return reply

    if replies[0] != 'json obj data unvalid':        
        return _select_reply(replies[1:], replies[0])
    return _select_reply(replies[1:], reply)


def _status(tuyaconnection, device: dict, cmd: int = DP_QUERY, expect_reply: int = 1, recurse_cnt: int = 0):    
    
    replies = list(reply for reply in tuyaconnection.send_request(cmd, None, expect_reply))  
        
    reply = _select_reply(replies)
    # print(device['ip'],reply,replies )
    if reply == None and recurse_cnt < 5:
        recurse_cnt += 1
        reply = _status(tuyaconnection, device, CONTROL_NEW, 2, recurse_cnt)
    return reply


def status(tuyaconnection, device: dict):
    
    reply = _status(tuyaconnection, device)    
    if reply == None:
        return reply
    return json.loads(reply)


def set_status(tuyaconnection, device: dict, dps: int, value: bool):

    replies = list(reply for reply in tuyaconnection.send_request(CONTROL, {str(dps): value}, 2)) 
    
    reply = _select_reply(replies)
    if reply == None:
        return reply
    return json.loads(reply)


#TuyaConnection
def printstats(device: dict, stats: dict, connected: bool):
       
        print("host %s connected %s, resets %d, refused %d, brokenpipe %d, os %d, failed %d, receive %d, time delta %f" %(
            device['ip'],
            connected,  
            stats['connection_reset_error_cnt'],      
            stats['connection_refused_error_cnt'], 
            stats['connection_brokenpipe_error_cnt'], 
            stats['connection_os_error_cnt'], 
            stats['connection_failed_cnt'],
            stats['receive_cnt'],
            time.time()-stats['connection_time']
        ))


class TuyaConnection:

    def __init__(self, device: dict):

        self.device = device        
        self.connected = False
        self.connection_timeout = 5
        self.stats = {
            'receive_cnt': 0,
            'request_cnt': 0,
            'connection_reset_error_cnt': 0,    
            'connection_failed_cnt': 0,
            'connection_refused_error_cnt': 0, 
            'connection_brokenpipe_error_cnt': 0, 
            'connection_os_error_cnt': 0,      
            'connection_time': time.time()
        }

    def _disconnect(self):

        """ close the connection """
        if self.s != None:
            try:
                # self.s.shutdown(socket.SHUT_RDWR)
                self.s.close()
            except Exception as e:
                pass
        self.s = None
        self.connected = False

    def _connect(self, device: dict):

        try:
            self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            self.s.settimeout(self.connection_timeout)

            self.s.connect((device['ip'], 6668))
            self.connected = True          
            self.stats['connection_refused_error_cnt'] = 0 
            self.stats['connection_brokenpipe_error_cnt'] = 0 
            self.stats['connection_os_error_cnt'] = 0 
            self.stats['receive_cnt'] = 0
            self.stats['request_cnt'] = 0
            self.stats['connection_time'] = time.time()
        except Exception as e:
            self.connected = False
            self.stats['connection_failed_cnt'] += 1
            sleep = self.stats['connection_failed_cnt']*15
            if sleep > 300:
                sleep = 300
            print('Failed to connect to %s. Retry in %d seconds' % (device['ip'], sleep))
            time.sleep(sleep)    
    

    def send_request(self, command: int=DP_QUERY, payload: dict = None, max_receive_cnt: int = 1):

        self.stats['request_cnt'] += 1
        device = self.device
        request = _generate_payload(device, self.stats['request_cnt'], command, payload)

        self.stats['receive_cnt'] = 0
        request_sent = False
      
        ipaddress = device['ip']

        while self.stats['receive_cnt'] < max_receive_cnt:
            if not self.connected:
                self._connect(device)
                continue
       
            if request_sent == False:
                try:
                    self.s.send(request)
                    request_sent = True
                except Exception as e:
                    break
          
            try:
                self.stats['receive_cnt'] += 1   
                data = self.s.recv(4096) 
                for reply in _process_raw_reply(device, data):
                    yield reply

            except socket.timeout as e:
                pass
            except (ConnectionResetError) as e:
                print('ConnectionResetError', ipaddress, e)
                self.connected = False
                self.stats['connection_reset_error_cnt'] += 1    
                self._disconnect()   
                self._connect(device)   
            except (ConnectionRefusedError) as e:
                print('ConnectionRefusedError', ipaddress, e)
                self.connected = False
                self.stats['connection_refused_error_cnt'] += 1
            except (BrokenPipeError) as e:
                print('BrokenPipeError', ipaddress, e)
                self.connected = False
                self.stats['connection_brokenpipe_error_cnt'] += 1
            except ( OSError) as e:
                print('OSError', ipaddress, e)
                self.connected = False
                self.stats['connection_os_error_cnt'] += 1
                self._disconnect()
                self._connect(device)
            # except SocketError as e:
            #     print('SocketError',ipaddress, e)
            except Exception as e:
                print('Exception', ipaddress, e)

            if self.stats['connection_reset_error_cnt'] > 20 or \
                self.stats['connection_refused_error_cnt'] > 20 or \
                self.stats['connection_brokenpipe_error_cnt'] > 20 or \
                self.stats['connection_os_error_cnt'] > 20:
                self._disconnect()
                print('Too many errors, break', ipaddress)
                break
       
            time.sleep(0.1)
    