
import inspect
import time
import socket
import json
from bitstring import BitArray
import binascii

from tuya.aescipher import AESCipher
from tuya.helper import *

   
def _generate_json_data(device_id: str, commandByte: str, data: dict):

    payload_dict = {        
    
        "07": {"devId": "", "uid": "", "t": ""}, 
        "08": {"gwId": "", "devId": ""},
        "09": {},
        "0a": {"gwId": "", "devId": "", "uid": "", "t": ""},  
        "0d": {"devId": "", "uid": "", "t": ""}, 
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

    if commandByte == '0d':
        json_data['dps'] = {"1": None, "2": None, "3": None}
    if data is not None:
        json_data['dps'] = data

    return json.dumps(json_data)  

def _generate_payload(device: dict, request_cnt: int, commandByte: str, data: dict=None):
        """
        Generate the payload to send.

        Args:
            command(str): The type of command.
                This is one of the entries from payload_dict
            data(dict, optional): The data to be send.
                This is what will be passed via the 'dps' entry
        """
        json_payload = _generate_json_data(device['id'], commandByte, data)

        json_payload = json_payload.replace(' ', '')
        json_payload = json_payload.encode('utf-8')


        if device['protocol'] == '3.3':
            # expect to connect and then disconnect to set new
            cipher = AESCipher(_encode_localkey(device['localkey']))
            json_payload = cipher.encrypt(json_payload, False)
            cipher = None
            if commandByte != '0a':
                # add the 3.3 header
                json_payload = b'3.3' + \
                    b"\0\0\0\0\0\0\0\0\0\0\0\0" + json_payload   

        postfix_payload = hex2bin(
            bin2hex(json_payload) + "000000000000aa55")

        assert len(postfix_payload) <= 0xff
        # TODO this assumes a single byte 0-255 (0x00-0xff)
        postfix_payload_hex_len = '%x' % len(postfix_payload)    
        
        
        buffer = hex2bin( '000055aa' + 
                        bin2hex(request_cnt.to_bytes(2, byteorder='big')) + 
                        '0000000000' +
                        commandByte +
                        '000000' +
                        postfix_payload_hex_len) + postfix_payload

        # calc the CRC of everything except where the CRC goes and the suffix
        hex_crc = format(binascii.crc32(buffer[:-8]) & 0xffffffff, '08X')
        buffer = buffer[:-8] + hex2bin(hex_crc) + buffer[-4:]
        
        return buffer

def _encode_localkey(localkey: str):

    return localkey.encode('latin1')


def on_connect():

    pass


def _process_contole_result(localkey: str, data: bytes):  # 07 / 7

    pass


def _process_status_result(localkey: str, data: bytes):  # 08 / 8

    cipher = AESCipher(localkey)
    result = cipher.decrypt(data[15:], False)
    return result


def _process_heartbeat_result(localkey: str, data: bytes):  # 09 / 9

    pass


def _process_query_result(localkey: str,  data: bytes):  # 0a / 10
    
    cipher = AESCipher(localkey)
    result = cipher.decrypt(data, False)
    return result


def _process_contole_new_result(localkey: str, data: bytes):  # 0d / 13

    pass


def _process_query_new_result(localkey: str, data: bytes):  # 10 / 16

    cipher = AESCipher(localkey)
    result = cipher.decrypt(data, False)
    return result

def _process_raw_reply(device: dict, raw_reply: bytes):
       
    a = BitArray(raw_reply)   
    processed_replies = []     
    localkey = _encode_localkey(device['localkey'])
    
    for s in a.split('0x55aa', bytealigned=True):
        sbytes = s.tobytes()
        
        if sbytes[:2] == b'\x55\xaa':
            count = int.from_bytes(sbytes[3:4], byteorder='little')
            cmd = int.from_bytes(sbytes[9:10], byteorder='little')
            lendata = int.from_bytes(sbytes[13:14], byteorder='little')
            dataend = 14+(lendata-8)
            data = sbytes[18:dataend]
            if cmd == 7:
                _process_contole_result(localkey, data)
            elif cmd == 8:
                processed_replies.append(_process_status_result(localkey, data))
            elif cmd == 9:
                _process_heartbeat_result(localkey, data)
            elif cmd == 10:
                processed_replies.append(_process_query_result(localkey, data))
            elif cmd == 13:
                _process_contole_new_result(localkey, data)
            elif cmd == 16:
                processed_replies.append(_process_query_new_result(localkey, data))
    
    return processed_replies


def _process_raw_replies(device: dict, raw_replies: list):

    replies = []
    for raw_reply in raw_replies:
        for processed_reply in _process_raw_reply(device, raw_reply):
            replies.append(processed_reply)        

    return replies


def _select_reply(replies: list):

    for reply in replies:
        if reply != 'json obj data unvalid':
            return reply 
    return None


def _status(tuyaconnection, device: dict, cmd: str = '0a', expect_reply: int = 1, recurse_cnt: int = 0):    
        
    reply = _select_reply(
        _process_raw_replies(
            device, 
            tuyaconnection.send_request(
                cmd, 
                None,
                expect_reply
            )
        )
    )

    if reply == None and recurse_cnt < 5:
        recurse_cnt += 1
        reply = _status(tuyaconnection, device, '0d', 2, recurse_cnt)
    return reply


def status(tuyaconnection, device: dict):

    reply = _status(tuyaconnection, device)
    
    if reply == None:
        return reply
    return json.loads(reply)


def set_status(tuyaconnection, device: dict, dps: int, value: bool):

    reply = _select_reply(
        _process_raw_replies(
            device, 
            tuyaconnection.send_request(
                '07', 
                {str(dps): value}, 
                2
            )
        )
    )

    if reply == None:
        return reply
    return json.loads(reply)

#TuyaConnection
def printstats(self, device: dict, stats: dict, connected: bool):
       
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
            'connection_failed_cnt': 0,       
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

   
    def send_request(self, commandByte: str='0a', payload: dict = None, max_receive_cnt: int = 1):

        self.stats['request_cnt'] += 1
        device = self.device
        request = _generate_payload(device, self.stats['request_cnt'], commandByte, payload)

        self.stats['receive_cnt'] = 0
        request_sent = False
        raw_replies = []
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
                    return raw_replies
          
            try:
                self.stats['receive_cnt'] += 1   
                data = self.s.recv(4096) 
                raw_replies.append(data)

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
                return raw_replies
       
            time.sleep(0.1)
        return raw_replies
