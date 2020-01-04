
import inspect
import time
import socket
import json
from bitstring import BitArray
import binascii

from tuya.aescipher import AESCipher
from tuya.helper import *

class Client:

    port = 6668

    payload_dict = {        
        
        "07": {"devId": "", "uid": "", "t": ""}, 
        "08": {"gwId": "", "devId": ""},
        "09": {},
        "0a": {"gwId": "", "devId": "", "uid": "", "t": ""},  
        "0d": {"devId": "", "uid": "", "t": ""}, 
        "10": {"devId": "", "uid": "", "t": ""},          
    }

    def __init__(self):
        self.version = '3.3'
        self.ipaddress = ''
 
        self.replies = []
        self.request_cnt = 0
        self.receive_cnt = 0
        self.device_id = None
        self.localkey = None
      
        self.connected = False
        self.connection_timeout = 5
        self.connection_reset_error_cnt = 0    
        self.connection_reset = 20
        self.connection_refused_error_cnt = 0 
        self.connection_brokenpipe_error_cnt = 0 
        self.connection_os_error_cnt = 0 
        self.connection_failed_cnt = 0       
        self.connection_time = time.time()
           

    def _disconnect(self):

        """ close the connection """
        if self.s != None:
            try:
                # self.s.shutdown(socket.SHUT_RDWR)
                self.s.close()
            except Exception as e:
                print('hier ?', e)
        self.s = None
        self.connected = False

    
    def _connect(self):

        # self.printstats()
       
        try:
            self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            self.s.settimeout(self.connection_timeout)

            self.s.connect((self.ipaddress, self.port))
            self.connected = True          
            self.connection_refused_error_cnt = 0 
            self.connection_brokenpipe_error_cnt = 0 
            self.connection_os_error_cnt = 0 
            self.receive_cnt = 0
            self.connection_time = time.time()
        except Exception as e:
            self.connected = False
            self.connection_failed_cnt += 1
            sleep = self.connection_failed_cnt*15
            if sleep > 300:
                sleep = 300
            print('Failed to connect to %s. Retry in %d seconds' % (self.ipaddress, sleep))
            time.sleep(sleep)  


    def printstats(self):
       
        print("host %s connected %s, resets %d, refused %d, brokenpipe %d, os %d, failed %d, receive %d, time delta %f" %(
            self.ipaddress,
            self.connected,  
            self.connection_reset_error_cnt,      
            self.connection_refused_error_cnt, 
            self.connection_brokenpipe_error_cnt, 
            self.connection_os_error_cnt, 
            self.connection_failed_cnt,
            self.receive_cnt,
            time.time()-self.connection_time
        ))


    def run(self, request, receive_cnt):

        self.receive_cnt = 0
        request_send = False
        while True:
            if not self.connected:
                self._connect()
                continue
       
            if request_send == False:
                try:
                    self.s.send(request)
                    request_send = True
                except Exception as e:
                    print(self.ipaddress,'hierdan', e)
                    return
          
            try:
                self.receive_cnt += 1   
                data = self.s.recv(4096) 
                self.on_message(data)                   

            except socket.timeout as e:
                pass
            except (ConnectionResetError) as e:
                print('ConnectionResetError',self.ipaddress, e)
                self.connected = False
                self.connection_reset_error_cnt += 1       
                self._connect()   
            except (ConnectionRefusedError) as e:
                print('ConnectionRefusedError',self.ipaddress, e)
                self.connected = False
                self.connection_refused_error_cnt += 1
            except (BrokenPipeError) as e:
                print('BrokenPipeError',self.ipaddress, e)
                self.connected = False
                self.connection_brokenpipe_error_cnt += 1
            except ( OSError) as e:
                print('OSError',self.ipaddress, e)
                self.connected = False
                self.connection_os_error_cnt += 1
                self._disconnect()
                self._connect()
            # except SocketError as e:
            #     print('SocketError',self.ipaddress, e)
            except Exception as e:
                print('Exception',self.ipaddress, e)
            
            if self.receive_cnt >= receive_cnt:
                return

            time.sleep(0.1)


    def connect(self, ipaddress, device_id = None, localkey = None):

        self.ipaddress = ipaddress
        if device_id != None:
            self.device_id = device_id

        if localkey != None:
            self.localkey = localkey.encode('latin1')


    def set_version(self, version):

        self.version = version      
    
   
    def generate_json_data(self, commandByte, data):

        json_data = self.payload_dict[commandByte]

        if 'gwId' in json_data:
            json_data['gwId'] = self.device_id
        if 'devId' in json_data:
            json_data['devId'] = self.device_id
        if 'uid' in json_data:
            json_data['uid'] = self.device_id  # still use id, no seperate uid
        if 't' in json_data:
            json_data['t'] = str(int(time.time()))

        if commandByte == '0d':
            json_data['dps'] = {"1": None, "2": None, "3": None}
        if data is not None:
            json_data['dps'] = data

        json_payload = json.dumps(json_data)  
        return json_payload


    def generate_payload(self, commandByte, data=None, protocol=False):
        """
        Generate the payload to send.

        Args:
            command(str): The type of command.
                This is one of the entries from payload_dict
            data(dict, optional): The data to be send.
                This is what will be passed via the 'dps' entry
        """
        json_payload = self.generate_json_data(commandByte, data)

        json_payload = json_payload.replace(' ', '')
        json_payload = json_payload.encode('utf-8')


        if self.version == 3.3:
            # expect to connect and then disconnect to set new
            self.cipher = AESCipher(self.localkey)
            json_payload = self.cipher.encrypt(json_payload, False)
            self.cipher = None
            if commandByte != '0a':
                # add the 3.3 header
                json_payload = b'3.3' + \
                    b"\0\0\0\0\0\0\0\0\0\0\0\0" + json_payload   

        postfix_payload = hex2bin(
            bin2hex(json_payload) + "000000000000aa55")

        assert len(postfix_payload) <= 0xff
        # TODO this assumes a single byte 0-255 (0x00-0xff)
        postfix_payload_hex_len = '%x' % len(postfix_payload)
     
        self.request_cnt += 1
        if self.request_cnt > 255:
            self.request_cnt = 0


        buffer = hex2bin( '000055aa' + 
                        bin2hex(self.request_cnt.to_bytes(2, byteorder='big')) + 
                        '0000000000' +
                        commandByte +
                        '000000' +
                        postfix_payload_hex_len) + postfix_payload

        # calc the CRC of everything except where the CRC goes and the suffix
        hex_crc = format(binascii.crc32(buffer[:-8]) & 0xffffffff, '08X')
        buffer = buffer[:-8] + hex2bin(hex_crc) + buffer[-4:]
        return buffer


    def _select_reply(self):

        for reply in self.replies:
            if reply != 'json obj data unvalid':
                return reply 
        return None


    def _status(self, cmd = '0a', count = 1):
      
        payload = self.generate_payload(cmd) 
        self.replies = []
        self.run(payload, count)      
        
        reply = self._select_reply()
        if reply == None:
            reply = self._status('0d', 2)
        return reply


    def status(self):

        return json.loads(self._status())


    def set_status(self, dps, payloads):

        payload = self.generate_payload('07', {str(dps): payloads}) 
        count = 2
        self.replies = []
        self.run(payload, count)

        reply = self._select_reply()
        if reply == None:
            return reply
        return json.loads(reply)


    def on_connect(self):
        pass


    def _process_contole_result(self, data):  # 07 / 7
        pass


    def _process_status_result(self, data):  # 08 / 8
        cipher = AESCipher(self.localkey)
        result = cipher.decrypt(data[15:], False)
        return result


    def _process_heartbeat_result(self, data):  # 09 / 9
        self.heartbeat_received = True


    def _process_query_result(self, data):  # 0a / 10
        
        cipher = AESCipher(self.localkey)
        result = cipher.decrypt(data, False)
        return result


    def _process_contole_new_result(self, data):  # 0d / 13
        pass


    def _process_query_new_result(self, data):  # 10 / 16

        cipher = AESCipher(self.localkey)
        result = cipher.decrypt(data, False)
        return result


    def on_message(self, reply):

        a = BitArray(reply)
        count = 0
        
        for s in a.split('0x55aa', bytealigned=True):
            sbytes = s.tobytes()
            if sbytes[:2] == b'\x55\xaa':
                count = int.from_bytes(sbytes[3:4], byteorder='little')
                cmd = int.from_bytes(sbytes[9:10], byteorder='little')
                lendata = int.from_bytes(sbytes[13:14], byteorder='little')
                dataend = 14+(lendata-8)
                data = sbytes[18:dataend]
                if cmd == 7:
                    self._process_contole_result(data)
                elif cmd == 8:
                    self.replies.append(self._process_status_result(data))
                elif cmd == 9:
                    self._process_heartbeat_result(data)
                elif cmd == 10:
                    self.replies.append(self._process_query_result(data))
                elif cmd == 13:
                    self._process_contole_new_result(data)
                elif cmd == 16:
                    self.replies.append(self._process_query_new_result(data))
        return count
   

   