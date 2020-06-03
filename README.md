<p align="center"><img width="50%" alt="TuyaFace logo" src="https://github.com/TradeFace/tuyamqtt/blob/development/docs/tuyaface_logo.png?raw=true"></p>

Tuya client that allows you to locally communicate with tuya devices __without__ the tuya-cloud.

Installation
================
```
pip install tuyaface
```



    
# Module `tuyaface` {#tuyaface}

Functionality for communicating with a Tuya device.


    
## Sub-modules

* [tuyaface.aescipher](#tuyaface.aescipher)
* [tuyaface.const](#tuyaface.const)
* [tuyaface.helper](#tuyaface.helper)
* [tuyaface.tuyaclient](#tuyaface.tuyaclient)



    
## Functions


    
### Function `set_state` {#tuyaface.set_state}



    
> `def set_state(device: dict, value, idx: int = 1)`


Send status update request for one dps value to the tuya device.

returns bool

    
### Function `set_status` {#tuyaface.set_status}



    
> `def set_status(device: dict, dps: dict)`


Send state update request to the tuya device and waits for response.

returns bool

    
### Function `status` {#tuyaface.status}



    
> `def status(device: dict)`


Request status of the tuya device.

returns dict




    
# Module `tuyaface.aescipher` {#tuyaface.aescipher}

Helpers for AES crypto.




    
## Functions


    
### Function `decrypt` {#tuyaface.aescipher.decrypt}



    
> `def decrypt(key, enc, use_base64=True)`


Optionally base64-decode and decrypt.

    
### Function `encrypt` {#tuyaface.aescipher.encrypt}



    
> `def encrypt(key, raw, use_base64=True)`


Encrypt and optionally base64-encode.




    
# Module `tuyaface.const` {#tuyaface.const}

Tuya constants.







    
# Module `tuyaface.helper` {#tuyaface.helper}

Helpers.




    
## Functions


    
### Function `bytes2hex` {#tuyaface.helper.bytes2hex}



    
> `def bytes2hex(data: bytes, pretty: bool = False)`


Render hexstring from bytes.

    
### Function `hex2bytes` {#tuyaface.helper.hex2bytes}



    
> `def hex2bytes(data: str)`


Parse hexstring to bytes.




    
# Module `tuyaface.tuyaclient` {#tuyaface.tuyaclient}

Helper to maintain a connection to and serialize access to a Tuya device.





    
## Classes


    
### Class `TuyaClient` {#tuyaface.tuyaclient.TuyaClient}



> `class TuyaClient(device: dict, on_status: <built-in function callable> = None, on_connection: <built-in function callable> = None)`


Helper class to maintain a connection to and serialize access to a Tuya device.

Initialize the Tuya client.


    
#### Ancestors (in MRO)

* [threading.Thread](#threading.Thread)






    
#### Methods


    
##### Method `run` {#tuyaface.tuyaclient.TuyaClient.run}



    
> `def run(self)`


Tuya client main loop.

    
##### Method `set_state` {#tuyaface.tuyaclient.TuyaClient.set_state}



    
> `def set_state(self, value, idx: int = 1)`


Set state.

    
##### Method `status` {#tuyaface.tuyaclient.TuyaClient.status}



    
> `def status(self)`


Request status.

    
##### Method `stop_client` {#tuyaface.tuyaclient.TuyaClient.stop_client}



    
> `def stop_client(self)`


Close the connection and stop the worker thread.


_example_
--------
```
from tuyaface.tuyaclient import TuyaClient

def on_status(data: dict):
    print(data)

def on_connection(value: bool):
    print(value)

device = {
    'protocol': '3.3', # 3.1 | 3.3
    'deviceid': '34280100600194d17c96',
    'localkey': 'e7e9339aa82abe61',
    'ip': '192.168.1.101',            
}

client = TuyaClient(device, on_status, on_connection)
client.start()

data = client.status()
client.set_state(!data['dps']['1'], 1) #toggle
client.stop_client()

```


Data structure
==================
__Device dict__
```
device = {
    'protocol': '3.3', # 3.1 | 3.3
    'deviceid': '34280100600194d17c96',
    'localkey': 'e7e9339aa82abe61',
    'ip': '192.168.1.101',
    'pref_status_cmd': 10 #optional, default 10
}
```
TuyaFace will automatically add `tuyaface` dict to the device with data to support implementations without the TuyaClient class. 
```
tuyaface = {
    "sequence_nr": 0, # Request counter
    "connection": None, # Holds the connection 
    "availability": False, # If the device could be reached
    "pref_status_cmd": 10, # Preferred status command 
    "status": None, # Reply to the last status request
}
```

__DPS dict__
```
dps = {
    '1': True,
    '2': False,
    '101': 255,
    '102': 128,
    ...etc...
}
```

Improvements
==============
Do you have ideas how we can make this package even better? Or would you like to contribute in another way? Drop a line in the issue section, all help is welcome.

Acknowledgements
=================
- https://github.com/emontnemery tuyaclient and much more
- https://github.com/jkerdreux-imt several improvements
- https://github.com/SDNick484 for testing protocol 3.1 reimplementation
- https://github.com/PortableProgrammer help on #20
- https://github.com/clach04/python-tuya formed the base for this lib
- https://github.com/codetheweb/tuyapi as reference on commands 

Implementations
================
- https://github.com/TradeFace/tuyamqtt
- _let me know, I'll add it here_
