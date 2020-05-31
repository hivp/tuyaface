<p align="center"><img widht="50%" alt="TuyaFace logo" src="https://github.com/TradeFace/tuyamqtt/blob/development/docs/tuyaface_logo.png?raw=true"></p>

Tuya client that allows you to locally communicate with tuya devices __without__ the tuya-cloud.

Installation
================
```
pip install tuyaface
```

Public Interface
==================

__Request current device status__
```
status(device: dict)
Returns dict
```

__Update device dps state__
```
set_state(device: dict, value, idx: int = 1)
Returns dict
```

__Update device status__
```
set_status(device: dict, dps: dict)
Returns dict
```

TuyaClient
----------

__Initialize client__
```
TuyaClient(device: dict, on_status: callable=None, on_connection: callable=None)

```

__Request current device status__
```
status()
Returns dict
```

__Update device dps state__
```
set_state(value, idx: int = 1)
Returns dict
```

__Close the connection and stop the worker thread__
```
stop_client()
```


_example_
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


Todo *v1.3.0*
==================
- validate/sanitize request
- throttle reconnect requests #48
- Pre-commit triggers (black, mypy, flake, etc) #54

Changelog
==================
*v1.2.0*
- WIP #44 sequence_nr
- WIP #44 connection
- Store preferred status command in device dict #43
- Nest tuyaface values in device: dict #44
- Improve message parsing #47

Earlier changes https://github.com/TradeFace/tuya/wiki

Implementations
================
- https://github.com/TradeFace/tuyamqtt
- _let me know, I'll add it here_

Acknowledgements
=================
- https://github.com/clach04/python-tuya formed the base for this lib
- https://github.com/codetheweb/tuyapi as reference on commands 
- https://github.com/SDNick484 for testing protocol 3.1 reimplementation
- https://github.com/jkerdreux-imt several improvements
- https://github.com/PortableProgrammer help on #20
- https://github.com/emontnemery tuyaclient 