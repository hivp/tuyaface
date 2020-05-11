TuyaFace
===================

Tuya client that allows you to locally communicate with tuya devices __without__ the tuya-cloud.

Installation
================
```
pip install tuyaface
```

Public Interface
==================

__Request device status__
```
status(device: dict)
Returns json string
```

__Change device state__
```
set_state(device: dict, value: bool, idx: int = 1)
Returns json string
```

__Change device status__
```
set_status(device: dict, dps: dict)
Returns json string
```

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
    '1': 0,
    '103' 255,
    ...etc...
}
```


Todo
==================


Changelog
==================
*v1.1.6*
- removed pyaes
- revert #20

*v1.1.5*
- fix #24
- additional condition on #20
- use const in _generate_json_data 

*v1.1.4*
- _select_reply use filter correction

*v1.1.3*
- _select_reply use filter (fix #20?)
- added check for empty string replies 
- corrected setup.py

*v1.1.2*
- moved constants to separate file
- _stitch_payload type casting

*v1.1.1*
- better description pub interface
- replaced pycrypto with pycryptodome

*v1.1.0* Breaking
- function set_status was added
- functionname set_status was changed to set_state

*v1.0.5*
- setup fixed
- split _generate_payload function to a readable format
- add support for older devices back in (untested, please report back)
- solved recursion problem in send_request
- moved functions back to init
- removed TuyaConnection class, use send_request in try/except
- declassified aescipher
- moved to a more functional programming style
- yield and list comprehensions
- setup.py
- removed code for older devices < 3.3 

Implementations
================
- https://github.com/TradeFace/tuyamqtt
- _let me know, I'll add it here_

Acknowledgements
=================
- This module is a rewrite of https://github.com/clach04/python-tuya
- https://github.com/codetheweb/tuyapi as reference on commands 
- https://github.com/SDNick484 for testing protocol 3.1 reimplementation
- https://github.com/jkerdreux-imt several improvements
- https://github.com/PortableProgrammer help on #20