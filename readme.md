Tuya
===================

Rewritten tuya client based on pytuya. Used by https://github.com/TradeFace/tuyamqtt

Public Interfaces
==================

Request device status
```
status(device: dict)
Returns json string
```

Change device state
```
set_state(device: dict, value: bool,idx: int = 1)
Returns json string
```

Change device status
```
set_status(device: dict, dps: dict)
Returns json string
```


Todo
==================


Changelog
==================
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

Acknowledgements
=================
- This module is a rewrite of https://github.com/clach04/python-tuya
- https://github.com/codetheweb/tuyapi as reference on commands 
- https://github.com/SDNick484 for testing protocol 3.1 reimplementation
- https://github.com/jkerdreux-imt several improvements