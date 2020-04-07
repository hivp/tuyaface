Tuya
===================

Rewritten tuya client based on pytuya. Used by https://github.com/TradeFace/tuyamqtt


Todo
==================
- split _generate_payload function to a readable format

Changelog
==================
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