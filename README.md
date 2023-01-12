mona
====

Corelan Repository for mona.py

### What is mona.py?

Mona.py is a python script that can be used to automate and speed up specific searches while developing exploits (typically for the Windows platform).
It runs on Immunity Debugger and WinDBG, and requires python 2.7.
Although it runs in WinDBG x64, the majority of its features were written specifically for 32bit processes.

For more info on mona.py and how to use it, please consider taking one of Corelan's exploit development classes:

https://www.corelan-training.com



Installation instructions
-------------------------

### Immunity Debugger
1. drop mona.py into the 'PyCommands' folder (inside the Immunity Debugger application folder).
2. install Python 2.7.14 (or a higher 2.7.xx version) into c:\python27, thus overwriting the version that was bundled with Immunity. This is needed to avoid TLS issues when trying to update mona.  Make sure you are installing the 32bit version of python.

### WinDBG
See https://github.com/corelan/windbglib



notes
-----

mona.py has been inventoried at Rawsec's CyberSecurity Inventory
[![Rawsec's CyberSecurity Inventory](https://inventory.raw.pm/img/badges/Rawsec-inventoried-FF5050_plastic.svg)](https://inventory.raw.pm/)
