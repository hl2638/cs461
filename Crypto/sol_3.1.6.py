import sys
from struct import *
from numpy import mask_indices 
from itertools import permutations
if len(sys.argv) > 2:
    fname_fi = sys.argv[1]
    fname_out = sys.argv[2]
    # print(fname_ci, fname_key)
else:
    fname_fi = '3.1.6_input_string.txt'
    fname_out = '3.1.6_out.hex'

with open(fname_fi) as f_fi:
    text = f_fi.read().strip()


def WHA(inStr):
    if type(inStr) == str:
        inStr = bytes(inStr, 'utf-8')
    elif type(inStr) == int:
        inStr = inStr.to_bytes(8, 'big')
    Mask = 0x3FFFFFFF
    outHash = 0
    for byte in inStr:
        int_val = \
            ((byte ^ 0xCC) << 24) | \
            ((byte ^ 0x33) << 16) | \
            ((byte ^ 0xAA) << 8 ) | \
            ((byte ^ 0x55) )
        outHash = (outHash & Mask) + (int_val & Mask)
    return hex(outHash)

# print(WHA("Hello world!"))

# h1 = int(WHA(text), 16)

# for perm in permutations(text):
#     inStr = ''.join([c for c in perm])
#     # print(inStr)
#     if inStr == text: continue
#     if int(WHA(inStr), 16) == h1:
#         col = inStr
#         break

# print(col)

with open(fname_out, 'w') as f_out:
    f_out.write(WHA(text))
