import sys
if len(sys.argv) > 3:
    fname_ci = sys.argv[1]
    fname_key = sys.argv[2]
    fname_out = sys.argv[3]
    # print(fname_ci, fname_key)
else:
    fname_ci = '3.1.2_sub_ciphertext.txt'
    fname_key = '3.1.2_sub_key.txt'
    fname_out = 'sol_3.1.2.txt'

with open(fname_key) as f_key:
    key = f_key.read().strip()
with open(fname_ci) as f_ci:
    ciphertext = f_ci.read().strip()

# print(key)
# print(ciphertext)

keymap = dict()

for i in range(26):
    cur_ord = ord('A')+i
    cur_chr = chr(cur_ord)
    keymap[key[i]] = cur_chr
    # print(cur_chr, keymap[cur_chr])

decoded = ''
for c in ciphertext:
    if keymap.get(c) != None:
        decoded += keymap.get(c)
    else:
        decoded += c

with open(fname_out, 'w') as f_out:
    f_out.write(decoded)

