import sys
from Crypto.Cipher import AES
if len(sys.argv) > 4:
    fname_ci = sys.argv[1]
    fname_key = sys.argv[2]
    fname_iv = sys.argv[3]
    fname_out = sys.argv[4]
    # print(fname_ci, fname_key)
else:
    fname_ci = '3.1.3_aes_ciphertext.hex'
    fname_key = '3.1.3_aes_key.hex'
    fname_iv = '3.1.3_aes_iv.hex'
    fname_out = 'sol_3.1.3.txt'

with open(fname_key) as f_key:
    key_hex = f_key.read().strip()
    # key = f_key.read().strip()
    # print(key_hex)
    key_bytes = bytes.fromhex(key_hex)
    # print(key_bytes)

with open(fname_ci) as f_ci:
    ciphertext_hex = f_ci.read().strip()
    ciphertext_bytes = bytes.fromhex(ciphertext_hex)
    # print(ciphertext_bytes)

with open(fname_iv) as f_iv:
    iv_hex = f_iv.read().strip()
    iv_bytes = bytes.fromhex(iv_hex)
    # print(iv_bytes)

aes_cipher = AES.new(key_bytes, AES.MODE_CBC, iv_bytes)

decoded = aes_cipher.decrypt(ciphertext_bytes).decode('utf-8')
# print(decoded)

with open(fname_out, 'w') as f_out:
    f_out.write(decoded)