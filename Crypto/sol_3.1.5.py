import sys 
# from Crypto.Cipher import PKCS1_OAEP
# from Crypto.PublicKey import RSA
if len(sys.argv) > 4:
    fname_ci = sys.argv[1]
    fname_key = sys.argv[2]
    fname_mod = sys.argv[3]
    fname_out = sys.argv[4]
    # print(fname_ci, fname_key)
else:
    fname_ci = '3.1.5_RSA_ciphertext.hex'
    fname_key = '3.1.5_RSA_private_key.hex'
    fname_mod = '3.1.5_RSA_modulo.hex'
    fname_out = 'sol_3.1.5.hex'

with open(fname_key) as f_key:
    key_hex = f_key.read().strip()
    # print(key_hex)
    key_bytes = bytes.fromhex(key_hex)
    key_int = int(key_hex, 16)
    # print(key_int)

with open(fname_ci) as f_ci:
    ciphertext_hex = f_ci.read().strip()
    # print(ciphertext_hex)
    ciphertext_bytes = bytes.fromhex(ciphertext_hex)
    ciphertext_int = int(ciphertext_hex, 16)
    # print(ciphertext_int)

with open(fname_mod) as f_mod:
    mod_hex = f_mod.read().strip()
    # print(mod_hex)
    mod_bytes = bytes.fromhex(mod_hex)
    mod_int = int(mod_hex, 16)
    # print(mod_int)

decoded_int = pow(ciphertext_int, key_int, mod_int)
with open(fname_out, 'w') as f_out:
    f_out.write(hex(decoded_int)[2:])

# rsa_key = RSA.import_key(key_bytes)
# rsa = PKCS1_OAEP.new(rsa_key)
# decoded = rsa.decrypt(ciphertext_bytes)
# print(decoded)

