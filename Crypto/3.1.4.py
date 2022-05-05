from Crypto.Cipher import AES
# from eth_utils import to_bytes

fname_ci = '3.1.4_aes_weak_ciphertext.hex'
fname_out = 'sol_3.1.4.hex'

with open(fname_ci) as f_ci:
    ciphertext_hex = f_ci.read().strip()
    ciphertext_bytes = bytes.fromhex(ciphertext_hex)

key_int = 0
iv_int = 0
iv_bytes = iv_int.to_bytes(AES.block_size, 'big')

# for i in range(2**5):
#     key_int += 1
#     key_bytes = key_int.to_bytes(32, 'big')
#     aes_cipher = AES.new(key_bytes, AES.MODE_CBC, iv_bytes)
#     decoded = aes_cipher.decrypt(ciphertext_bytes)
#     print(key_int, key_bytes, decoded)

key_int = 27
key_bytes = key_int.to_bytes(32, 'big')
aes_cipher = AES.new(key_bytes, AES.MODE_CBC, iv_bytes)
decoded = aes_cipher.decrypt(ciphertext_bytes).decode('utf-8')
# print(key_bytes, decoded, sep='\n')
with open(fname_out, 'w') as f_out:
    f_out.write(key_bytes.hex())