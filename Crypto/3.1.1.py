with open('3.1.1_value.hex') as f:
    val_hex = f.read().strip()[2:]

print(len(val_hex))
print(val_hex)

val_int = int(val_hex, 16)
print(val_int)

val_bin = bin(val_int)[2:]
print(val_bin)
