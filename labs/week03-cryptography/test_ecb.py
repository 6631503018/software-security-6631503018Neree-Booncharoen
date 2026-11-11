from vulnerable_crypto import encrypt_ecb

plaintext = b"A" * 16 + b"A" * 16
ciphertext = encrypt_ecb(plaintext)

blocks = [
    ciphertext[i:i+16]
    for i in range(0, len(ciphertext), 16)
]

print("Plaintext block 1:", plaintext[:16])
print("Plaintext block 2:", plaintext[16:32])
print("Ciphertext block 1:", blocks[0].hex())
print("Ciphertext block 2:", blocks[1].hex())
print("Blocks identical:", blocks[0] == blocks[1])
