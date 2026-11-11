import os
from Crypto.Cipher import AES
from solution_skeleton import encrypt_gcm

key = os.urandom(32)
message = b"Hello, secure encryption!"

nonce, ciphertext, tag = encrypt_gcm(message, key)

print("Nonce length:", len(nonce))
print("Ciphertext:", ciphertext.hex())
print("Tag:", tag.hex())

# Decrypt the original ciphertext
cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
plaintext = cipher.decrypt_and_verify(ciphertext, tag)
print("Original message verified:", plaintext == message)

# Change one byte and test authentication
tampered = bytearray(ciphertext)
tampered[0] ^= 1

try:
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    cipher.decrypt_and_verify(bytes(tampered), tag)
    print("Tampering detected: False")
except ValueError:
    print("Tampering detected: True")
