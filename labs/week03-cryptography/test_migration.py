import hashlib
from solution_skeleton import store_password, verify_password

def verify_and_upgrade(stored_hash, password):
    legacy_hash = hashlib.md5(password.encode()).hexdigest()

    if stored_hash == legacy_hash:
        return True, store_password(password)

    if verify_password(stored_hash, password):
        return True, stored_hash

    return False, stored_hash

# Simulate a legacy MD5 account
old_hash = hashlib.md5(b"password123").hexdigest()

ok, upgraded_hash = verify_and_upgrade(old_hash, "password123")

print("Legacy password accepted:", ok)
print("Upgraded to Argon2id:", upgraded_hash.startswith("$argon2id$"))
print("New password verification:", verify_password(upgraded_hash, "password123"))
print("Wrong password rejected:", not verify_password(upgraded_hash, "wrongpassword"))
