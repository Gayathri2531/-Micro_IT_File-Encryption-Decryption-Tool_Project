import base64
import os
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

# Derive a 32-byte key from a user password
def derive_key_from_password(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))
    

# Generate or get key
def get_key():
    choice = input("Do you want to enter a password to derive the key? (y/n): ").strip().lower()

    if choice == 'y':
        password = input("Enter your password (will be converted to encryption key): ")
        salt = os.urandom(16)
        key = derive_key_from_password(password, salt)
        print("\n[+] Derived key (base64):", key.decode())
        print("[+] Salt (save this too!):", base64.urlsafe_b64encode(salt).decode())
        return key, salt
    else:
        key = Fernet.generate_key()
        print("\n[+] Auto-generated key:", key.decode())
        return key, None

# Encrypt and decrypt
print("Author By: Gayathri Nalluri")
print("GitHub: https://github.com/Gayathri2531\n")
def main():
    print("=== Encryption with Custom Password-Based Key ===")
    message = input("Enter message to encrypt: ").strip()

    key, salt = get_key()
    fernet = Fernet(key)

    encrypted = fernet.encrypt(message.encode())
    print("\n[+] Encrypted message:", encrypted.decode())

    decrypted = fernet.decrypt(encrypted).decode()
    print("[+] Decrypted message:", decrypted)

if __name__ == "__main__":
    main()
