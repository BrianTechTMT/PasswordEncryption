#EncryptPass
import os
import base64
import secrets
import string
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet

def generate_password(length=12):
    "General password generation"
    if length < 12:
        raise ValueError("Length must be at least 12.")
    
    uppercase = string.ascii_uppercase
    lowercase = string.ascii_lowercase
    digits = string.digits
    symbols = string.punctuation
    
    # Make sure everything from each category is generated for the password
    password_chars = [
        secrets.choice(uppercase),
        secrets.choice(lowercase),
        secrets.choice(digits),
        secrets.choice(symbols)
    ]
    join_chars = uppercase + lowercase + digits + symbols
    password_chars.extend(secrets.choice(join_chars) for _ in range(length - 4 ))
    secrets.SystemRandom().shuffle(password_chars)
    return ''.join(password_chars)

def derive_key(master_password: str, salt: bytes) -> bytes:
    """Derive a key from the master password and salt using PBKDF2HMAC."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(master_password.encode()))

def main():
    # Prompt master password
    master_password = input("Enter master password for encryption: ")
    salt = os.urandom(16)
    key = derive_key(master_password, salt)
    fernet = Fernet(key)
    
    password = generate_password(12)
    print("Generated Password:", password)
    encrypted = fernet.encrypt(password.encode())
    
    with open("encrypted_password.txt", "wb") as f:
        f.write(salt + b"\n" + encrypted)
    print ("encrypted password is saved")

main()