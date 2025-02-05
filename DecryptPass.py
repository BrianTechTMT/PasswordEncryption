import base64
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet

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
    master_password = input("Enter master password for decryption:")
    
     # Read the file that contains the salt and encrypted password.
    try:
        with open("encrypted_password.txt", "rb") as f:
            data = f.read()
    except FileNotFoundError:
        print("Encrypted file not found.")
        return

    # The file is expected to have the salt and the encrypted message separated by a newline.
    try:
        salt, encrypted = data.split(b"\n", 1)
    except ValueError:
        print("Invalid file format.")
        return

    key = derive_key(master_password, salt)
    fernet = Fernet(key)
    
    try:
        decrypted = fernet.decrypt(encrypted)
    except Exception as e:
        print("Decryption failed:", e)
        return
    
    print("Decrypted password:", decrypted.decode())

if __name__ == "__main__":
    main()