from cryptography.fernet import Fernet
from django.conf import settings

def get_fernet_instance():
    # Fetch configured encryption key from django settings
    encryption_key = getattr(settings, 'ENCRYPTION_KEY', '')
    if not encryption_key:
        # Generate a stable key derived from SECRET_KEY so it's a valid 32-byte base64 string
        import hashlib, base64
        secret_bytes = settings.SECRET_KEY.encode()
        derived_key = hashlib.sha256(secret_bytes).digest()
        encryption_key = base64.urlsafe_b64encode(derived_key).decode()
    
    return Fernet(encryption_key.encode())

def encrypt_key(plain_text: str) -> str:
    """Encrypts an API key string using AES Fernet."""
    if not plain_text:
        return ""
    try:
        f = get_fernet_instance()
        return f.encrypt(plain_text.encode()).decode()
    except Exception as e:
        print(f"Encryption Failure: {e}")
        return ""

def decrypt_key(encrypted_text: str) -> str:
    """Decrypts an AES encrypted cipher string back to plain text."""
    if not encrypted_text:
        return ""
    try:
        f = get_fernet_instance()
        return f.decrypt(encrypted_text.encode()).decode()
    except Exception as e:
        print(f"Decryption Failure: {e}")
        return ""
