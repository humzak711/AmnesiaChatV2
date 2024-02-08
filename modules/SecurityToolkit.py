from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import hashlib

# Function to hash data
def hash_data(data: str) -> str:
    ''' Hashes data in a way which is designed to be deterministic'''
    hashed_data: str = hashlib.sha256(data.encode()).hexdigest()
    return hashed_data

# Function to encrypt messages
def encrypt_message(message: str, message_public_key: bytes) -> bytes:
    ''' Function to encode a message to UTF-8 then decrypt it'''
    cipher_text: bytes = message_public_key.encrypt(
        message.encode('utf-8'),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return cipher_text

# Function to decrypt messages
def decrypt_message(cipher_text: bytes, message_private_key: bytes) -> str:
    ''' Function to decrypt a  UTF-8 encoded string '''
    decrypted_text: bytes = message_private_key.decrypt(
        cipher_text,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted_text.decode('utf-8')
