from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from modules.KeyPair import message_private_key, message_public_key
import hashlib

# Function to hash data
def hash_data(data: str) -> str:
    ''' Hashes data in a way which is designed to be deterministic'''
    hashed_data: str = hashlib.sha256(data.encode()).hexdigest()
    return hashed_data


def encrypt_message(message: bytes) -> bytes:
    ''' Function to encrypt a message with bytes type '''
    cipher_text: bytes = message_public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return cipher_text


def decrypt_message(cipher_text: bytes) -> bytes:
    ''' Function to decrypt a message with bytes type '''
    decrypted_text: bytes = message_private_key.decrypt(
        cipher_text,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    ).decode()
    return decrypted_text
