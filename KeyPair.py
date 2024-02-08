from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from typing import Tuple

def generate_key_pair() -> Tuple[bytes, bytes]:
    ''' Function to generate an RSA key pair to allow encryption and decryption
        between the server and the client'''
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

message_private_key, message_public_key = generate_key_pair()