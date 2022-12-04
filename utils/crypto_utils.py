import os
import time
import traceback

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def get_padded_data(content, size=256):
    pad = padding.PKCS7(size).padder()
    padded_data = pad.update(data=content) + pad.finalize()
    return padded_data


def get_unpadded_data(content, size=256):
    unpadder = padding.PKCS7(size).unpadder()
    return unpadder.update(content) + unpadder.finalize()       # return plain 'un-padded' text


def encrypt_server_to_client(key, plaintext):

    # Generate a random 16 bytes long IV
    iv = generate_iv()
    if not isinstance(plaintext, bytes):
        plaintext = bytes(plaintext, 'utf-8')

    plaintext = get_padded_data(content=plaintext)

    # Construct an AES-GCM Cipher object with SRP Key and IV
    cipher = Cipher(
        algorithm=algorithms.AES(key),
        mode=modes.GCM(iv),
        backend=default_backend()
    )
    encryptor = cipher.encryptor()

    encryptor.authenticate_additional_data(b'authenticated but not encrypted')

    # Encrypt plaintext and get associated ciphertext
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return iv, ciphertext, encryptor.tag


def decrypt_client_to_server(key, iv, ciphertext, tag):

    # Construct a Cipher object, with key, iv, and GCM tag
    cipher = Cipher(
        algorithm=algorithms.AES(key),
        mode=modes.GCM(iv, tag),
        backend=default_backend()
    )
    decryptor = cipher.decryptor()

    decryptor.authenticate_additional_data(b'authenticated but not encrypted')

    # Decrypt the ciphertext and get the associated plaintext and then un-pad it
    decrypted_text = decryptor.update(ciphertext) + decryptor.finalize()
    return get_unpadded_data(content=decrypted_text)



def generate_iv():
    return os.urandom(16)


def generate_symmetric_keys():      # 32 bytes ~ 256 bits keys for encrypting the communication between the clients
    return os.urandom(16)


def generate_timestamp():
    """Get seconds since epoch (UTC)."""
    return str(int(time.time()))
