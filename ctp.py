import os
import zlib
import hashlib
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

# Generování privátního klíče ECDH (Elliptic Curve Diffie-Hellman)
def generate_ecdh_key():
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key = private_key.public_key()
    return private_key, public_key

# Vytvoření shared secret na základě veřejného klíče druhé strany
def ecdh_shared_secret(private_key, peer_public_key):
    shared_secret = private_key.exchange(ec.ECDH(), peer_public_key)
    return hashlib.sha256(shared_secret).digest()

# AES-256-CTR šifrování pro payloady
def aes_256_ctr_encrypt(key, plaintext):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CTR(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return iv + ciphertext

# AES-256-GCM šifrování pro zprávy a soubory
def aes_256_gcm_encrypt(key, plaintext, associated_data=None):
    iv = os.urandom(12)
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    if associated_data:
        encryptor.authenticate_additional_data(associated_data)
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return iv + encryptor.tag + ciphertext

# Dešifrování AES-256-GCM
def aes_256_gcm_decrypt(key, ciphertext, associated_data=None):
    iv = ciphertext[:12]
    tag = ciphertext[12:28]
    data = ciphertext[28:]
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    if associated_data:
        decryptor.authenticate_additional_data(associated_data)
    plaintext = decryptor.update(data) + decryptor.finalize()
    return plaintext

# Dekomprese pomocí zlib
def decompress_data(data):
    return zlib.decompress(data)

# Komprese dat
def compress_data(data):
    return zlib.compress(data)

# Příklad vytvoření protokolu
class cryptmanx:
    def __init__(self):
        self.private_key, self.public_key = generate_ecdh_key()

    def key_exchange(self, peer_public_key):
        return ecdh_shared_secret(self.private_key, peer_public_key)

    def encrypt_data(self, key, data):
        compressed_data = compress_data(data)
        return aes_256_gcm_encrypt(key, compressed_data)

    def decrypt_data(self, key, ciphertext):
        decrypted_data = aes_256_gcm_decrypt(key, ciphertext)
        return decompress_data(decrypted_data)

# Uložená knihovna by poskytovala funkce pro generování klíčů, šifrování a dešifrování s kompresí a dekompresí dat.
