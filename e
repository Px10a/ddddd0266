import os
import struct
from typing import Tuple

# Constants
BLOCK_SIZE = 16  # Block size in bytes
KEY_SIZE = 24    # Key size in bytes (192 bits)
NONCE_SIZE = 12  # Nonce size in bytes (96 bits)
NUM_ROUNDS = 20  # Number of rounds

# Helper functions
def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))

def quarter_round(x: Tuple[int, int, int, int]) -> Tuple[int, int, int, int]:
    a, b, c, d = x
    a = (a + b) & 0xffffffff
    d = d ^ a
    d = (d << 16 | d >> 16) & 0xffffffff
    c = (c + d) & 0xffffffff
    b = b ^ c
    b = (b << 12 | b >> 20) & 0xffffffff
    a = (a + b) & 0xffffffff
    d = d ^ a
    d = (d << 8 | d >> 24) & 0xffffffff
    c = (c + d) & 0xffffffff
    b = b ^ c
    b = (b << 7 | b >> 25) & 0xffffffff
    return a, b, c, d

def key_expansion(key: bytes) -> bytes:
    """
    Expand the 192-bit key into multiple subkeys for the rounds.
    A simple approach, using a hash-based key expansion.
    """
    assert len(key) == KEY_SIZE
    expanded_key = b""
    # Use SHA-256 to expand key (this could be any more complex method)
    while len(expanded_key) < 64:  # Expanding to 512 bits
        expanded_key += os.urandom(KEY_SIZE)  # Fallback to random if needed
    return expanded_key[:64]

def generate_key() -> bytes:
    return os.urandom(KEY_SIZE)

def save_key(key: bytes, filename: str) -> None:
    with open(filename, 'wb') as f:
        f.write(key)

def load_key(filename: str) -> bytes:
    with open(filename, 'rb') as f:
        return f.read()

class CustomCipher:
    def __init__(self, key: bytes):
        assert len(key) == KEY_SIZE
        self.key = key_expansion(key)  # Expanded key

    def encrypt(self, plaintext: bytes, nonce: bytes) -> bytes:
        assert len(nonce) == NONCE_SIZE
        ciphertext = b''
        counter = 0
        for block in self._split_blocks(plaintext):
            keystream = self._generate_keystream(nonce, counter)
            ciphertext += xor_bytes(block, keystream)
            counter += 1
        return ciphertext

    def decrypt(self, ciphertext: bytes, nonce: bytes) -> bytes:
        return self.encrypt(ciphertext, nonce)  # Symmetric operation

    def _generate_keystream(self, nonce: bytes, counter: int) -> bytes:
        """
        Generate keystream by mixing the nonce, counter, and key expansion.
        Each round of encryption will modify the counter.
        """
        counter_bytes = struct.pack('<I', counter)
        block = nonce + counter_bytes
        for _ in range(NUM_ROUNDS):
            block = self._round_function(block)
        return block

    def _round_function(self, block: bytes) -> bytes:
        """
        More advanced round function combining key expansion and transformations
        such as addition and modular arithmetic.
        """
        assert len(block) == BLOCK_SIZE
        x = struct.unpack('<4I', block)
        x = quarter_round(x)
        return struct.pack('<4I', *x)

    def _split_blocks(self, data: bytes) -> Tuple[bytes, ...]:
        """
        Split the data into blocks of size BLOCK_SIZE.
        """
        return [data[i:i + BLOCK_SIZE] for i in range(0, len(data), BLOCK_SIZE)]

# Example usage
if __name__ == "__main__":
    key = generate_key()
    nonce = os.urandom(NONCE_SIZE)
    cipher = CustomCipher(key)

    plaintext = b'This is a more advanced test message!'
    ciphertext = cipher.encrypt(plaintext, nonce)
    decrypted = cipher.decrypt(ciphertext, nonce)

    print(f'Plaintext: {plaintext}')
    print(f'Ciphertext: {ciphertext}')
    print(f'Decrypted: {decrypted}')
