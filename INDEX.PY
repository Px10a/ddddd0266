import os
from cipher import CustomCipher

class CCA_Attack_Real:
    def __init__(self, cipher: CustomCipher, nonce: bytes):
        self.cipher = cipher
        self.nonce = nonce

    def perform_attack(self, target_ciphertext: bytes) -> bytes:
        """
        Perform a real Chosen Ciphertext Attack (CCA) where we simulate modifications
        and oracle interaction. The attacker can alter ciphertexts and observe the result.
        """
        print("Performing Real Chosen Ciphertext Attack (CCA)...")
        
        # The attacker can modify a byte of the ciphertext (simulate manipulation)
        modified_ciphertext = self._flip_byte(target_ciphertext, 10)
        
        # The real attack here is based on observing changes in the decrypted output.
        decrypted_modified = self.cipher.decrypt(modified_ciphertext, self.nonce)
        
        print(f"Original Ciphertext: {target_ciphertext.hex()}")
        print(f"Modified Ciphertext: {modified_ciphertext.hex()}")
        print(f"Decrypted (Modified): {decrypted_modified.hex()}")
        
        return decrypted_modified

    def _flip_byte(self, ciphertext: bytes, byte_index: int) -> bytes:
        """
        Flip a specific byte in the ciphertext. This simulates a modification attack where the attacker
        changes the ciphertext and checks how the system reacts to it.
        """
        flipped_byte = ciphertext[byte_index] ^ 0xFF  # Flip the byte by XOR with 0xFF
        return ciphertext[:byte_index] + bytes([flipped_byte]) + ciphertext[byte_index + 1:]

if __name__ == "__main__":
    key = os.urandom(24)  # 192-bit key
    nonce = os.urandom(12)  # Nonce size is 96 bits
    cipher = CustomCipher(key)

    plaintext = b"Real attack testing for CCA!"
    ciphertext = cipher.encrypt(plaintext, nonce)

    cca_attack = CCA_Attack_Real(cipher, nonce)
    decrypted_plaintext = cca_attack.perform_attack(ciphertext)

    print(f"Original Plaintext: {plaintext}")
    print(f"Decrypted (Original): {cipher.decrypt(ciphertext, nonce).hex()}")
    print(f"Decrypted (Modified): {decrypted_plaintext.hex()}")
