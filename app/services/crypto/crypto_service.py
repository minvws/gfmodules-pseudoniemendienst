class CryptoAlgorithm:
    SHA256 = "sha256"


class CryptoService:
    """
    Interface for a cryptographic service that provides encryption, decryption, signing, and verification.
    """
    def encrypt_and_digest(self, plaintext: bytes, key_id: str, iv: bytes) -> (bytes, bytes):
        """
        Encrypt the plaintext with the given key_id and iv and return the ciphertext and tag.
        """
        pass

    def decrypt_and_verify(self, ciphertext: bytes, tag: bytes, key_id: str, iv: bytes) -> bytes:
        """
        Decrypt the ciphertext with the given key_id and iv and verify the tag.
        """
        pass

    def encrypt(self, plaintext: bytes, key_id: str, iv: bytes) -> bytes:
        """
        Encrypt the plaintext with the given key_id and iv.
        """
        pass

    def decrypt(self, ciphertext: bytes, key_id: str, iv: bytes) -> bytes:
        """
        Decrypt the ciphertext with the given key_id and iv.
        """
        pass

    def sign(self, alg: CryptoAlgorithm, data: bytes, key_id: str) -> bytes:
        """
        Sign the data with the given key_id.
        """
        pass

    def verify(self, alg: CryptoAlgorithm, data: bytes, signature: bytes, key_id: str) -> bool:
        """
        Verify the signature of the data with the given key_id.
        """
        pass

    def generate_key(self, key_id: str) -> None:
        """
        Generate a key with the given key_id. This will create both a GENERIC and AES key.
        """
        pass
