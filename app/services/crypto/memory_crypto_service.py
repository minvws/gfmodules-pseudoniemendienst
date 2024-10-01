import hashlib
import hmac

from Crypto.Cipher import AES

from app.services.crypto.crypto_service import CryptoService, CryptoAlgorithm, CryptoAlgorithms
from app.services.crypto.json_keystore import JsonKeyStorage


class MemoryCryptoService(CryptoService):
    """
    A cryptographic service that uses a JSON file to store keys and performs encryption, decryption, signing, and
    validation in-memory.

    Very unsafe and should not be used in production.
    """
    def __init__(self, keystore: JsonKeyStorage):
        self.bs = AES.block_size
        self.keystore = keystore

    def encrypt_and_digest(self, plaintext: bytes, key_id: str, iv: bytes) -> tuple[bytes, bytes]:
        key = self._get_key(key_id)

        cipher = AES.new(key, AES.MODE_GCM, iv)
        return cipher.encrypt_and_digest(plaintext)

    def decrypt_and_verify(self, ciphertext: bytes, tag: bytes, key_id: str, iv: bytes) -> bytes:
        key = self._get_key(key_id)

        cipher = AES.new(key, AES.MODE_GCM, iv)
        cipher.update(b'')
        return cipher.decrypt_and_verify(ciphertext, tag)

    def encrypt(self, plaintext: bytes, key_id: str, iv: bytes) -> bytes:
        key = self._get_key(key_id)

        cipher = AES.new(key, AES.MODE_GCM, iv)
        return cipher.encrypt(plaintext)

    def decrypt(self, ciphertext: bytes, key_id: str, iv: bytes) -> bytes:
        key = self._get_key(key_id)

        cipher = AES.new(key, AES.MODE_GCM, iv)
        return cipher.decrypt(ciphertext)

    def sign(self, alg: CryptoAlgorithm, data: bytes, key_id: str) -> bytes:
        key = self._get_key(key_id)
        return hmac.new(key, data, self._get_digest_mod(alg)).digest()

    def verify(self, alg: CryptoAlgorithm, data: bytes, signature: bytes, key_id: str) -> bool:
        key = self._get_key(key_id)
        return hmac.compare_digest(signature, hmac.new(key, data, self._get_digest_mod(alg)).digest())

    def generate_key(self, key_id: str) -> None:
        self.keystore.generate_key(key_id)

    def _get_key(self, key_id: str) -> bytes:
        key = self.keystore.get_key(key_id)
        if key is None:
            raise Exception(f"Key with id {key_id} not found")
        return key

    def _get_digest_mod(self, alg: CryptoAlgorithm) -> any: # type: ignore
        if alg == CryptoAlgorithms.SHA256:
            return hashlib.sha256

        raise Exception(f"Unsupported algorithm {alg}")
