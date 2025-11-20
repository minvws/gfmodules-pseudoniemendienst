import base64

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

from app.services.pseudonym_service import hkdf_derive


class RidService:
    def __init__(self, master_key: bytes, aad: bytes) -> None:
        # Derive the necessary keys from the master key
        self.__rid_aes_key = hkdf_derive(master_key, b"prs:rid", 32)
        self.__aad = aad


    def encrypt_rid(self, rid: str) -> str:
        message = rid.encode('utf-8')

        nonce = get_random_bytes(12)
        cipher = AES.new(self.__rid_aes_key, AES.MODE_GCM, nonce=nonce)
        cipher.update(self.__aad)

        ciphertext, tag = cipher.encrypt_and_digest(message)

        token = nonce + tag + ciphertext

        return base64.urlsafe_b64encode(token).decode('utf-8')


    def decrypt_rid(self, enc_rid: str) -> str:
        data = base64.urlsafe_b64decode(enc_rid)

        nonce = data[:12]
        tag = data[12:28]
        ciphertext = data[28:]

        cipher = AES.new(self.__rid_aes_key, AES.MODE_GCM, nonce=nonce)
        cipher.update(self.__aad)

        message = cipher.decrypt_and_verify(ciphertext, tag)
        return message.decode('utf-8')
