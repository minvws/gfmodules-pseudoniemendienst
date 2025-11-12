import base64

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes


class RidService:
    def __init__(self, aes_key: bytes) -> None:
        self.__aes_key = aes_key


    def encrypt_rid(self, rid: str) -> str:
        message = f"{rid}".encode('utf-8')

        iv = get_random_bytes(AES.block_size)
        cipher = AES.new(self.__aes_key, AES.MODE_GCM, iv)
        ciphertext = cipher.encrypt(pad(message, AES.block_size))

        return base64.urlsafe_b64encode(iv + ciphertext).decode('utf-8')


    def decrypt_rid(self, enc_rid: str) -> str:
        data = base64.urlsafe_b64decode(enc_rid)
        iv = data[:AES.block_size]
        ciphertext = data[AES.block_size:]
        cipher = AES.new(self.__aes_key, AES.MODE_GCM, iv)

        return unpad(cipher.decrypt(ciphertext), AES.block_size).decode('utf-8')
