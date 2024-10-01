import base64
import hmac

import requests

from app.services.crypto.crypto_service import CryptoService, CryptoAlgorithm, CryptoAlgorithms

AAD = "plaintext aad"

class HsmApiCryptoService(CryptoService):
    def __init__(self, url: str, module: str, slot: str, cert_path: str):
        self.url = url
        self.module = module
        self.slot = slot
        self.cert_path = cert_path

    def encrypt_and_digest(self, plaintext: bytes, key_id: str, iv: bytes) -> tuple[bytes, bytes]:
        ciphertext = self.encrypt(plaintext, key_id, iv)

        digest_data = AAD.encode() + iv + ciphertext + len(AAD).to_bytes(8, byteorder='big')
        digest_hmac = self.sign(CryptoAlgorithms.SHA256, digest_data, key_id)

        return ciphertext, digest_hmac[:16]

    def decrypt_and_verify(self, ciphertext: bytes, tag: bytes, key_id: str, iv: bytes) -> bytes:
        digest_data = AAD.encode() + iv + ciphertext + len(AAD).to_bytes(8, byteorder='big')
        digest_hmac = self.sign(CryptoAlgorithms.SHA256, digest_data, key_id)

        if not hmac.compare_digest(digest_hmac[:16], tag):
            raise Exception("Invalid authentication tag")

        return self.decrypt(ciphertext, key_id, iv)

    def encrypt(self, plaintext: bytes, key_id: str, iv: bytes) -> bytes:
        hsm_data = {
            "label": key_id,
            "objtype": "SECRET_KEY",
            "data": base64.b64encode(plaintext).decode('utf-8'),
            "mechanism": "AES-GCM",
            "hashmethod": "sha256",
            "iv": base64.b64encode(iv).decode('utf-8'),
        }

        r = requests.post(f"{self.url}/hsm/{self.module}/{self.slot}/encrypt", json=hsm_data, cert=self.cert_path)
        if r.status_code != 200:
            raise Exception(f"Failed to encrypt data: {r.text}")

        try:
            res = r.json()['result']['data']
            return base64.b64decode(res)
        except KeyError:
            raise Exception(f"Failed to encrypt data: {r.text}")

    def decrypt(self, ciphertext: bytes, key_id: str, iv: bytes) -> bytes:
        hsm_data = {
            "label": key_id,
            "objtype": "SECRET_KEY",
            "data": base64.b64encode(ciphertext).decode('utf-8'),
            "mechanism": "AES_GCM",
            "hashmethod": "sha256",
            "iv": base64.b64encode(iv).decode('utf-8'),
        }

        r = requests.post(f"{self.url}/hsm/{self.module}/{self.slot}/decrypt", json=hsm_data, cert=self.cert_path)
        if r.status_code != 200:
            raise Exception(f"Failed to decrypt data: {r.text}")

        try:
            res = r.json()['result']['data']
            return base64.b64decode(res)
        except KeyError:
            raise Exception(f"Failed to decrypt data: {r.text}")

    def sign(self, alg: CryptoAlgorithm, data: bytes, key_id: str) -> bytes:
        hsm_data = {
            "label": key_id,
            "objtype": "SECRET_KEY",
            "data": base64.b64encode(data).decode('utf-8'),
            "mechanism": "AES_CMAC",
            "hashmethod": "sha256",
        }
        r = requests.post(f"{self.url}/hsm/{self.module}/{self.slot}/sign", json=hsm_data, cert=self.cert_path)
        if r.status_code != 200:
            raise Exception(f"Failed to sign data: {r.text}")

        try:
            res = r.json()['result']['data']
            return base64.b64decode(res)
        except KeyError:
            raise Exception(f"Failed to sign data: {r.text}")

    def verify(self, alg: CryptoAlgorithm, data: bytes, signature: bytes, key_id: str) -> bool:
        hsm_data = {
            "label": key_id,
            "objtype": "SECRET_KEY",
            "data": base64.b64encode(data).decode('utf-8'),
            "mechanism": "AES_CMAC",
            "signature": base64.b64encode(signature).decode('utf-8'),
            "hashmethod": "sha256",
        }
        r = requests.post(f"{self.url}/hsm/{self.module}/{self.slot}/verify", json=hsm_data, cert=self.cert_path)
        return r.status_code == 200
