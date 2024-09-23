import json
import base64

from app.services.crypto.crypto_service import CryptoService

class JweAlgorithm(str):
    pass

class JweAlgorithms:
    A256GCM = JweAlgorithm("A256GCM")
    DIR = JweAlgorithm("DIR")

class JWEVerifyException(Exception):
    pass

def encrypt(
    crypto_service: CryptoService,
    key_id: str,
    plaintext: bytes,
    iv: bytes,
    encryption: JweAlgorithm = JweAlgorithms.A256GCM,
    algorithm: JweAlgorithm = JweAlgorithms.DIR
) -> str:
    """
    Encrypt a plaintext using JWE
    """
    if encryption != JweAlgorithms.A256GCM:
        raise ValueError("Unsupported encryption algorithm")
    if algorithm != JweAlgorithms.DIR:
        raise ValueError("Unsupported algorithm")
    if len(iv) != 12:
        raise ValueError("IV length is not 12")

    header = {
        "alg": algorithm,
        "enc": encryption,
        "kid": key_id,
    }
    header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode('utf-8')).decode('utf-8')
    ciphertext, tag = crypto_service.encrypt_and_digest(plaintext, key_id, iv)

    key_b64 = ""
    iv_b64 = base64.urlsafe_b64encode(iv).decode('utf-8')
    ciphertext_b64 = base64.urlsafe_b64encode(ciphertext).decode('utf-8')
    tag_b64 = base64.urlsafe_b64encode(tag).decode('utf-8')

    jwe_compact = f"{header_b64}.{key_b64}.{iv_b64}.{ciphertext_b64}.{tag_b64}"
    return jwe_compact


def verify(jwe_token: str) -> tuple[dict[str, str], bytes, bytes, bytes, bytes]:
    header, key, iv, ciphertext, tag = split_jwe(jwe_token)

    # key must not be present
    if key != b"":
        raise JWEVerifyException("Key must not be present")

    # Check if the header is valid
    if header['alg'] != JweAlgorithms.DIR:
        raise JWEVerifyException("Unsupported algorithm")
    if header['enc'] != JweAlgorithms.A256GCM:
        raise JWEVerifyException("Unsupported encryption algorithm")
    if header['kid'] == "":
        raise JWEVerifyException("Missing key ID")

    # Check if the IV is valid
    if len(iv) != 12:
        raise JWEVerifyException("IV length is not 12")

    # Check if the ciphertext is valid
    if len(ciphertext) == 0:
        raise JWEVerifyException("Ciphertext is empty")

    # Check if the tag is valid
    if len(tag) == 0:
        raise JWEVerifyException("Tag is empty")

    return header, key, iv, ciphertext, tag



def decrypt(crypto_service: CryptoService, jwe_token: str) -> bytes:
    """
    Decrypt a JWE compact serialization
    """
    try:
        (header, _, iv, ciphertext, tag) = verify(jwe_token)
    except JWEVerifyException as e:
        # This is to make implicit that this block can raise an error
        raise e

    return crypto_service.decrypt_and_verify(ciphertext, tag, header['kid'], iv)


def split_jwe(jwe_compact: str) -> tuple[dict[str, str], bytes, bytes, bytes, bytes]:
    """
    Split a JWE compact serialization into its components
    """
    try:
        header_b64, key_b64, iv_b64, ciphertext_b64, tag_b64 = jwe_compact.split('.')

        header = json.loads(base64.urlsafe_b64decode(header_b64).decode('utf-8'))
        key = base64.urlsafe_b64decode(key_b64)
        iv = base64.urlsafe_b64decode(iv_b64)
        ciphertext = base64.urlsafe_b64decode(ciphertext_b64)
        tag = base64.urlsafe_b64decode(tag_b64)

        return header, key, iv, ciphertext, tag

    except ValueError:
        raise ValueError("Invalid JWE compact serialization")
