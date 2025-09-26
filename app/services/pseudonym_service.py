import base64
import hashlib
import hmac
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

from app.personal_id import PersonalId


class PseudonymService:
    def __init__(self, hmac_key: bytes, aes_key: bytes) -> None:
        self.__hmac_key = hmac_key
        self.__aes_key = aes_key

    def exchange_irreversible_pseudonym(
        self,
        personal_id: PersonalId,
        recipient_organization: str,
        recipient_scope: str,
    ) -> str:
        """
        Generate an irreversible pseudonym using HMAC-SHA256.
        """
        subject = self.get_subject(personal_id, recipient_organization, recipient_scope)
        digest = hmac.new(self.__hmac_key, subject.encode('utf-8'), hashlib.sha256).digest()
        return base64.urlsafe_b64encode(digest).decode('utf-8')

    def exchange_reversible_pseudonym(
        self,
        personal_id: PersonalId,
        recipient_organization: str,
        recipient_scope: str,
    ) -> str:
        """
        Generate a reversible pseudonym using AES encryption.
        """
        subject = self.get_subject(personal_id, recipient_organization, recipient_scope)
        return self.encode_pseudonym(subject)

    def decode_reversible_pseudonym(self, encoded_pseudonym: str) -> dict[str, str|PersonalId]:
        """
        Decode a reversible pseudonym to retrieve the original personal ID and associated info.
        """
        subject = self.decode_pseudonym(encoded_pseudonym)
        parts = subject.split('|')
        if len(parts) != 3:
            raise ValueError("Invalid encoded subject format")

        return {
            'personal_id': PersonalId.from_str(parts[0]),
            'recipient_organization': parts[1],
            'recipient_scope': parts[2],
        }


    def get_subject(
        self,
        personal_id: PersonalId,
        recipient_organization: str,
        recipient_scope: str,
    ) -> str:
        """
        Construct the subject string for pseudonym generation.
        """
        return f"{personal_id.as_str()}|{recipient_organization}|{recipient_scope}"


    def encode_pseudonym(self, pseudonym: str) -> str:
        """
        Encode the personal ID using AES encryption in CBC mode with PKCS7 padding.
        """
        iv = get_random_bytes(AES.block_size)
        message = f"{pseudonym}".encode('utf-8')
        cipher = AES.new(self.__aes_key, AES.MODE_GCM, iv)
        ciphertext = cipher.encrypt(pad(message, AES.block_size))
        return base64.urlsafe_b64encode(iv + ciphertext).decode('utf-8')


    def decode_pseudonym(self, encoded_pseudonym: str) -> str:
        """
        Decode the personal ID using AES decryption
        """
        data = base64.urlsafe_b64decode(encoded_pseudonym)
        iv = data[:AES.block_size]
        ciphertext = data[AES.block_size:]
        cipher = AES.new(self.__aes_key, AES.MODE_GCM, iv)
        return unpad(cipher.decrypt(ciphertext), AES.block_size).decode('utf-8')
