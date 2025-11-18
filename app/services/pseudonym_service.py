import base64
import hashlib
import hmac
from enum import Enum

from Crypto.Cipher import AES
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from app.personal_id import PersonalId

def hkdf_derive(master_key: bytes, info: bytes, length: int = 32) -> bytes:
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=None,
        info=info,
    )
    return hkdf.derive(master_key)

class PseudonymType(str, Enum):
    Irreversible = "irreversible"
    Reversible = "reversible"

class PseudonymService:
    def __init__(self, master_key: bytes) -> None:
        # Derive the necessary keys from the master key
        self.__master_key = master_key
        self.__irp_hmac_key = hkdf_derive(master_key, b"prs:irp:hmac", 32)
        self.__aad = b"PRS:Pseudonym:v1"

    def generate_irreversible_pseudonym(
        self,
        personal_id: PersonalId,
        recipient_organization: str,
        recipient_scope: str,
    ) -> str:
        """
        Generate a deterministic irreversible pseudonym
        """
        subject = self._get_subject(personal_id, recipient_organization, recipient_scope)
        digest = hmac.new(self.__irp_hmac_key, subject.encode('utf-8'), hashlib.sha256).digest()
        return base64.urlsafe_b64encode(digest).decode('utf-8')

    def generate_reversible_pseudonym(
        self,
        personal_id: PersonalId,
        recipient_organization: str,
        recipient_scope: str,
    ) -> str:
        """
        Generate a deterministic reversible pseudonym using AES-SIV
        """
        subject = self._get_subject(personal_id, recipient_organization, recipient_scope)
        return self._encrypt_data(subject, recipient_organization)

    def decrypt_reversible_pseudonym(self, reversible_pseudonym: str, recipient_organization: str) -> dict[str, str|PersonalId]:
        """
        Decode a reversible pseudonym to retrieve the original personal ID and associated info.
        """
        try:
            subject = self._decrypt_data(reversible_pseudonym, recipient_organization)
            parts = subject.split('|')
            if len(parts) != 3:
                raise ValueError("Invalid encoded subject format")
        except ValueError as e:
            raise ValueError("Failed to decode reversible pseudonym") from e

        return {
            'personal_id': PersonalId.from_str(parts[0]),
            'recipient_organization': parts[1],
            'recipient_scope': parts[2],
        }


    def _get_subject(
        self,
        personal_id: PersonalId,
        recipient_organization: str,
        recipient_scope: str,
    ) -> str:
        """
        Construct the subject string for pseudonym generation.
        """
        if '|' in recipient_organization or '|' in recipient_scope:
            raise ValueError("Invalid characters in input")

        return f"{personal_id.as_str()}|{recipient_organization}|{recipient_scope}"

    def _derive_rp_key(self, recipient_organization: str) -> bytes:
        """
        Derive the AES key for reversible pseudonyms for a specific recipient organization
        """
        info = b"prs:rp:aes-siv:" + recipient_organization.encode('utf-8')
        return hkdf_derive(self.__master_key, info, 32)

    def _encrypt_data(self, message: str, recipient_organization: str) -> str:
        try:
            key = self._derive_rp_key(recipient_organization)

            cipher = AES.new(key, AES.MODE_SIV)
            cipher.update(self.__aad)

            ciphertext, tag = cipher.encrypt_and_digest(message.encode('utf-8'))
            data = tag + ciphertext
            return base64.urlsafe_b64encode(data).decode('utf-8')
        except Exception as e:
            raise ValueError("Failed to encrypt data") from e


    def _decrypt_data(self, ciphertext: str, recipient_organization: str) -> str:
        """
        Decrypt the reverssible pseudonym to retrieve the original subject
        """
        try:
            key = self._derive_rp_key(recipient_organization)

            data = base64.urlsafe_b64decode(ciphertext)

            tag = data[:16]
            ct = data[16:]

            cipher = AES.new(key, AES.MODE_SIV)
            cipher.update(self.__aad)

            message = cipher.decrypt_and_verify(ct, tag)
            return message.decode('utf-8')
        except Exception as e:
            raise ValueError("Failed to decrypt pseudonym") from e
