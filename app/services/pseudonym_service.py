import base64
import hashlib
import hmac
import logging

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from app.personal_id import PersonalId

logger = logging.getLogger(__name__)


def hkdf_derive(master_key: bytes, info: bytes, length: int = 32) -> bytes:
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=None,
        info=info,
    )
    return hkdf.derive(master_key)


class PseudonymService:
    def __init__(self, master_key: bytes) -> None:
        # Derive the necessary keys from the master key
        self.__irp_hmac_key = hkdf_derive(master_key, b"prs:irp:hmac", 32)

    def generate_irreversible_pseudonym(
        self,
        personal_id: PersonalId,
        recipient_organization: str,
        recipient_scope: str,
    ) -> str:
        """
        Generate a deterministic irreversible pseudonym
        """
        subject = self._get_subject(
            personal_id, recipient_organization, recipient_scope
        )
        digest = hmac.new(
            self.__irp_hmac_key, subject.encode("utf-8"), hashlib.sha256
        ).digest()
        return base64.urlsafe_b64encode(digest).decode("utf-8")

    def _get_subject(
        self,
        personal_id: PersonalId,
        recipient_organization: str,
        recipient_scope: str,
    ) -> str:
        """
        Construct the subject string for pseudonym generation.
        """
        if "|" in recipient_organization or "|" in recipient_scope:
            logger.error("invalid characters in recipient organization or scope")
            raise ValueError("Invalid characters in input")

        return f"{personal_id.as_str()}|{recipient_organization}|{recipient_scope}"
