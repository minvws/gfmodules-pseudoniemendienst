import base64
import hashlib
import hmac

class PseudonymService:
    def __init__(self, hmac_key: bytes) -> None:
        self.__hmac_key = hmac_key

    def exchange_irreversible_pseudonym(
        self,
        personal_id: str,
        recipient_organization: str,
        recipient_scope: str,
    ) -> str:
        message = f"{personal_id}|{recipient_organization}|{recipient_scope}".encode('utf-8')
        digest = hmac.new(self.__hmac_key, message, hashlib.sha256).digest()
        return base64.urlsafe_b64encode(digest).decode('utf-8')
