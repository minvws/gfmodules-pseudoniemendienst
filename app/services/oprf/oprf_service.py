import base64
import pyoprf
from jwcrypto import jwk
from pydantic import BaseModel, Field, field_validator

from app.services.oprf.jwe_token import BlindJwe


class BlindRequest(BaseModel):
    encryptedPersonalId: str = Field(..., min_length=2)
    recipientOrganization: str = Field(..., min_length=2)
    recipientScope: str = Field(..., min_length=2)

    @field_validator("encryptedPersonalId")
    def validate_base64(cls, v: str) -> str:
        try:
            pad = "=" * ((4 - len(v) % 4) % 4)
            base64.urlsafe_b64decode(v +pad)
        except Exception as e:
            raise ValueError(f"must be base64url: {e}")

        return v


class OprfService:
    def __init__(self, server_key: str):
        self.__server_key = base64.urlsafe_b64decode(server_key)

    @staticmethod
    def generate_server_key() -> str:
        """
        Returns a base64 encoded pyoprf server key for evaluation
        """
        return base64.urlsafe_b64encode(pyoprf.keygen()).decode('ascii')

    def eval_blind(self, req: BlindRequest, pub_key: jwk.JWK) -> str:
        """
        Evaluate a blind and returns a JWE encrypted on the pubkey
        """
        bi = base64.urlsafe_b64decode(req.encryptedPersonalId)
        eval = pyoprf.evaluate(self.__server_key, bi)

        subject = "pseudonym:eval:" + base64.urlsafe_b64encode(eval).decode('utf-8')
        jwe = BlindJwe.build(
            audience=req.recipientOrganization,
            scope=req.recipientScope,
            subject=subject,
            pub_key=pub_key
        )

        return jwe
