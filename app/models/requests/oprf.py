import base64
import binascii

from pydantic import BaseModel, Field, field_validator

from app.models.oin import RecipientOrganizationOin


class BlindRequest(BaseModel):
    encryptedPersonalId: str = Field(..., min_length=2)
    recipientOrganization: RecipientOrganizationOin
    recipientScope: str = Field(..., min_length=2)

    @field_validator("encryptedPersonalId")
    @classmethod
    def validate_base64(cls, v: str) -> str:
        try:
            pad = "=" * ((4 - len(v) % 4) % 4)
            normalized = v + pad
            base64.urlsafe_b64decode(normalized)
        except binascii.Error as e:
            raise ValueError(f"must be base64url: {e}") from e

        return normalized
