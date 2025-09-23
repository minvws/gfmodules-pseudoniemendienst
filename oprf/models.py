from pydantic import BaseModel, Field, field_validator
import base64


class PseudonymRequest(BaseModel):
    bf: str = Field(..., min_length=2)
    jwe: str = Field(..., min_length=2)

    @field_validator("jwe")
    def validate_jwe(cls, v: str) -> str:
        parts = v.split(".")
        if len(parts) != 5:
            raise ValueError("must be a JWE with 5 parts")

        return v


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
