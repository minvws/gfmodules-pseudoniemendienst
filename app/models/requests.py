import base64
import logging
from datetime import datetime
from typing import Any, Literal, List

from pydantic import BaseModel, ConfigDict, model_validator, Field, field_validator

from app.personal_id import PersonalId
from app.services.pseudonym_service import PseudonymType
from app.rid import RidUsage

logger = logging.getLogger(__name__)
URA_PATTERN = r"^\d{8}$"


class RegisterRequest(BaseModel):
    scope: List[str]


class OrgRequest(BaseModel):
    ura: str = Field(..., pattern=URA_PATTERN)
    name: str = Field(..., min_length=5, max_length=50)
    max_key_usage: RidUsage

    @field_validator("ura")
    def ura_must_be_numbers(cls, v: Any) -> Any:
        if not v.isdigit():
            logger.warning("URA must contain only digits (got %s)", v)
            raise ValueError("URA must contain 8 digits")
        return v


class HsmKeyVersionRequest(BaseModel):
    ura: str = Field(..., pattern=URA_PATTERN)
    from_dt: datetime | None = None
    until_dt: datetime | None = None


class HsmKeyVersionUpdateRequest(BaseModel):
    until_dt: datetime | None = None
    removed: bool = False


class RidReceiveRequest(BaseModel):
    rid: str
    recipientOrganization: str
    recipientScope: str
    pseudonymType: Literal["rp", "irp", "bsn"]


class BlindRequest(BaseModel):
    encryptedPersonalId: str = Field(..., min_length=2)
    recipientOrganization: str = Field(..., min_length=2)
    recipientScope: str = Field(..., min_length=2)

    @field_validator("encryptedPersonalId")
    def validate_base64(cls, v: str) -> str:
        try:
            pad = "=" * ((4 - len(v) % 4) % 4)
            normalized = v + pad
            base64.urlsafe_b64decode(normalized)
        except Exception as e:
            raise ValueError(f"must be base64url: {e}")

        return normalized


class RidExchangeRequest(BaseModel):
    personalId: Any
    recipientOrganization: str
    recipientScope: str
    ridUsage: Any

    @model_validator(mode="before")
    @classmethod
    def convert_personal_id(cls, data: dict[str, Any]) -> dict[str, Any]:
        pid = data.get("personalId")
        if isinstance(pid, str):
            data["personalId"] = PersonalId.from_str(pid)
        if isinstance(pid, dict):
            data["personalId"] = PersonalId.from_dict(pid)

        return data

    @model_validator(mode="before")
    @classmethod
    def convert_rid_usage(cls, data: dict[str, Any]) -> dict[str, Any]:
        ridUsage = data.get("ridUsage")
        if isinstance(ridUsage, str):
            data["ridUsage"] = RidUsage(ridUsage)

        return data


class ExchangeRequest(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    personalId: Any
    recipientOrganization: str
    recipientScope: str = Field(..., min_length=1, max_length=100)
    pseudonymType: PseudonymType

    @model_validator(mode="before")
    @classmethod
    def convert_personal_id(cls, data: dict[str, Any]) -> dict[str, Any]:
        pid = data.get("personalId")
        if isinstance(pid, str):
            data["personalId"] = PersonalId.from_str(pid)
        if isinstance(pid, dict):
            data["personalId"] = PersonalId.from_dict(pid)
        return data


class InputRequest(BaseModel):
    personalId: Any

    @model_validator(mode="before")
    @classmethod
    def convert_personal_id(cls, data: dict[str, Any]) -> dict[str, Any]:
        pid = data.get("personalId")
        if isinstance(pid, str):
            data["personalId"] = PersonalId.from_str(pid)
        if isinstance(pid, dict):
            data["personalId"] = PersonalId.from_dict(pid)

        return data


class ReceiverRequest(BaseModel):
    blind_factor: str
    jwe: str
    priv_key_pem: str

    @model_validator(mode="before")
    @classmethod
    def validate_jwe(cls, data: dict[str, Any]) -> dict[str, Any]:
        # Check if JWE is actually a jwe token
        jwe_token = data.get("jwe")
        if not isinstance(jwe_token, str) or len(jwe_token.split(".")) != 5:
            logger.warning("invalid JWE token format: %s", jwe_token)
            raise ValueError("Invalid JWE token")
        return data

    @model_validator(mode="before")
    @classmethod
    def validate_priv_key_pem(cls, data: dict[str, Any]) -> dict[str, Any]:
        priv_key_pem = data.get("priv_key_pem")
        if not isinstance(priv_key_pem, str) or not priv_key_pem.startswith(
            "-----BEGIN PRIVATE KEY-----"
        ):
            logger.warning("invalid private key PEM format")
            raise ValueError("Invalid private key PEM format")
        return data


class JweReceiverRequest(BaseModel):
    jwe: str
    priv_key_pem: str

    @model_validator(mode="before")
    @classmethod
    def validate_jwe(cls, data: dict[str, Any]) -> dict[str, Any]:
        # Check if JWE is actually a jwe token
        jwe_token = data.get("jwe")
        if not isinstance(jwe_token, str) or len(jwe_token.split(".")) != 5:
            logger.warning("invalid JWE token format: %s", jwe_token)
            raise ValueError("Invalid JWE token")
        return data

    @model_validator(mode="before")
    @classmethod
    def validate_priv_key_pem(cls, data: dict[str, Any]) -> dict[str, Any]:
        priv_key_pem = data.get("priv_key_pem")
        if not isinstance(priv_key_pem, str) or not priv_key_pem.startswith(
            "-----BEGIN PRIVATE KEY-----"
        ):
            logger.warning("invalid private key PEM format")
            raise ValueError("Invalid private key PEM format")
        return data
