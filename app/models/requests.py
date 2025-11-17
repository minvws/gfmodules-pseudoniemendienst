from typing import Any, Literal, List

from pydantic import BaseModel, ConfigDict, model_validator, Field, field_validator

from app.personal_id import PersonalId
from app.services.pseudonym_service import PseudonymType
from app.rid import RidUsage


class RegisterRequest(BaseModel):
    scope: List[str]

class OrgRequest(BaseModel):
    ura: str = Field(..., pattern=r"^\d{8}$")
    name: str = Field(..., min_length=5, max_length=50)
    max_key_usage: RidUsage

    @field_validator("ura")
    def ura_must_be_numbers(cls, v: Any) -> Any:
        if not v.isdigit():
            raise ValueError("URA must contain 8 digits")
        return v

class RidReceiveRequest(BaseModel):
    rid: str
    recipientOrganization: str
    recipientScope: str
    pseudonymType: Literal['rp', 'irp', 'bsn']


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
        print(pid)
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
        if not isinstance(jwe_token, str) or len(jwe_token.split('.')) != 5:
            raise ValueError("Invalid JWE token")
        return data

    @model_validator(mode="before")
    @classmethod
    def validate_priv_key_pem(cls, data: dict[str, Any]) -> dict[str, Any]:
        priv_key_pem = data.get("priv_key_pem")
        if not isinstance(priv_key_pem, str) or not priv_key_pem.startswith("-----BEGIN PRIVATE KEY-----"):
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
        if not isinstance(jwe_token, str) or len(jwe_token.split('.')) != 5:
            raise ValueError("Invalid JWE token")
        return data

    @model_validator(mode="before")
    @classmethod
    def validate_priv_key_pem(cls, data: dict[str, Any]) -> dict[str, Any]:
        priv_key_pem = data.get("priv_key_pem")
        if not isinstance(priv_key_pem, str) or not priv_key_pem.startswith("-----BEGIN PRIVATE KEY-----"):
            raise ValueError("Invalid private key PEM format")
        return data
