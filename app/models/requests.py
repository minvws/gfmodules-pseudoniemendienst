from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, model_validator

from app.personal_id import PersonalId
from app.services.pseudonym_service import PseudonymType
from app.rid import RidUsage

class OrgRequest(BaseModel):
    ura: str
    name: str
    max_key_usage: RidUsage

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
    recipientScope: str
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
