from typing import Any

from pydantic import BaseModel, ConfigDict, model_validator

from app.personal_id import PersonalId
from app.services.pseudonym_service import PseudonymType


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
    personalId: str


class ReceiverRequest(BaseModel):
    blind_factor: str
    jwe: str
    priv_key_pem: str


class JweReceiverRequest(BaseModel):
    jwe: str
    priv_key_pem: str
