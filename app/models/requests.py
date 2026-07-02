import base64
import logging
from datetime import datetime, timezone
from typing import Any, Literal, List

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.models.oin import RecipientOrganizationOin
from app.personal_id import PersonalId
from app.services.pseudonym_service import PseudonymType
from app.rid import RidUsage

logger = logging.getLogger(__name__)


class RegisterRequest(BaseModel):
    scope: List[str]
    key_id: str | None


class HsmKeyVersionRequest(BaseModel):
    model_config = ConfigDict(
        json_schema_extra={
            "x-temporal-constraints": [
                "from_dt is validated against the current UTC timestamp",
                "until_dt must be at or after from_dt (or current UTC when from_dt is omitted)",
                "timezone offset is required for from_dt and until_dt (RFC3339 date-time format)",
            ],
            "x-supported-timezones": "Any RFC3339 timezone offset (for example: +01:00, -05:00, or Z)",
            "examples": [
                {
                    "from_dt": "2026-01-01T00:00:00+02:00",
                    "until_dt": "2027-01-01T00:00:00+01:00",
                },
                {
                    "from_dt": "2026-01-01T00:00:00Z",
                    "until_dt": None,
                },
            ],
        }
    )

    from_dt: datetime | None = Field(
        default=None,
        description=(
            "Start of the key validity window as an ISO-8601 datetime. If omitted, "
            "the server sets it to now and this value must not be in the past."
            " Values must include an explicit timezone offset (RFC3339 date-time)."
        ),
        json_schema_extra={
            "examples": [
                "2026-01-01T00:00:00+02:00",
                "2026-01-01T00:00:00Z",
            ]
        },
    )
    until_dt: datetime | None = Field(
        default=None,
        description=(
            "End of the key validity window as an ISO-8601 datetime. If provided, "
            "it must be at or after `from_dt` (or after the implicit now if "
            "from_dt is omitted). An explicit timezone offset is required (RFC3339"
            " date-time)."
        ),
        json_schema_extra={
            "examples": [
                "2027-01-01T00:00:00+01:00",
                "2027-01-01T00:00:00Z",
                None,
            ]
        },
    )

    @field_validator("from_dt", "until_dt")
    @classmethod
    def require_timezone(cls, value: datetime | None) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None:
            raise ValueError("datetime values must include a timezone offset")
        return value

    @model_validator(mode="after")
    def validate_temporal_window(self) -> "HsmKeyVersionRequest":
        now = datetime.now(timezone.utc)
        effective_from_dt = self.from_dt or now

        if self.from_dt and self.from_dt < now:
            raise ValueError("from_dt must not be earlier than now")

        if self.until_dt and self.until_dt < effective_from_dt:
            raise ValueError("until_dt must not be earlier than from_dt")

        return self


class HsmKeyVersionUpdateRequest(BaseModel):
    model_config = ConfigDict(
        json_schema_extra={
            "x-temporal-constraints": [
                "timezone offset is required for until_dt (RFC3339 date-time format)",
            ],
            "examples": [
                {"until_dt": "2027-01-01T00:00:00+03:00"},
                {"until_dt": None},
            ],
        }
    )

    until_dt: datetime | None = Field(
        default=None,
        description=(
            "New end datetime for the key version as an ISO-8601 timestamp, or null "
            "to clear the existing value. Must include an explicit timezone "
            "offset (RFC3339 date-time)."
        ),
        json_schema_extra={
            "examples": [
                "2027-01-01T00:00:00+03:00",
                "2027-01-01T00:00:00Z",
                None,
            ]
        },
    )

    @field_validator("until_dt")
    @classmethod
    def require_timezone(cls, value: datetime | None) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None:
            raise ValueError("datetime values must include a timezone offset")
        return value


class RidReceiveRequest(BaseModel):
    rid: str
    recipientOrganization: RecipientOrganizationOin
    recipientScope: str
    pseudonymType: Literal["rp", "irp", "bsn"]


class BlindRequest(BaseModel):
    encryptedPersonalId: str = Field(..., min_length=2)
    recipientOrganization: RecipientOrganizationOin
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
    recipientOrganization: RecipientOrganizationOin
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
    recipientOrganization: RecipientOrganizationOin
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


class ReceiverRequest(JweReceiverRequest):
    blind_factor: str
