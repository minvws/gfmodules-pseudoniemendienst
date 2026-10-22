from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.models.oin import RecipientOrganizationOin

REVERSIBLE_PSEUDONYM_PREFIX = "pseudonym:reversible:"


class PseudonymExchangeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    recipientOrganization: RecipientOrganizationOin
    recipientScope: str = Field(
        ...,
        min_length=1,
        max_length=100,
        pattern=r"^[^|]+$",
        description="Scope of the recipient organization which the pseudonym is bound to.",
    )


class ReversiblePseudonymInputRequest(PseudonymExchangeRequest):
    model_config = ConfigDict(
        json_schema_extra={
            "examples": [
                {
                    "reversiblePseudonym": "AQAB....",
                    "recipientOrganization": "oin:00000099000000001000",
                    "recipientScope": "nvi",
                },
            ]
        },
    )

    reversiblePseudonym: str = Field(
        ...,
        description=(
            "A reversible pseudonym issued to the calling organization, as the "
            "bare value or as received in the JWE `subject` "
            "(`pseudonym:reversible:<value>`). The PRS reverses it first."
        ),
    )

    @field_validator("reversiblePseudonym")
    @classmethod
    def strip_reversible_prefix(cls, value: str) -> str:
        return value.removeprefix(REVERSIBLE_PSEUDONYM_PREFIX)


class PersonalIdInputRequest(PseudonymExchangeRequest):
    model_config = ConfigDict(
        json_schema_extra={
            "examples": [
                {
                    "personalId": "NL:bsn:950000012",
                    "recipientOrganization": "oin:00000099000000001000",
                    "recipientScope": "nvi",
                },
                {
                    "personalId": {
                        "landCode": "NL",
                        "type": "bsn",
                        "value": "950000012",
                    },
                    "recipientOrganization": "oin:00000099000000001000",
                    "recipientScope": "nvi",
                },
            ]
        },
    )

    personalId: str | dict[str, str] = Field(
        ...,
        description=(
            "Personal ID as `<landCode>:<type>:<value>` or as an object with "
            "`landCode`, `type` and `value`."
        ),
    )


ExchangeInputRequest = PersonalIdInputRequest | ReversiblePseudonymInputRequest
