from pydantic import BaseModel, ConfigDict, Field


class OrganizationPublicKeyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    domain: str = Field(...)
    jws: str = Field(..., min_length=32)
    key_id: str | None = None
