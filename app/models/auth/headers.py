from typing import Annotated, Any, Dict, Self

from fastapi import Request
from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.models.auth.data import AuthorizationScope
from app.models.oin import Oin


class AuthHeaders(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    organization_id: Annotated[Oin, Field(alias="x-gf-sub")]
    client_organization_id: Annotated[Oin, Field(alias="x-gf-act-sub")]
    client_organization_common_name: Annotated[str, Field(alias="x-gf-act-cn")]
    audience: Annotated[str, Field(alias="x-gf-audience")]
    scope: Annotated[str, Field(alias="x-gf-scope")]

    @field_validator("scope", mode="after")
    @classmethod
    def validate_scope(cls, data: str) -> str:
        entries = data.split()
        if not entries:
            raise ValueError("x-gf-scope must hold at least one scope")

        for entry in entries:
            try:
                _ = AuthorizationScope(entry)
            except ValueError as e:
                raise ValueError(f"Invalid scope {entry}: {e}")

        return data

    @classmethod
    def from_request(cls, req: Request) -> Self:
        headers = req.headers
        data: Dict[str, Any] = {}
        for name, field in cls.model_fields.items():
            header_name = field.alias or name
            value = headers.get(header_name)

            data[name] = value

        return cls(**data)
