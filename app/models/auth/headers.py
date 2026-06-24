from typing import Annotated, Any, Dict, Self

from fastapi import Request
from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.models.auth.data import AuthorizationScope
from app.models.oin import Oin


class AuthHeaders(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    oin: Annotated[str | None, Field(alias="x-gf-oin", default=None)]
    audience: Annotated[str, Field(alias="x-gf-audience")]
    scope: Annotated[str, Field(alias="x-gf-scope")]

    @field_validator("oin", mode="before")
    @classmethod
    def validate_oin_number(cls, data: str) -> str:
        try:
            oin = Oin(data)
        except ValueError as e:
            raise ValueError(f"Invalid OIN Number in header: {data}") from e

        return oin.value

    @field_validator("scope", mode="before")
    @classmethod
    def validate_scope(cls, data: Any) -> str:
        if not isinstance(data, str):
            raise ValueError(f"Invalid scope type in AuthorizationRoles: {data}")

        for entry in data.split():
            try:
                _ = AuthorizationScope(entry)
            except ValueError as e:
                raise ValueError(f"Invalid scope {entry}: {e}")

        return data

    @classmethod
    def from_request(cls, req: Request) -> Self:
        headers = req.headers
        data: Dict[str, Any] = {}
        optional_fields = ["oin", "x-gf-oin"]
        for name, field in cls.model_fields.items():
            header_name = field.alias or name
            value = headers.get(header_name)

            if header_name not in optional_fields and value is None:
                raise ValueError(f"{header_name} is required for {cls.__name__}")

            data[name] = value

        return cls(**data)
