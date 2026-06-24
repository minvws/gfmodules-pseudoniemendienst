from typing import Annotated, Any, Dict, Self

from fastapi import Request
from pydantic import BaseModel, ConfigDict, Field, field_validator
from app.models.oin import Oin


class AuthHeaders(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    oin: Annotated[str, Field(alias="x-gf-oin")]
    audience: Annotated[str, Field(alias="x-gf-audience")]

    @field_validator("oin", mode="before")
    @classmethod
    def validate_oin(cls, data: str) -> str:
        try:
            oin = Oin(data)
        except ValueError as e:
            raise ValueError(f"Invalid OIN Number in header: {data}") from e

        return oin.value

    @classmethod
    def from_request(cls, req: Request) -> Self:
        headers = req.headers
        data: Dict[str, Any] = {}
        for name, field in cls.model_fields.items():
            header_name = field.alias or name
            value = headers.get(header_name)

            data[name] = value

        return cls(**data)
