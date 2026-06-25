from typing import Annotated, Any, Dict, Self

from fastapi import Request
from pydantic import BaseModel, ConfigDict, Field
from app.models.oin import Oin


class AuthHeaders(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    oin: Annotated[Oin, Field(alias="x-gf-oin")]
    audience: Annotated[str, Field(alias="x-gf-audience")]

    @classmethod
    def from_request(cls, req: Request) -> Self:
        headers = req.headers
        data: Dict[str, Any] = {}
        for name, field in cls.model_fields.items():
            header_name = field.alias or name
            value = headers.get(header_name)

            data[name] = value

        return cls(**data)
