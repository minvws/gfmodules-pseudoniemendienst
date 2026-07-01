from typing import Annotated, Any, Dict, Final, Self

from fastapi import Request
from pydantic import BaseModel, ConfigDict, Field
from app.models.oin import Oin


AUTH_HEADER_X_GF_OIN: Final[str] = "x-gf-oin"
AUTH_HEADER_X_GF_AUDIENCE: Final[str] = "x-gf-audience"


class AuthHeaders(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    oin: Annotated[Oin, Field(alias=AUTH_HEADER_X_GF_OIN)]
    audience: Annotated[str, Field(alias=AUTH_HEADER_X_GF_AUDIENCE)]

    @classmethod
    def from_request(cls, req: Request) -> Self:
        headers = req.headers
        data: Dict[str, Any] = {}
        for name, field in cls.model_fields.items():
            header_name = field.alias or name
            value = headers.get(header_name)

            data[name] = value

        return cls(**data)
