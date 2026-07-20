from typing import Annotated, Any, Dict, Self

from fastapi import Request
from pydantic import BaseModel, ConfigDict, Field


class AuthHeaders(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    sub: Annotated[str, Field(alias="x-gf-sub")]
    act_sub: Annotated[str, Field(alias="x-gf-act-sub")]
    act_cn: Annotated[str, Field(alias="x-gf-act-cn")]
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
