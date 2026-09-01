from typing import Annotated, Any, Dict, Self

from fastapi import Request
from pydantic import BaseModel, ConfigDict, Field

from app.models.oin import Oin


class AuthHeaders(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    organization_id: Annotated[Oin, Field(alias="x-gf-sub")]
    client_organization_id: Annotated[Oin, Field(alias="x-gf-act-sub")]
    client_organization_common_name: Annotated[str, Field(alias="x-gf-act-cn")]
    audience: Annotated[str, Field(alias="x-gf-audience")]
    # Space-separated OAuth scopes from the token, forwarded by the proxy.
    # Optional: tokens without a scope claim arrive as an empty or absent
    # header; scope requirements are enforced per route via require_scope.
    scope: Annotated[str | None, Field(alias="x-gf-scope", default=None)]

    @classmethod
    def from_request(cls, req: Request) -> Self:
        headers = req.headers
        data: Dict[str, Any] = {}
        for name, field in cls.model_fields.items():
            header_name = field.alias or name
            value = headers.get(header_name)

            data[name] = value

        return cls(**data)
