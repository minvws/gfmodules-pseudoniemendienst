import logging
from typing import Annotated, Any, Dict, Self

from fastapi import Request
from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.models.auth.data import AuthorizationScope
from app.models.oin import Oin

logger = logging.getLogger(__name__)


class AuthHeaders(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    organization_id: Annotated[Oin, Field(alias="x-gf-sub")]
    client_organization_id: Annotated[Oin, Field(alias="x-gf-act-sub")]
    client_organization_common_name: Annotated[str, Field(alias="x-gf-act-cn")]
    audience: Annotated[str, Field(alias="x-gf-audience")]
    scope: Annotated[list[AuthorizationScope], Field(alias="x-gf-scope", default_factory=list)]

    @field_validator("scope", mode="before")
    @classmethod
    def parse_scope(cls, data: Any) -> list[AuthorizationScope]:
        """Keep the scopes this service knows about and ignore the rest."""
        entries = data.split() if isinstance(data, str) else []

        granted = []
        for entry in entries:
            try:
                granted.append(AuthorizationScope(entry))
            except ValueError:
                logger.debug("ignoring scope %s, not a scope of this service", entry)

        if not granted:
            raise ValueError("x-gf-scope must hold at least one known scope")

        return granted

    @classmethod
    def from_request(cls, req: Request) -> Self:
        headers = req.headers
        data: Dict[str, Any] = {}
        for name, field in cls.model_fields.items():
            header_name = field.alias or name
            value = headers.get(header_name)

            data[name] = value

        return cls(**data)
