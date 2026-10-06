from dataclasses import dataclass

from app.models.auth.data import AuthorizationScope
from app.models.oin import Oin


@dataclass(frozen=True)
class AuthenticationClaims:
    organization_id: Oin
    client_organization_id: Oin
    client_common_name: str


@dataclass(frozen=True)
class AuthContext:
    claims: AuthenticationClaims
    audience: str
    scope: list[AuthorizationScope]
