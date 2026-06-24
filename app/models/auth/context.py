from dataclasses import dataclass
from typing import List

from app.models.auth.data import AuthorizationScope


@dataclass(frozen=True)
class AuthenticationClaims:
    oin: str | None = None


@dataclass(frozen=True)
class AuthContext:
    """
    Authentication context extracted from the bearer token. This can be used in the route handlers
    """

    # List of claims from the token
    claims: AuthenticationClaims
    # OAuth scope
    scope: List[AuthorizationScope]
    # audience intended for
    audience: str
