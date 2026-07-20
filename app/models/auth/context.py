from dataclasses import dataclass

from app.models.oin import Oin


@dataclass(frozen=True)
class AuthenticationClaims:
    sub: Oin
    act_sub: str
    act_cn: str


@dataclass(frozen=True)
class AuthContext:
    """
    Authentication context extracted from the bearer token. This can be used in the route handlers
    """

    # List of claims from the token
    claims: AuthenticationClaims
    # audience intended for
    audience: str
