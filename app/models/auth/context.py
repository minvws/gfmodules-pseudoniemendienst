from dataclasses import dataclass


@dataclass(frozen=True)
class AuthenticationClaims:
    oin: str


@dataclass(frozen=True)
class AuthContext:
    """
    Authentication context extracted from the bearer token. This can be used in the route handlers
    """

    # List of claims from the token
    claims: AuthenticationClaims
    # OAuth scope
    # audience intended for
    audience: str
