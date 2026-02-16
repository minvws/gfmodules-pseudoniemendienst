import logging
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from fastapi import Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from starlette.requests import Request

from app.container import get_client_oauth_service
from app.models.ura import UraNumber
from app.services.client_oauth import ClientOAuthService

logger = logging.getLogger(__name__)


class OAuthError(Exception):
    """
    Raised for general OAuth2 errors.
    """

    def __init__(self, code: str, description: str, status_code: int = 400):
        super().__init__(description)
        self.code = code
        self.description = description
        self.status_code = status_code


@dataclass(frozen=True)
class AuthContext:
    """
    Authentication context extracted from the bearer token. This can be used in the route handlers
    """

    # List of claims from the token
    claims: Dict[str, Any]
    # OAuth scope
    scope: List[str]
    # URA number of the authenticated user
    ura_number: UraNumber


bearer = HTTPBearer(auto_error=False)


def get_auth_ctx(
    request: Request,
    creds: Optional[HTTPAuthorizationCredentials] = Depends(bearer),
    client_oauth_service: ClientOAuthService = Depends(get_client_oauth_service),
) -> AuthContext:
    if not client_oauth_service.enabled():
        ctx = AuthContext(
            claims={},
            scope=[],
            ura_number=client_oauth_service.override_ura_number(),
        )
        request.state.auth = ctx
        return ctx

    if creds is None or creds.scheme.lower() != "bearer":
        logger.error("missing or invalid bearer token")
        raise HTTPException(status_code=401, detail="Missing bearer token")

    try:
        claims = client_oauth_service.verify(request)
    except OAuthError as e:
        desc = getattr(e, "description", None) or str(e)
        status = getattr(e, "status_code", None) or 401

        logger.exception("oauth verification failed (status=%s): %r", status, desc)
        raise HTTPException(status_code=status, detail="Invalid or unauthorized request") from e

    ctx = AuthContext(
        claims=claims,
        scope=claims["scope"],
        ura_number=UraNumber(claims["sub"]),
    )
    request.state.auth = ctx
    return ctx
