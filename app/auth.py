import logging

from fastapi import Depends, HTTPException
from starlette.requests import Request

from app import container
from app.models.auth.context import AuthContext, AuthenticationClaims
from app.models.auth.headers import AuthHeaders
from app.models.oin import Oin
from app.services.auth.header import AuthHeaderService

logger = logging.getLogger(__name__)


def get_auth_ctx(
    request: Request,
    auth_headers_service: AuthHeaderService = Depends(
        container.get_auth_headers_service
    ),
) -> AuthContext:
    try:
        auth_headers = AuthHeaders.from_request(request)
    except ValueError as e:
        logger.exception(f"Inavalid Authorization Headers in request: {e}")
        raise HTTPException(status_code=403, detail="Unauthorized request")

    validated_auth_headers = auth_headers_service.validate(auth_headers)
    claims = AuthenticationClaims(
        oin=validated_auth_headers.oin,
    )
    ctx = AuthContext(
        claims=claims,
        audience=validated_auth_headers.audience,
    )
    request.state.auth = ctx
    return ctx


def authenticated_oin(auth_ctx: AuthContext = Depends(get_auth_ctx)) -> Oin:
    """Return the caller OIN from the validated auth context."""
    return auth_ctx.claims.oin


def require_matching_oin(
    oin: Oin,
    auth_oin: Oin = Depends(authenticated_oin),
) -> Oin:
    """Require a path/body OIN to match the caller-authenticated OIN."""
    if oin != auth_oin:
        raise HTTPException(status_code=403, detail="forbidden")
    return oin
