import logging

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from fastapi import Depends, HTTPException
from starlette.requests import Request
from starlette.responses import Response
from starlette.types import ASGIApp

from app import container
from app.db.entities.organization import Organization
from app.models.auth.context import AuthContext, AuthenticationClaims
from app.models.auth.headers import (
    AUTH_HEADER_X_GF_AUDIENCE,
    AUTH_HEADER_X_GF_OIN,
    AuthHeaders,
)
from app.models.oin import Oin
from app.services.auth.header import AuthHeaderService
from app.services.org_service import OrgService

logger = logging.getLogger(__name__)


def apply_development_auth_header_overrides(
    request: Request,
    override_oin: str | None,
    override_audience: str | None,
) -> None:
    if override_oin is not None and request.headers.get(AUTH_HEADER_X_GF_OIN) is None:
        request.scope["headers"].append(
            (AUTH_HEADER_X_GF_OIN.encode("ascii"), override_oin.encode("ascii"))
        )

    if (
        override_audience is not None
        and request.headers.get(AUTH_HEADER_X_GF_AUDIENCE) is None
    ):
        request.scope["headers"].append(
            (
                AUTH_HEADER_X_GF_AUDIENCE.encode("ascii"),
                override_audience.encode("ascii"),
            )
        )


class DevelopmentAuthHeaderMiddleware(BaseHTTPMiddleware):
    def __init__(
        self,
        app: ASGIApp,
        override_oin: str | None,
        override_audience: str | None,
    ) -> None:
        super().__init__(app)
        self.override_oin = override_oin
        self.override_audience = override_audience

    async def dispatch(
        self,
        request: Request,
        call_next: RequestResponseEndpoint,
    ) -> Response:
        apply_development_auth_header_overrides(
            request,
            override_oin=self.override_oin,
            override_audience=self.override_audience,
        )
        return await call_next(request)


def get_auth_ctx(
    request: Request,
    auth_headers_service: AuthHeaderService = Depends(
        container.get_auth_headers_service
    ),
) -> AuthContext:
    try:
        auth_headers = AuthHeaders.from_request(request)
    except Exception as e:
        logger.exception(f"Invalid authorization headers in request: {e}")
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


def authenticated_organization(
    auth_ctx: AuthContext = Depends(get_auth_ctx),
    org_service: OrgService = Depends(container.get_org_service),
) -> Organization:
    """Return the authenticated organization resolved from the caller OIN."""
    organization = org_service.get_by_oin(auth_ctx.claims.oin)
    if organization is None:
        logger.warning("organization for OIN %r not found", auth_ctx.claims.oin.value)
        raise HTTPException(
            status_code=400, detail="organization for this OIN is not registered"
        )

    return organization
