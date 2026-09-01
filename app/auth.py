import logging
from typing import Annotated

from fastapi import Depends, HTTPException, Security
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer, SecurityScopes
from starlette.requests import Request

from app import container
from app.db.entities.organization import Organization
from app.models.auth.context import AuthContext, AuthenticationClaims
from app.models.auth.data import AuthorizationScope
from app.models.auth.headers import AuthHeaders
from app.services.auth.header import AuthHeaderService
from app.services.org_service import OrgService

logger = logging.getLogger(__name__)

bearer_auth = HTTPBearer(
    scheme_name="BearerAuth",
    description="OAuth access token. Swagger will send it as: Authorization: Bearer <token>",
    # Actual authentication happens through the proxy-verified headers below;
    # this scheme only exists so swagger shows the authorize button.
    auto_error=False,
)


def get_auth_ctx(
    request: Request,
    # We don't do anything with it, but it's just a marker that allows swagger to add the authorize button
    _credentials: Annotated[HTTPAuthorizationCredentials | None, Security(bearer_auth)],
    auth_headers_service: AuthHeaderService = Depends(
        container.get_auth_headers_service
    ),
) -> AuthContext:
    try:
        auth_headers = AuthHeaders.from_request(request)
    except ValueError as e:
        logger.exception(f"Invalid Authorization Headers in request: {e}")
        raise HTTPException(status_code=403, detail="Unauthorized request")

    validated_auth_headers = auth_headers_service.validate(auth_headers)
    claims = AuthenticationClaims(
        organization_id=validated_auth_headers.organization_id,
        client_organization_id=validated_auth_headers.client_organization_id,
        client_common_name=validated_auth_headers.client_organization_common_name,
    )
    ctx = AuthContext(
        claims=claims,
        audience=validated_auth_headers.audience,
        scope=[AuthorizationScope(s) for s in validated_auth_headers.scope.split()],
    )
    request.state.auth = ctx
    return ctx


def get_auth_context(request: Request) -> AuthContext:
    ctx: AuthContext | None = getattr(request.state, "auth", None)
    if ctx is None:
        logger.error("no authentication context on request for %s", request.url.path)
        raise HTTPException(status_code=403, detail="Unauthorized request")
    return ctx


def assert_scope(ctx: AuthContext, required: AuthorizationScope) -> AuthContext:
    if required not in ctx.scope:
        granted = " ".join(s.value for s in ctx.scope)
        logger.warning(
            "scope %s missing for request, granted scopes: %s", required.value, granted
        )
        raise HTTPException(status_code=403, detail="Unauthorized request")
    return ctx


def require_scopes(
    security_scopes: SecurityScopes,
    _credentials: Annotated[HTTPAuthorizationCredentials | None, Security(bearer_auth)],
    ctx: AuthContext = Depends(get_auth_context),
) -> AuthContext:
    for scope in security_scopes.scopes:
        assert_scope(ctx, AuthorizationScope(scope))
    return ctx


def authenticated_organization(
    auth_ctx: Annotated[AuthContext, Depends(get_auth_ctx)],
    org_service: Annotated[OrgService, Depends(container.get_org_service)],
) -> Organization:
    organization = org_service.get_by_oin(auth_ctx.claims.organization_id)
    if organization is None:
        logger.warning(
            "organization for oin=%s not found", auth_ctx.claims.organization_id
        )
        raise HTTPException(status_code=401, detail="unauthorized")
    return organization
