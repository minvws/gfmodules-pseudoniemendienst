from typing import Annotated
import logging

from fastapi import Depends, HTTPException
from fastapi import Depends, HTTPException, Security
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer, SecurityScopes
from starlette.requests import Request

from app import container
from app.models.auth.context import AuthContext, AuthenticationClaims
from app.models.auth.data import AuthorizationScope
from app.models.auth.headers import AuthHeaders
from app.services.auth.header import AuthHeaderService

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
        scope=validated_auth_headers.scope,
    )
    request.state.auth = ctx
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
    ctx: AuthContext = Depends(get_auth_ctx),
) -> AuthContext:
    for scope in security_scopes.scopes:
        assert_scope(ctx, AuthorizationScope(scope))
    return ctx
