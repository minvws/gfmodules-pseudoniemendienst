import logging
from typing import Annotated

import gfmodules.logging as gflog
from fastapi import Depends, Security
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer, SecurityScopes
from pydantic import ValidationError
from starlette.requests import Request

from app import container
from app.exceptions.access import UnauthorizedRequestError
from app.logging.events import Log
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


def _header_errors(error: ValueError) -> str:
    if not isinstance(error, ValidationError):
        return type(error).__name__
    fields = AuthHeaders.model_fields
    return ", ".join(
        f"{fields[str(detail['loc'][0])].alias}: {detail['type']}"
        for detail in error.errors()
    )


def get_auth_ctx(
    request: Request,
    auth_headers_service: Annotated[
        AuthHeaderService, Depends(container.get_auth_headers_service)
    ],
) -> AuthContext:
    try:
        auth_headers = AuthHeaders.from_request(request)
    except ValueError as e:
        gflog.emit(
            logger,
            Log.MISSING_AUTHORIZATION_HEADER,
            "invalid authorization headers in request",
            fields={"error_reason": _header_errors(e)},
        )
        raise UnauthorizedRequestError() from e

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
        gflog.emit(
            logger,
            Log.AUTHORIZATION_DENIED,
            f"scope {required.value} missing for request, granted scopes: {granted}",
            fields={
                "acting_organization_identifier": str(
                    ctx.claims.client_organization_id
                ),
                "represented_organization_identifier": str(ctx.claims.organization_id),
                "requested_operation": required.value,
                "error_reason": "scope_missing",
            },
        )
        raise UnauthorizedRequestError()
    return ctx


def require_scopes(
    security_scopes: SecurityScopes,
    _credentials: Annotated[HTTPAuthorizationCredentials | None, Security(bearer_auth)],
    ctx: Annotated[AuthContext, Depends(get_auth_ctx)],
) -> AuthContext:
    for scope in security_scopes.scopes:
        assert_scope(ctx, AuthorizationScope(scope))
    return ctx
