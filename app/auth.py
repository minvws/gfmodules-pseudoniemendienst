import logging

from fastapi import Depends, HTTPException
from starlette.requests import Request

from app import container
from app.models.auth.context import AuthContext, AuthenticationClaims
from app.models.auth.headers import AuthHeaders
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
    )
    request.state.auth = ctx
    return ctx
