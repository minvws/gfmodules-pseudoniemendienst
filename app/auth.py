import logging
from typing import Annotated

from fastapi import Depends, HTTPException, Security
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from starlette.requests import Request

from app import container
from app.models.auth.context import AuthContext, AuthenticationClaims
from app.models.auth.headers import AuthHeaders
from app.models.oin import Oin
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
    # We don't do anything with it, but it's just a marker that allows swagger to add the authorize button
    _credentials: Annotated[HTTPAuthorizationCredentials | None, Security(bearer_auth)],
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
        organization_id=Oin(validated_auth_headers.organization_id),
        client_organization_id=Oin(validated_auth_headers.client_organization_id),
        client_common_name=validated_auth_headers.client_organization_common_name,
    )
    ctx = AuthContext(
        claims=claims,
        audience=validated_auth_headers.audience,
    )
    request.state.auth = ctx
    return ctx
