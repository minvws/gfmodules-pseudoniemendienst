import logging
from inspect import Signature, Parameter
from typing import Annotated

import inject
from fastapi import Depends, Header, HTTPException
from starlette.requests import Request
from app.db.entities.organization import Organization
from app.models.auth.context import AuthContext, AuthenticationClaims
from app.models.auth.headers import (
    AUTH_HEADER_X_GF_AUDIENCE,
    AUTH_HEADER_X_GF_OIN,
    AuthHeaders,
    MtlsHeaders,
)
from app.models.oin import Oin
from app.services.auth.header import AuthHeaderService
from app.services.org_service import OrgService


logger = logging.getLogger(__name__)


class AuthContextDependency:
    def __init__(self, include_auth_headers_in_openapi: bool) -> None:
        self.include_auth_headers_in_openapi = include_auth_headers_in_openapi
        self.__signature__ = self._build_signature()

    def _build_signature(self) -> Signature:
        return Signature(
            [
                Parameter(
                    name="request",
                    kind=Parameter.POSITIONAL_OR_KEYWORD,
                    annotation=Request,
                ),
                Parameter(
                    name="auth_headers_service",
                    kind=Parameter.POSITIONAL_OR_KEYWORD,
                    annotation=Annotated[
                        AuthHeaderService,
                        Depends(lambda: inject.instance(AuthHeaderService)),
                    ],
                ),
                Parameter(
                    name="oin",
                    kind=Parameter.POSITIONAL_OR_KEYWORD,
                    annotation=Oin,
                    default=Header(
                        alias=AUTH_HEADER_X_GF_OIN,
                        include_in_schema=self.include_auth_headers_in_openapi,
                    ),
                ),
                Parameter(
                    name="audience",
                    kind=Parameter.POSITIONAL_OR_KEYWORD,
                    annotation=str,
                    default=Header(
                        alias=AUTH_HEADER_X_GF_AUDIENCE,
                        include_in_schema=self.include_auth_headers_in_openapi,
                    ),
                ),
            ]
        )

    def __call__(
        self,
        request: Request,
        auth_headers_service: AuthHeaderService,
        oin: Oin,
        audience: str,
    ) -> AuthContext:
        validated_auth_headers = auth_headers_service.validate(
            AuthHeaders(oin=oin, audience=audience)
        )

        claims = AuthenticationClaims(
            oin=validated_auth_headers.oin,
        )
        ctx = AuthContext(
            claims=claims,
            audience=validated_auth_headers.audience,
        )
        request.state.auth = ctx
        return ctx


class MtlsHeadersDependency:
    def __init__(self, include_auth_headers_in_openapi: bool) -> None:
        self.include_auth_headers_in_openapi = include_auth_headers_in_openapi
        self.__signature__ = self._build_signature()

    def _build_signature(self) -> Signature:
        return Signature(
            [
                Parameter(
                    name="mtls_headers",
                    kind=Parameter.POSITIONAL_OR_KEYWORD,
                    annotation=Annotated[
                        MtlsHeaders,
                        Header(
                            include_in_schema=self.include_auth_headers_in_openapi,
                        ),
                    ],
                )
            ]
        )

    def __call__(self, mtls_headers: MtlsHeaders) -> MtlsHeaders:
        return mtls_headers


def _get_auth_ctx_from_request(request: Request) -> AuthContext:
    auth_ctx = getattr(request.state, "auth", None)
    if isinstance(auth_ctx, AuthContext):
        return auth_ctx

    raise HTTPException(status_code=401, detail="Unauthorized")


def authenticated_oin(
    auth_ctx: Annotated[AuthContext, Depends(_get_auth_ctx_from_request)],
) -> Oin:
    """Return the caller OIN from the validated auth context."""
    return auth_ctx.claims.oin


def authenticated_organization(
    auth_oin: Annotated[Oin, Depends(authenticated_oin)],
    org_service: Annotated[
        OrgService,
        Depends(lambda: inject.instance(OrgService)),
    ],
) -> Organization:
    """Return the authenticated organization resolved from the caller OIN."""
    organization = org_service.get_by_oin(auth_oin)
    if organization is None:
        logger.warning("organization for OIN %r not found", auth_oin.value)
        raise HTTPException(
            status_code=400, detail="organization for this OIN is not registered"
        )

    return organization
