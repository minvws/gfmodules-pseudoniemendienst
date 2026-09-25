import json
import logging
import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import gfmodules.logging as gflog
import uvicorn
from fastapi import Depends, FastAPI, Request, Security
from fastapi.responses import JSONResponse
from fastapi.security import APIKeyHeader
from gfmodules.logging.middleware import (
    RequestContextMiddleware,
    restore_request_context,
)

from app.auth import get_auth_ctx, require_scopes
from app.config import _ENVIRONMENT_CONFIG_PATH_NAME, _PATH, get_config
from app.logging.events import Log
from app.models.auth.data import SCOPE_DESCRIPTIONS, AuthorizationScope
from app.routers.administration.hsm_key_version import router as hsm_key_version_router
from app.routers.administration.key import router as key_router
from app.routers.default import router as default_router
from app.routers.errors import install_domain_error_handler
from app.routers.exchange import router as exchange_router
from app.routers.health import router as health_router
from app.routers.oprf import router as oprf_router
from app.routers.reversible_pseudonym import router as reversible_pseudonym_router
from app.routers.saml_exchange import router as saml_exchange_router
from app.routers.test_oprf import router as test_oprf_router

logger = logging.getLogger(__name__)

API_DESCRIPTION = """
The Pseudoniemendienst (PRS) lets parties exchange data about a person without
sharing their BSN. Instead of a BSN, parties exchange **reversible pseudonyms** and **pseudonyms**
that are scoped to a recipient organization and scope.

A recipient organization is always identified by a OIN in the form
`oin:<20 digits>` (e.g. `oin:00000099000000001000`).

The endpoints are grouped into the sections below. Most sections are protected by
mutual TLS (mTLS); the calling organization and, where relevant, its public key
are derived from the client certificate.
"""

# OpenAPI extension to describe the possible authorization scopes. See https://swagger.io/docs/specification/v3_0/openapi-extensions/
SCOPES_EXTENSION = "x-authorization-scopes"


GF_HEADER_SECURITY_SCHEMES: dict[str, dict[str, str]] = {
    "AudienceHeader": {
        "type": "apiKey",
        "in": "header",
        "name": "x-gf-audience",
        "description": "The accepted audience, e.g.: `https://localhost:6502`",
    },
    "SubjectHeader": {
        "type": "apiKey",
        "in": "header",
        "name": "x-gf-sub",
        "description": "The organization name (should be an OIN), e.g.: `00000003123456780000`",
    },
    "ActorCnHeader": {
        "type": "apiKey",
        "in": "header",
        "name": "x-gf-act-cn",
        "description": "The client's (actor) CN, e.g.: `www.example.com`",
    },
    "ActorSubjectHeader": {
        "type": "apiKey",
        "in": "header",
        "name": "x-gf-act-sub",
        "description": "The client's (actor) subject (should be an OIN), e.g.: `00000003123456780000`",
    },
}

BEARER_SECURITY_SCHEME: dict[str, dict[str, str]] = {
    "BearerAuth": {
        "type": "http",
        "scheme": "bearer",
        "bearerFormat": "JWT",  # Optional, helps UI display context
    }
}


def install_openapi_extensions(fastapi: FastAPI, document_gf_headers: bool) -> None:
    """
    Extend the generated OpenAPI schema with the authorization scope catalogue
    and the security schemes. Wraps FastAPI's own schema builder so the title,
    description, tags and root path configured on the app are preserved.
    """
    build_schema = fastapi.openapi

    def openapi() -> dict[str, Any]:
        if fastapi.openapi_schema:
            return fastapi.openapi_schema

        schema = build_schema()

        schema[SCOPES_EXTENSION] = {
            scope.value: SCOPE_DESCRIPTIONS[scope] for scope in AuthorizationScope
        }

        security_schemes = schema.setdefault("components", {}).setdefault(
            "securitySchemes", {}
        )
        security_schemes.update(
            GF_HEADER_SECURITY_SCHEMES
            if document_gf_headers
            else BEARER_SECURITY_SCHEME
        )

        # Apply the security schemes globally in the schema (UI only) so the
        # "lock" icon appears on all endpoints, WITHOUT enforcing it in the code.
        schema["security"] = [{name: [] for name in security_schemes}]

        fastapi.openapi_schema = schema
        return schema

    fastapi.openapi = openapi  # type: ignore[method-assign]


GF_HEADERS = [
    "x-gf-sub",
    "x-gf-act-sub",
    "x-gf-act-cn",
    "x-gf-audience",
    "x-gf-scope",
]


def gf_header_params(document_gf_headers: bool) -> list[Any]:
    if not document_gf_headers:
        return []

    return [
        Security(APIKeyHeader(name=header, scheme_name=header, auto_error=False))
        for header in GF_HEADERS
    ]


# Section (tag) metadata shown in the Swagger UI / OpenAPI schema. The order here
# determines the order in which the sections are rendered.
TAGS_METADATA = [
    {
        "name": "Service Information",
        "description": (
            "Public, unauthenticated endpoints reporting the service version and "
            "health status. Useful for load balancers, monitoring, and smoke tests."
        ),
    },
    {
        "name": "Key Registration Services",
        "description": (
            "Register and manage the public keys that pseudonyms and reversible pseudonyms are "
            "encrypted to. The organization and its public key are derived from the "
            "mTLS client certificate, so they are not part of the request body."
        ),
    },
    {
        "name": "Key Version Services",
        "description": (
            "Manage the HSM key versions used to derive pseudonyms. Multiple "
            "versions can be active at once to support key rotation, where older "
            "versions remain available alongside the latest one."
        ),
    },
    {
        "name": "OPRF Services",
        "description": (
            "Evaluate a blinded personal identifier using the Oblivious "
            "Pseudo-Random Function and return a JWE (encrypted to the recipient's "
            "public key) containing the evaluation for the active key version(s)."
        ),
    },
]

# Section (tag) metadata for the exchange routes. Only included in the OpenAPI
# schema when `enable_exchange_services_routes` is set, matching when these routes
# are mounted.
EXCHANGE_TAGS_METADATA = [
    {
        "name": "Exchange Services",
        "description": (
            "Exchange a personal ID for a reversible pseudonym or reversible pseudonyms targeted at a "
            "recipient organization/scope, and redeem a previously issued reversible pseudonyms for a "
            "pseudonym (or the BSN, when permitted by both the reversible pseudonyms usage and the "
            "organization's `max_key_usage`). Exchanges that involve a personal ID "
            "require both the calling and the recipient organization to be "
            "authorized for that personal ID type by a PRS administrator."
        ),
    },
]

# Section (tag) metadata for the SAML exchange routes. Only included in the
# OpenAPI schema when `enable_saml_exchange_routes` is set, matching when these
# routes are mounted.
SAML_EXCHANGE_TAGS_METADATA = [
    {
        "name": "SAML Exchange Services",
        "description": (
            "Exchange a DigiD SAML response for a pseudonym. Currently a mock "
            "that echoes the request body so the VAD/MGO can integrate; only "
            "mounted when `enable_saml_exchange_routes` is set (test "
            "environments only)."
        ),
    },
]

# Section (tag) metadata for the test/helper routes. Only included in the OpenAPI
# schema when `enable_test_routes` is set, matching when these routes are mounted.
TEST_TAGS_METADATA = [
    {
        "name": "OPRF Testing Services",
        "description": (
            "Helper endpoints for testing and debugging the OPRF and JWE flows "
            "(client-side blinding, receiver finalization, JWE decoding, pseudonym "
            "reversal, and mTLS introspection). These are only mounted when "
            "`enable_test_routes` is set and must not be enabled in production."
        ),
    },
]


def get_uvicorn_params() -> dict[str, Any]:
    config = get_config()

    kwargs = {
        "host": config.uvicorn.host,
        "port": config.uvicorn.port,
        "reload": config.uvicorn.reload,
        "reload_delay": config.uvicorn.reload_delay,
        "reload_dirs": config.uvicorn.reload_dirs,
        "factory": True,
    }
    if (
        config.uvicorn.use_ssl
        and config.uvicorn.ssl_base_dir is not None
        and config.uvicorn.ssl_cert_file is not None
        and config.uvicorn.ssl_key_file is not None
    ):
        kwargs["ssl_keyfile"] = (
            config.uvicorn.ssl_base_dir + "/" + config.uvicorn.ssl_key_file
        )
        kwargs["ssl_certfile"] = (
            config.uvicorn.ssl_base_dir + "/" + config.uvicorn.ssl_cert_file
        )
    return kwargs


def run() -> None:
    uvicorn.run("app.application:create_fastapi_app", **get_uvicorn_params())


def application_init() -> None:
    setup_logging()
    gflog.install_excepthook(logger)
    gflog.install_signal_handlers()


def create_fastapi_app() -> FastAPI:
    application_init()
    try:
        fastapi = setup_fastapi()
    except Exception as exc:
        gflog.emit(
            logger,
            Log.SYS_UNHANDLED_EXCEPTION,
            "Unhandled exception during application startup",
            fields={"exception_type": type(exc).__name__},
            exc_info=exc,
        )
        raise

    return fastapi


def _read_version() -> str:
    path = Path(__file__).parent.parent / "version.json"
    try:
        with open(path, "r") as fh:
            data = json.load(fh)
            return str(data.get("version", "unknown"))
    except (FileNotFoundError, json.JSONDecodeError):
        return "unknown"


@asynccontextmanager
async def _lifespan(_: FastAPI) -> AsyncIterator[None]:
    config = get_config()
    async with gflog.lifespan_logging(
        logger,
        version=_read_version(),
        config_path=os.environ.get(_ENVIRONMENT_CONFIG_PATH_NAME, _PATH),
        started_fields={
            "pseudoniem_api_enabled": config.app.enable_exchange_services_routes,
        },
    ):
        yield


@restore_request_context
def _unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    gflog.emit(
        logger,
        Log.SYS_UNHANDLED_EXCEPTION,
        "Unhandled exception",
        fields={"exception_type": type(exc).__name__},
        exc_info=exc,
    )
    return JSONResponse(status_code=500, content={"error": "Internal server error"})


def setup_logging() -> None:
    config = get_config()
    gflog.configure(config=config.logging, loglevel=config.app.loglevel, catalogue=Log)


def setup_fastapi() -> FastAPI:

    config = get_config()

    openapi_tags = list(TAGS_METADATA)
    if config.app.enable_exchange_services_routes:
        openapi_tags += EXCHANGE_TAGS_METADATA
    if config.app.enable_saml_exchange_routes:
        openapi_tags += SAML_EXCHANGE_TAGS_METADATA
    if config.app.enable_test_routes:
        openapi_tags += TEST_TAGS_METADATA

    # Swagger only toggles the documentation UI; the app metadata, root path
    # and header documentation apply regardless.
    swagger = config.uvicorn.swagger_enabled
    fastapi = FastAPI(
        docs_url=config.uvicorn.docs_url if swagger else None,
        redoc_url=config.uvicorn.redoc_url if swagger else None,
        title="Pseudoniemendienst API",
        summary="API for the Pseudoniemendienst",
        description=API_DESCRIPTION,
        openapi_tags=openapi_tags,
        root_path=config.uvicorn.root_path,
        lifespan=_lifespan,
        dependencies=gf_header_params(config.uvicorn.document_gf_headers),
    )

    fastapi.add_middleware(
        RequestContextMiddleware,
        correlation_id_expected=config.logging.correlation_id_expected,
    )
    fastapi.add_exception_handler(Exception, _unhandled_exception_handler)
    install_domain_error_handler(fastapi)

    # Non-OAuth routes
    public_routers = [
        default_router,
        health_router,
    ]
    for router in public_routers:
        fastapi.include_router(router)

    # OAuth protected routes
    routers = [
        oprf_router,
    ]
    if config.app.enable_exchange_services_routes:
        routers.append(exchange_router)
        routers.append(reversible_pseudonym_router)
    if config.app.enable_saml_exchange_routes:
        routers.append(saml_exchange_router)
    if config.app.enable_test_routes:
        routers.append(test_oprf_router)

    for router in routers:
        fastapi.include_router(router, dependencies=[Depends(get_auth_ctx)])

    # OAuth protected administration routes
    administration_routers = [
        key_router,
        hsm_key_version_router,
    ]
    for router in administration_routers:
        fastapi.include_router(
            router,
            prefix="/administration",
            dependencies=[
                Depends(get_auth_ctx),
                Security(
                    require_scopes, scopes=[AuthorizationScope.ADMINISTRATION.value]
                ),
            ],
        )
    install_openapi_extensions(fastapi, config.uvicorn.document_gf_headers)
    return fastapi
