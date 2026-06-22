import logging

from typing import Any

from fastapi import FastAPI, Depends
import uvicorn

from app.routers.default import router as default_router
from app.routers.health import router as health_router
from app.routers.oprf import router as oprf_router
from app.routers.test_oprf import router as test_oprf_router
from app.routers.key import router as key_router
from app.routers.hsm_key_version import router as hsm_key_version_router
from app.routers.org import router as org_router
from app.routers.exchange import router as exchange_router
from app.config import get_config
from app.auth import get_auth_ctx


API_DESCRIPTION = """
The Pseudoniemendienst (PRS) lets parties exchange data about a person without
sharing their BSN. Instead of a BSN, parties exchange **RIDs** and **pseudonyms**
that are scoped to a recipient organization and scope.

A recipient organization is always identified by a URA in the form
`ura:<8 digits>` (e.g. `ura:90000036`).

The endpoints are grouped into the sections below. Most sections are protected by
mutual TLS (mTLS); the calling organization and, where relevant, its public key
are derived from the client certificate.
"""

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
        "name": "Organizational Services",
        "description": (
            "Manage recipient organizations. An organization is identified by its "
            "URA and has a `max_key_usage` (`bsn`, `rp`, or `irp`) that caps which "
            "pseudonym types it is allowed to exchange."
        ),
    },
    {
        "name": "Key Registration Services",
        "description": (
            "Register and manage the public keys that pseudonyms and RIDs are "
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
            "Exchange a personal ID for a pseudonym or RID targeted at a recipient "
            "organization/scope, and redeem a previously issued RID for a pseudonym "
            "(or the BSN, when permitted by both the RID usage and the "
            "organization's `max_key_usage`)."
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


def create_fastapi_app() -> FastAPI:
    application_init()
    fastapi = setup_fastapi()

    return fastapi


def setup_logging() -> None:
    loglevel = logging.getLevelName(get_config().app.loglevel.upper())

    if isinstance(loglevel, str):
        raise ValueError(f"Invalid loglevel {loglevel.upper()}")
    logging.basicConfig(
        level=loglevel,
        datefmt="%m/%d/%Y %I:%M:%S %p",
    )


def setup_fastapi() -> FastAPI:
    config = get_config()

    openapi_tags = list(TAGS_METADATA)
    if config.app.enable_exchange_services_routes:
        openapi_tags += EXCHANGE_TAGS_METADATA
    if config.app.enable_test_routes:
        openapi_tags += TEST_TAGS_METADATA

    fastapi = (
        FastAPI(
            docs_url=config.uvicorn.docs_url,
            redoc_url=config.uvicorn.redoc_url,
            title="Pseudoniemendienst API",
            summary="API for the Pseudoniemendienst",
            description=API_DESCRIPTION,
            openapi_tags=openapi_tags,
            root_path=config.uvicorn.root_path,
        )
        if config.uvicorn.swagger_enabled
        else FastAPI(docs_url=None, redoc_url=None)
    )

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
        key_router,
        hsm_key_version_router,
        org_router,
    ]
    if config.app.enable_exchange_services_routes:
        routers.append(exchange_router)
    if config.app.enable_test_routes:
        routers.append(test_oprf_router)

    for router in routers:
        fastapi.include_router(router, dependencies=[Depends(get_auth_ctx)])

    return fastapi
