import json
import logging
import signal
import sys

from contextlib import asynccontextmanager
from logging.config import dictConfig
from pathlib import Path
from types import TracebackType
from typing import Any, AsyncIterator

from fastapi import FastAPI, Depends, Request
from fastapi.responses import JSONResponse
import uvicorn

from app.logging.config_builder import LogConfigBuilder
from app.logging.events import (
    SYS_APP_CRASHED,
    SYS_APP_STARTED,
    SYS_APP_STOPPED,
    SYS_UNHANDLED_EXCEPTION,
    log_event,
)
from app.logging.middleware import RequestContextMiddleware

from app.routers.default import router as default_router
from app.routers.health import router as health_router
from app.routers.oprf import router as oprf_router
from app.routers.test_oprf import router as test_oprf_router
from app.routers.key import router as key_router
from app.routers.hsm_key_version import router as hsm_key_version_router
from app.routers.exchange import router as exchange_router
from app.config import get_config
from app.auth import get_auth_ctx

logger = logging.getLogger(__name__)

# Component name carried on the PRS-HEALTH / PRS-SYS audit events.
COMPONENT = "pseudoniemendienst"

API_DESCRIPTION = """
The Pseudoniemendienst (PRS) lets parties exchange data about a person without
sharing their BSN. Instead of a BSN, parties exchange **RIDs** and **pseudonyms**
that are scoped to a recipient organization and scope.

A recipient organization is always identified by a OIN in the form
`oin:<20 digits>` (e.g. `oin:00000099000000001000`).

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
            "OIN and has a `max_key_usage` (`bsn`, `rp`, or `irp`) that caps which "
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
    _install_excepthook()
    _install_signal_handlers()


def create_fastapi_app() -> FastAPI:
    application_init()
    try:
        fastapi = setup_fastapi()
    except Exception as exc:
        log_event(
            logger,
            SYS_APP_CRASHED,
            "Application crashed during startup",
            exc_info=exc,
            component=COMPONENT,
            shutdown_reason="crash",
            last_exception_type=type(exc).__name__,
        )
        raise
    _emit_app_started()

    return fastapi


_shutdown_reason: str = "graceful"


def _read_version() -> str:
    path = Path(__file__).parent.parent / "version.json"
    try:
        with open(path, "r") as fh:
            data = json.load(fh)
            return str(data.get("version", "unknown"))
    except (FileNotFoundError, json.JSONDecodeError):
        return "unknown"


def _emit_app_started() -> None:
    config = get_config()
    log_event(
        logger,
        SYS_APP_STARTED,
        "Application started",
        component=COMPONENT,
        version=_read_version(),
        environment=config.app.environment,
        pseudoniem_api_enabled=config.app.enable_exchange_services_routes,
    )


def _install_excepthook() -> None:
    """Route uncaught exceptions through our own logging so the crash is
    recorded as a PRS-SYS-002 event before the process dies."""

    def _hook(
        exc_type: type[BaseException],
        exc_value: BaseException,
        exc_tb: TracebackType | None,
    ) -> None:
        if issubclass(exc_type, KeyboardInterrupt):
            sys.__excepthook__(exc_type, exc_value, exc_tb)
            return
        global _shutdown_reason
        _shutdown_reason = "crash"
        log_event(
            logger,
            SYS_APP_CRASHED,
            "Application crashed: uncaught exception",
            exc_info=(exc_type, exc_value, exc_tb),
            component=COMPONENT,
            shutdown_reason="crash",
            last_exception_type=exc_type.__name__,
        )

    sys.excepthook = _hook


def _install_signal_handlers() -> None:
    """Record the shutdown reason then delegate to the previously-installed
    handler (typically uvicorn's), so we don't disrupt graceful shutdown."""

    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            previous = signal.getsignal(sig)
        except (ValueError, OSError):
            continue

        def _make_handler(signum: int, prev: Any) -> Any:
            def _handler(s: int, frame: Any) -> None:
                global _shutdown_reason
                _shutdown_reason = f"signal:{signal.Signals(signum).name}"
                if callable(prev):
                    prev(s, frame)

            return _handler

        try:
            signal.signal(sig, _make_handler(sig, previous))
        except (ValueError, OSError):
            pass


@asynccontextmanager
async def _lifespan(_: FastAPI) -> AsyncIterator[None]:
    global _shutdown_reason
    try:
        yield
    finally:
        if _shutdown_reason != "crash":
            log_event(
                logger,
                SYS_APP_STOPPED,
                "Application stopped",
                component=COMPONENT,
                shutdown_reason=_shutdown_reason,
            )


def _unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    log_event(
        logger,
        SYS_UNHANDLED_EXCEPTION,
        "Unhandled exception",
        exc_info=exc,
        exception_type=type(exc).__name__,
        endpoint=request.url.path,
        method=request.method,
    )
    return JSONResponse(status_code=500, content={"error": "Internal server error"})


def setup_logging() -> None:
    config = get_config()
    loglevel = config.app.loglevel.upper()
    if loglevel not in logging.getLevelNamesMapping():
        raise ValueError(f"Invalid loglevel {loglevel}")

    log_config = LogConfigBuilder(
        loglevel=loglevel,
        logging_config=config.logging,
    ).build()
    dictConfig(log_config)


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
            lifespan=_lifespan,
        )
        if config.uvicorn.swagger_enabled
        else FastAPI(docs_url=None, redoc_url=None, lifespan=_lifespan)
    )

    fastapi.add_middleware(RequestContextMiddleware)
    fastapi.add_exception_handler(Exception, _unhandled_exception_handler)

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
    ]
    if config.app.enable_exchange_services_routes:
        routers.append(exchange_router)
    if config.app.enable_test_routes:
        routers.append(test_oprf_router)

    for router in routers:
        fastapi.include_router(router, dependencies=[Depends(get_auth_ctx)])

    return fastapi
