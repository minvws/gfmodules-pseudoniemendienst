"""
Maps app exceptions to HTTP responses.

This is the only place where an app error becomes a status code. Code below
the routers raises the exceptions from ``app/exceptions/``; the handler
registered here turns them into the same ``{"detail": ...}`` body FastAPI uses
for ``HTTPException``.
"""

import logging

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from app.exceptions.access import (
    InvalidAudienceError,
    NotAllowedToRequestError,
    OrganizationNotRegisteredError,
    RecipientNotFoundError,
    UnauthorizedRequestError,
)
from app.exceptions.base import AppError
from app.exceptions.pseudonym import (
    CryptoFailureError,
    HsmOperationFailedError,
    HsmTimeoutError,
    HsmUnreachableError,
    InvalidBlindedInputError,
    InvalidPersonalIdError,
    InvalidPseudonymError,
    NoActiveKeyVersionError,
    PseudonymVersionDestroyedError,
)
from app.exceptions.registration import (
    DomainAlreadyRegisteredError,
    DomainNotRegisteredError,
    InvalidJwsError,
    KeyVersionNotFoundError,
    KeyVersionRemovedError,
    NoKeyVersionError,
    PublicKeyNotFoundError,
)

logger = logging.getLogger(__name__)

STATUS_CODES: dict[type[AppError], int] = {
    UnauthorizedRequestError: 403,
    InvalidAudienceError: 403,
    OrganizationNotRegisteredError: 403,
    NotAllowedToRequestError: 403,
    RecipientNotFoundError: 404,
    InvalidJwsError: 422,
    PublicKeyNotFoundError: 404,
    DomainAlreadyRegisteredError: 409,
    DomainNotRegisteredError: 404,
    KeyVersionNotFoundError: 404,
    KeyVersionRemovedError: 409,
    NoKeyVersionError: 409,
    InvalidPersonalIdError: 400,
    InvalidPseudonymError: 400,
    InvalidBlindedInputError: 400,
    PseudonymVersionDestroyedError: 410,
    NoActiveKeyVersionError: 404,
    CryptoFailureError: 500,
    HsmOperationFailedError: 502,
    HsmUnreachableError: 503,
    HsmTimeoutError: 504,
}


def status_code_for(exc: AppError) -> int:
    for cls in type(exc).__mro__:
        if cls in STATUS_CODES:
            return STATUS_CODES[cls]
    logger.error("no status code mapped for %s", type(exc).__name__)
    return 500


def app_error_handler(request: Request, exc: AppError) -> JSONResponse:
    status_code = status_code_for(exc)
    logger.warning(
        "%s %s refused with %d: %s",
        request.method,
        request.url.path,
        status_code,
        exc.message,
    )
    return JSONResponse(status_code=status_code, content={"detail": exc.message})


def install_app_error_handler(fastapi: FastAPI) -> None:
    fastapi.exception_handler(AppError)(app_error_handler)


def validation_error_handler(
    request: Request, exc: RequestValidationError
) -> JSONResponse:
    return JSONResponse(
        status_code=422,
        content={
            "detail": [
                {"type": error["type"], "loc": error["loc"], "msg": error["msg"]}
                for error in exc.errors()
            ]
        },
    )


def install_validation_error_handler(fastapi: FastAPI) -> None:
    fastapi.exception_handler(RequestValidationError)(validation_error_handler)
