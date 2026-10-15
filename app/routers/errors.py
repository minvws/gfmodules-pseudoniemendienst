"""
Maps domain exceptions to HTTP responses.

This is the only place where a domain error becomes a status code. Services
raise the exceptions from ``app/exceptions.py``; the handler registered here
turns them into the same ``{"detail": ...}`` body FastAPI uses for
``HTTPException``.
"""

import logging

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from app.exceptions import (
    CryptoFailureError,
    DomainAlreadyRegisteredError,
    DomainError,
    DomainNotRegisteredError,
    ExchangeInputError,
    HsmOperationFailedError,
    HsmTimeoutError,
    HsmUnreachableError,
    InvalidAudienceError,
    InvalidBlindedInputError,
    InvalidJwsError,
    InvalidPersonalIdError,
    InvalidPseudonymError,
    KeyVersionNotFoundError,
    KeyVersionRemovedError,
    NoActiveKeyVersionError,
    NoKeyVersionError,
    NotAllowedToRequestError,
    OrganizationNotRegisteredError,
    PseudonymVersionDestroyedError,
    PublicKeyNotFoundError,
    RecipientNotFoundError,
    UnauthorizedRequestError,
)

logger = logging.getLogger(__name__)

STATUS_CODES: dict[type[DomainError], int] = {
    # The proxy already authenticated the caller, so both an unregistered
    # organization and a policy refusal are 403: known, but not allowed.
    OrganizationNotRegisteredError: 403,
    NotAllowedToRequestError: 403,
    InvalidAudienceError: 403,
    RecipientNotFoundError: 404,
    InvalidJwsError: 422,
    PublicKeyNotFoundError: 404,
    DomainAlreadyRegisteredError: 409,
    DomainNotRegisteredError: 404,
    KeyVersionNotFoundError: 404,
    # The version exists and belongs to the caller; its state forbids the change.
    KeyVersionRemovedError: 409,
    NoKeyVersionError: 409,
    UnauthorizedRequestError: 403,
    ExchangeInputError: 400,
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


def status_code_for(exc: DomainError) -> int:
    for cls in type(exc).__mro__:
        if cls in STATUS_CODES:
            return STATUS_CODES[cls]
    logger.error("no status code mapped for %s", type(exc).__name__)
    return 500


def domain_error_handler(request: Request, exc: DomainError) -> JSONResponse:
    status_code = status_code_for(exc)
    logger.warning(
        "%s %s refused with %d: %s",
        request.method,
        request.url.path,
        status_code,
        exc.message,
    )
    return JSONResponse(status_code=status_code, content={"detail": exc.message})


def install_domain_error_handler(fastapi: FastAPI) -> None:
    fastapi.exception_handler(DomainError)(domain_error_handler)
