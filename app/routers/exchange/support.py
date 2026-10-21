import logging
from typing import NoReturn

import gfmodules.logging as gflog
from fastapi import HTTPException
from gfmodules.logging import LogEvent

from app.enums.personal_id_type import PersonalIdType
from app.enums.pseudonym_error_type import PseudonymErrorType
from app.exceptions import (
    DomainError,
    PseudonymOperationError,
    RecipientNotFoundError,
)
from app.logging.events import Log
from app.logging.exchange_audit import ExchangeAudit
from app.models.auth.context import AuthContext
from app.models.oin import Oin
from app.models.personal_id import PersonalId, PersonalIdValidationError
from app.services.authorization_service import AuthorizationService

_EXCHANGE_FAILED = "Pseudonym exchange failed"
_PSEUDONYM_FAILURES = {
    PseudonymErrorType.HSM_UNREACHABLE: (503, _EXCHANGE_FAILED),
    PseudonymErrorType.VERSION_DESTROYED: (
        410,
        "Pseudonym key version no longer available",
    ),
    PseudonymErrorType.INVALID_PSEUDONYM: (400, "Invalid pseudonym"),
}


def authorize_exchange(
    logger: logging.Logger,
    authorization_service: AuthorizationService,
    auth: AuthContext,
    recipient: Oin,
    personal_id_type: PersonalIdType,
    operation: str,
) -> None:
    def deny(reason: str, error: DomainError) -> None:
        gflog.emit(
            logger,
            Log.AUTHORIZATION_DENIED,
            f"Authorization denied ({reason}): {error.message}",
            fields={
                **ExchangeAudit.from_auth(auth, recipient).fields(),
                "requested_operation": operation,
            },
        )

    try:
        authorization_service.validate_allowed_to_request(
            auth.claims.organization_id, personal_id_type
        )
    except DomainError as e:
        deny(f"sender_may_not_request_{personal_id_type}", e)
        raise

    try:
        authorization_service.validate_allowed_to_receive(recipient, personal_id_type)
    except DomainError as e:
        deny(f"recipient_may_not_receive_{personal_id_type}", e)
        raise


def parse_personal_id(
    logger: logging.Logger, raw: str | dict[str, str], audit: ExchangeAudit
) -> PersonalId:
    try:
        return PersonalId.parse(raw)
    except PersonalIdValidationError as e:
        gflog.emit(
            logger,
            Log.PERSONAL_ID_VALIDATION_FAILED,
            "Personal ID validation failed",
            fields={
                "handelende_oin": audit.handelende_oin,
                "namens_oin": audit.namens_oin,
                "validation_error": e.kind,
            },
        )
        raise HTTPException(status_code=400, detail="Invalid personal ID") from e


def raise_pseudonym_error(
    logger: logging.Logger,
    audit: ExchangeAudit,
    error: PseudonymOperationError,
    event: LogEvent,
    message: str,
) -> NoReturn:
    gflog.emit(
        logger,
        event,
        message,
        exc_info=error,
        fields={**audit.fields(), "error_type": error.error_type},
    )
    if error.error_type == PseudonymErrorType.NO_ACTIVE_KEY_VERSION:
        raise RecipientNotFoundError() from error
    status, detail = _PSEUDONYM_FAILURES.get(error.error_type, (500, _EXCHANGE_FAILED))
    raise HTTPException(status_code=status, detail=detail) from error
