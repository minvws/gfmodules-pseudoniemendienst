import logging
from dataclasses import asdict, dataclass
from typing import NoReturn, Self

import gfmodules.logging as gflog
from gfmodules.logging import LogEvent

from app.enums.personal_id_type import PersonalIdType
from app.exceptions import (
    DomainError,
    InvalidPersonalIdError,
    PseudonymOperationError,
)
from app.logging.events import Log
from app.models.auth.context import AuthContext
from app.models.oin import Oin
from app.models.personal_id import PersonalId, PersonalIdValidationError
from app.services.authorization_service import AuthorizationService


@dataclass(frozen=True)
class ExchangeAudit:
    handelende_oin: str
    namens_oin: str
    doel_oin: str

    @classmethod
    def from_auth(cls, auth: AuthContext, recipient: Oin) -> Self:
        return cls(
            handelende_oin=str(auth.claims.client_organization_id),
            namens_oin=str(auth.claims.organization_id),
            doel_oin=str(recipient),
        )

    def fields(self) -> dict[str, str]:
        return asdict(self)


def authorize_exchange(
    logger: logging.Logger,
    authorization_service: AuthorizationService,
    auth: AuthContext,
    recipient: Oin,
    personal_id_type: PersonalIdType,
    operation: str,
) -> ExchangeAudit:
    audit = ExchangeAudit.from_auth(auth, recipient)

    def deny(reason: str, error: DomainError) -> None:
        gflog.emit(
            logger,
            Log.AUTHORIZATION_DENIED,
            f"Authorization denied ({reason}): {error.message}",
            fields={**audit.fields(), "requested_operation": operation},
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

    return audit


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
        raise InvalidPersonalIdError() from e


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
    raise error
