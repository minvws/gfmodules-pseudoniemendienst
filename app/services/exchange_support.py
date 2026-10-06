import logging
from dataclasses import dataclass
from typing import NoReturn

import gfmodules.logging as gflog
from fastapi import HTTPException

from app.enums.personal_id_type import PersonalIdType
from app.exceptions import (
    DomainError,
    InvalidPersonalIdError,
    InvalidPseudonymError,
    PseudonymOperationError,
    PseudonymVersionDestroyedError,
    RecipientNotFoundError,
)
from app.logging.events import Log
from app.models.auth.context import AuthContext
from app.models.oin import Oin
from app.models.personal_id import PersonalId, PersonalIdValidationError
from app.services.authorization_service import AuthorizationService
from app.services.reversible.service import ReversiblePseudonymService

# Client refusals: a mapped DomainError (4xx only, enforced by test_domain_errors.py).
_CLIENT_ERROR_TYPES: dict[str, type[DomainError]] = {
    "version_destroyed": PseudonymVersionDestroyedError,
    "invalid_pseudonym": InvalidPseudonymError,
}


@dataclass(frozen=True)
class ExchangeAudit:
    handelende_oin: str
    namens_oin: str
    doel_oin: str

    @classmethod
    def from_auth(cls, auth: AuthContext, recipient: Oin) -> "ExchangeAudit":
        return cls(
            handelende_oin=str(auth.claims.client_organization_id),
            namens_oin=str(auth.claims.organization_id),
            doel_oin=str(recipient),
        )

    def fields(self) -> dict[str, str]:
        return {
            "handelende_oin": self.handelende_oin,
            "namens_oin": self.namens_oin,
            "doel_oin": self.doel_oin,
        }


def authorize_exchange(
    logger: logging.Logger,
    authorization_service: AuthorizationService,
    auth: AuthContext,
    recipient: Oin,
    personal_id_type: PersonalIdType,
    operation: str,
) -> ExchangeAudit:
    audit = ExchangeAudit.from_auth(auth, recipient)

    # Sender checked first, so an unauthorized caller cannot probe which
    # recipient organizations exist.

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


def raise_pseudonym_error(
    logger: logging.Logger, audit: ExchangeAudit, error: PseudonymOperationError
) -> NoReturn:
    gflog.emit(
        logger,
        Log.PSEUDONYM_CREATE_FAILED,
        "Pseudonym exchange failed",
        exc_info=error,
        fields={**audit.fields(), "error_type": error.error_type},
    )
    if error.error_type == "no_active_key_version":
        # Same message as an unknown recipient, so a caller cannot tell the two apart.
        raise RecipientNotFoundError() from error
    if error.error_type in _CLIENT_ERROR_TYPES:
        raise _CLIENT_ERROR_TYPES[error.error_type]() from error
    # hsm_unreachable, crypto_failure and anything unforeseen: a server-side
    # failure, not a domain refusal, so it stays outside the DomainError map.
    status = 503 if error.error_type == "hsm_unreachable" else 500
    raise HTTPException(
        status_code=status, detail="Pseudonym exchange failed"
    ) from error


def resolve_personal_id(
    logger: logging.Logger,
    personal_id: str | dict[str, str] | None,
    reversible_pseudonym: str | None,
    auth: AuthContext,
    reversible_service: ReversiblePseudonymService,
    audit: ExchangeAudit,
) -> PersonalId:
    if reversible_pseudonym is not None:
        try:
            # Reversed against the caller's own authenticated identity, never
            # a request-supplied one: a caller can only reverse a pseudonym
            # issued to itself.
            reversed_pseudonym = reversible_service.reverse(
                reversible_pseudonym, auth.claims.organization_id
            )
        except PseudonymOperationError as e:
            raise_pseudonym_error(logger, audit, e)
        return reversed_pseudonym.personal_id

    assert personal_id is not None  # enforced by the request model

    try:
        return PersonalId.parse(personal_id)
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
