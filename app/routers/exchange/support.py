import logging

import gfmodules.logging as gflog
from gfmodules.logging import LogEvent

from app.db.models.organization_public_key import OrganizationPublicKeyEntity
from app.enums.personal_id_type import PersonalIdType
from app.exceptions.access import AccessError
from app.exceptions.base import AppError
from app.exceptions.pseudonym import InvalidPersonalIdError, PseudonymOperationError
from app.logging.events import Log
from app.logging.exchange_audit import ExchangeAudit
from app.models.auth.context import AuthContext
from app.models.oin import Oin
from app.models.personal_id import PersonalId, PersonalIdValidationError
from app.models.requests.exchange import (
    ExchangeInputRequest,
    ReversiblePseudonymInputRequest,
)
from app.services.authorization_service import AuthorizationService
from app.services.organization_public_key_service import OrganizationPublicKeyService
from app.services.reversible.service import ReversiblePseudonymService


def authorize_exchange(
    logger: logging.Logger,
    authorization_service: AuthorizationService,
    auth: AuthContext,
    recipient: Oin,
    personal_id_type: PersonalIdType,
    operation: str,
) -> None:
    def deny(reason: str, error: AccessError) -> None:
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
    except AccessError as e:
        deny(f"sender_may_not_request_{personal_id_type}", e)
        raise

    try:
        authorization_service.validate_allowed_to_receive(recipient, personal_id_type)
    except AccessError as e:
        deny(f"recipient_may_not_receive_{personal_id_type}", e)
        raise


def get_recipient_public_key(
    logger: logging.Logger,
    organization_public_key_service: OrganizationPublicKeyService,
    audit: ExchangeAudit,
    recipient: Oin,
    scope: str,
) -> OrganizationPublicKeyEntity:
    try:
        return organization_public_key_service.get_by_org_and_domain(recipient, scope)
    except AppError as e:
        gflog.emit(
            logger,
            Log.EXCHANGE_REFUSED_NO_ACTIVE_PUBKEY,
            f"Exchange refused: {e.message}",
            fields=audit.fields(),
        )
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
        raise InvalidPersonalIdError() from e


def log_pseudonym_failure(
    logger: logging.Logger,
    audit: ExchangeAudit,
    error: PseudonymOperationError,
    event: LogEvent,
    message: str,
) -> None:
    gflog.emit(
        logger,
        event,
        message,
        exc_info=error,
        fields={**audit.fields(), "error_type": error.error_type},
    )


def resolve_personal_id(
    logger: logging.Logger,
    reversible_service: ReversiblePseudonymService,
    audit: ExchangeAudit,
    req: ExchangeInputRequest,
    caller: Oin,
    failure_message: str,
) -> PersonalId:
    if not isinstance(req, ReversiblePseudonymInputRequest):
        return parse_personal_id(logger, req.personalId, audit)
    try:
        return reversible_service.reverse(req.reversiblePseudonym, caller).personal_id
    except PseudonymOperationError as e:
        log_pseudonym_failure(
            logger, audit, e, Log.PSEUDONYM_CREATE_FAILED, failure_message
        )
        raise
