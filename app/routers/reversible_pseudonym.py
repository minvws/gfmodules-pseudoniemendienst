import logging
from typing import Annotated

import gfmodules.logging as gflog
from fastapi import APIRouter, Depends, HTTPException, Security
from jwcrypto.jwk import JWK
from starlette.responses import Response

from app import container
from app.auth import require_scopes
from app.enums.personal_id_type import PersonalIdType
from app.exceptions import DomainError, RecipientNotFoundError
from app.logging.events import Log
from app.models.auth.context import AuthContext
from app.models.auth.data import AuthorizationScope
from app.models.requests import ReversiblePseudonymExchangeRequest
from app.personal_id import PersonalId, PersonalIdValidationError
from app.services.authorization_service import AuthorizationService
from app.services.oprf.jwe_token import BlindJwe
from app.services.organization_public_key_service import OrganizationPublicKeyService
from app.services.reversible.service import (
    ReversiblePseudonymError,
    ReversiblePseudonymService,
)

logger = logging.getLogger(__name__)
router = APIRouter()

_ENDPOINT = "/exchange/reversible-pseudonym"
_OPERATION = "exchange:reversible-pseudonym"
_SUBJECT_PREFIX = "pseudonym:reversible:"


def _parse_personal_id(raw: str | dict[str, str]) -> PersonalId:
    if isinstance(raw, str):
        return PersonalId.from_str(raw)
    return PersonalId.from_dict(raw)


@router.post(
    _ENDPOINT,
    summary="Exchange a personal ID for a reversible pseudonym",
    tags=["Exchange Services"],
    status_code=201,
    response_class=Response,
    responses={
        201: {
            "description": (
                "A JWE encrypted to the recipient's public key for the scope. Its "
                "decrypted `subject` claim is `pseudonym:reversible:<...>`."
            ),
            "content": {"application/jwe": {}},
        },
        400: {"description": "The personal ID is malformed."},
        403: {
            "description": (
                "Insufficient scope (the token requires `prs:pseudonym`), the "
                "calling organization is not registered, or it is not allowed to "
                "request reversible pseudonyms."
            )
        },
        404: {
            "description": (
                "The recipient organization is unknown, is not allowed to receive "
                "reversible pseudonyms, has no public key registered for the "
                "scope, or has no active HSM key version."
            )
        },
        500: {"description": "The pseudonym could not be produced."},
        503: {"description": "The HSM could not be reached; retry later."},
    },
    description="""
Exchange a personal ID for a reversible pseudonym bound to the recipient
organization and scope. The pseudonym is deterministic for the same input and
can only be reversed to the personal ID by the PRS itself.

Requires the `prs:pseudonym` OAuth scope. Before the personal ID is
processed, two administrator-managed authorizations are checked: the calling
organization must be allowed to request reversible pseudonyms, and the recipient
organization must be allowed to receive them. The sender is checked first, so an
unauthorized caller cannot probe which recipient organizations exist.
""",
)
def exchange_reversible_pseudonym(
    req: ReversiblePseudonymExchangeRequest,
    auth: Annotated[
        AuthContext,
        Security(
            require_scopes,
            scopes=[AuthorizationScope.PSEUDONYM.value],
        ),
    ],
    authorization_service: Annotated[
        AuthorizationService, Depends(container.get_authorization_service)
    ],
    organization_public_key_service: Annotated[
        OrganizationPublicKeyService,
        Depends(container.get_organization_public_key_service),
    ],
    pseudonym_service: Annotated[
        ReversiblePseudonymService,
        Depends(container.get_reversible_pseudonym_service),
    ],
) -> Response:
    handelende_oin = str(auth.claims.client_organization_id)
    namens_oin = str(auth.claims.organization_id)
    doel_oin = str(req.recipientOrganization)

    def deny(reason: str, error: DomainError) -> None:
        gflog.emit(
            logger,
            Log.AUTHORIZATION_DENIED,
            f"Authorization denied ({reason}): {error.message}",
            fields={
                "handelende_oin": handelende_oin,
                "namens_oin": namens_oin,
                "doel_oin": doel_oin,
                "requested_operation": _OPERATION,
            },
        )

    personal_id_type = PersonalIdType.REVERSIBLE_PSEUDONYM
    try:
        authorization_service.validate_allowed_to_request(
            auth.claims.organization_id, personal_id_type
        )
    except DomainError as e:
        deny("sender_may_not_request_reversible_pseudonym", e)
        raise

    try:
        authorization_service.validate_allowed_to_receive(
            req.recipientOrganization, personal_id_type
        )
    except DomainError as e:
        deny("recipient_may_not_receive_reversible_pseudonym", e)
        raise

    try:
        personal_id = _parse_personal_id(req.personalId)
    except PersonalIdValidationError as e:
        # PRS-PSE-005: only the kind of failure, never the value.
        gflog.emit(
            logger,
            Log.PERSONAL_ID_VALIDATION_FAILED,
            "Personal ID validation failed",
            fields={
                "handelende_oin": handelende_oin,
                "namens_oin": namens_oin,
                "validation_error": e.kind,
            },
        )
        raise HTTPException(status_code=400, detail="Invalid personal ID")

    # Raises 404 when the recipient has no public key for the scope.
    public_key = organization_public_key_service.get_by_org_and_domain(
        req.recipientOrganization, req.recipientScope
    )

    try:
        pseudonym = pseudonym_service.generate(
            personal_id=personal_id,
            recipient=req.recipientOrganization,
            recipient_scope=req.recipientScope,
        )
    except ReversiblePseudonymError as e:
        gflog.emit(
            logger,
            Log.PSEUDONYM_CREATE_FAILED,
            "Reversible pseudonym creation failed",
            exc_info=e,
            fields={
                "handelende_oin": handelende_oin,
                "namens_oin": namens_oin,
                "doel_oin": doel_oin,
                "error_type": e.error_type,
            },
        )
        if e.error_type == "no_active_key_version":
            # Must be the same message as for when we don't find the server, so we cannot
            # differentiate between the two cases and leak information about the recipient organization.
            raise RecipientNotFoundError()
        status = 503 if e.error_type == "hsm_unreachable" else 500
        raise HTTPException(status_code=status, detail="Pseudonym exchange failed")

    jwe = BlindJwe.build(
        audience=doel_oin,
        scope=req.recipientScope,
        subject=_SUBJECT_PREFIX + pseudonym.value,
        pub_key=JWK(**public_key.jwk),
        extra_claims={"keyVersion": pseudonym.version},
    )

    gflog.emit(
        logger,
        Log.PSEUDONYM_REVERSIBLE_CREATED,
        "Reversible pseudonym created",
        fields={
            "handelende_oin": handelende_oin,
            "namens_oin": namens_oin,
            "doel_oin": doel_oin,
            "domein": req.recipientScope,
            "sleutel_versie": pseudonym.version,
        },
    )
    return Response(status_code=201, content=jwe, media_type="application/jwe")
