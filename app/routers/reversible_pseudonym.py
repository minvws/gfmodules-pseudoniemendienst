import logging
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Security
from jwcrypto.jwk import JWK
from starlette.responses import Response

from app import container
from app.auth import require_scopes
from app.enums.personal_id_type import PersonalIdType
from app.logging.events import (
    AUTHORIZATION_DENIED,
    PERSONAL_ID_VALIDATION_FAILED,
    PSEUDONYM_CREATE_FAILED,
    PSEUDONYM_REVERSIBLE_CREATED,
    log_event,
)
from app.models.auth.context import AuthContext
from app.models.auth.data import AuthorizationScope
from app.models.requests import ReversiblePseudonymExchangeRequest
from app.personal_id import PersonalId
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
        401: {
            "description": (
                "The calling organization is unknown or is not allowed to request "
                "reversible pseudonyms."
            )
        },
        403: {"description": "The token lacks the `prs:reversible-pseudonym` scope."},
        404: {
            "description": (
                "The recipient organization is unknown, is not allowed to receive "
                "reversible pseudonyms, or has no public key registered for the "
                "scope."
            )
        },
        503: {"description": "The HSM that holds the pseudonym keys is unreachable."},
    },
    description="""
Exchange a personal ID for a reversible pseudonym bound to the recipient
organization and scope. The pseudonym is deterministic for the same input and
can only be reversed to the personal ID by the PRS itself.

Requires the `prs:reversible-pseudonym` OAuth scope. Before the personal ID is
processed, two administrator-managed authorizations are checked: the calling
organization (the verified `x-gf-sub` identity) must be allowed to request
reversible pseudonyms, and the recipient organization must be allowed to
receive them. The sender is checked first, so an unauthorized caller cannot
probe which recipient organizations exist.
""",
)
def exchange_reversible_pseudonym(
    req: ReversiblePseudonymExchangeRequest,
    auth: Annotated[
        AuthContext,
        Security(
            require_scopes,
            scopes=[AuthorizationScope.REVERSIBLE_PSEUDONYM.value],
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

    def deny(reason: str, error: HTTPException) -> HTTPException:
        log_event(
            logger,
            AUTHORIZATION_DENIED,
            f"Authorization denied ({reason}): {error.detail}",
            handelende_oin=handelende_oin,
            namens_oin=namens_oin,
            doel_oin=doel_oin,
            requested_operation=_OPERATION,
            endpoint=_ENDPOINT,
            method="POST",
        )
        return error

    personal_id_type = PersonalIdType.REVERSIBLE_PSEUDONYM
    try:
        authorization_service.validate_allowed_to_request(
            auth.claims.organization_id, personal_id_type
        )
    except HTTPException as e:
        raise deny("sender_may_not_request_reversible_pseudonym", e)

    try:
        authorization_service.validate_allowed_to_receive(
            req.recipientOrganization, personal_id_type
        )
    except HTTPException as e:
        raise deny("recipient_may_not_receive_reversible_pseudonym", e)

    try:
        personal_id = _parse_personal_id(req.personalId)
    except ValueError:
        log_event(
            logger,
            PERSONAL_ID_VALIDATION_FAILED,
            "Personal ID validation failed",
            handelende_oin=handelende_oin,
            namens_oin=namens_oin,
            validation_error="format",
            endpoint=_ENDPOINT,
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
        log_event(
            logger,
            PSEUDONYM_CREATE_FAILED,
            "Reversible pseudonym creation failed",
            exc_info=e,
            handelende_oin=handelende_oin,
            namens_oin=namens_oin,
            doel_oin=doel_oin,
            error_type=e.error_type,
            endpoint=_ENDPOINT,
        )
        status = 503 if e.error_type == "hsm_unreachable" else 500
        raise HTTPException(status_code=status, detail="Pseudonym exchange failed")

    jwe = BlindJwe.build(
        audience=doel_oin,
        scope=req.recipientScope,
        subject=_SUBJECT_PREFIX + pseudonym.value,
        pub_key=JWK(**public_key.jwk),
        extra_claims={"keyVersion": pseudonym.version},
    )

    log_event(
        logger,
        PSEUDONYM_REVERSIBLE_CREATED,
        "Reversible pseudonym created",
        handelende_oin=handelende_oin,
        namens_oin=namens_oin,
        doel_oin=doel_oin,
        domein=req.recipientScope,
        sleutel_versie=pseudonym.version,
    )
    return Response(status_code=201, content=jwe, media_type="application/jwe")
