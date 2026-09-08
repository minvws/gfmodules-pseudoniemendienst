import logging
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Security
from starlette.responses import Response

from app import container
from app.auth import authenticated_organization, require_scopes
from app.db.entities.organization import Organization
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
from app.routers.exchange import OrganizationNotFound, PubKeyNotFound
from app.services.exchange_authorization import (
    ExchangeNotAuthorized,
    assert_may_provide_personal_id,
    assert_may_receive_reversible_pseudonym,
)
from app.services.key_resolver import KeyResolver
from app.services.oprf.jwe_token import BlindJwe
from app.services.org_service import OrgService
from app.services.pseudonym_service import PseudonymService

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
                "The token lacks the `prs:reversible-pseudonym` scope, the calling "
                "organization may not provide a personal ID, or the recipient "
                "organization may not receive reversible pseudonyms."
            )
        },
        404: {
            "description": (
                "The recipient organization is unknown or has no public key "
                "registered for the scope."
            )
        },
    },
    description="""
Exchange a personal ID for a reversible pseudonym bound to the recipient
organization and scope. The pseudonym is deterministic for the same input and
can only be reversed to the personal ID by the PRS itself.

Requires the `prs:reversible-pseudonym` OAuth scope. Before the personal ID is
processed, two administrator-managed authorizations are checked: the calling
organization (the verified `x-gf-sub` identity) must be allowed to provide a
personal ID, and the recipient organization must be allowed to receive
reversible pseudonyms. Either failing yields `403`.
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
    sender: Annotated[Organization, Depends(authenticated_organization)],
    org_service: Annotated[OrgService, Depends(container.get_org_service)],
    key_resolver: Annotated[KeyResolver, Depends(container.get_key_resolver)],
    pseudonym_service: Annotated[
        PseudonymService, Depends(container.get_pseudonym_service)
    ],
) -> Response:
    handelende_oin = str(auth.claims.client_organization_id)
    namens_oin = str(auth.claims.organization_id)
    doel_oin = str(req.recipientOrganization)

    def deny(error: ExchangeNotAuthorized) -> HTTPException:
        log_event(
            logger,
            AUTHORIZATION_DENIED,
            f"Authorization denied ({error.reason}): {error}",
            handelende_oin=handelende_oin,
            namens_oin=namens_oin,
            doel_oin=doel_oin,
            requested_operation=_OPERATION,
            endpoint=_ENDPOINT,
            method="POST",
        )
        return HTTPException(status_code=403, detail=str(error))

    try:
        assert_may_provide_personal_id(sender)
    except ExchangeNotAuthorized as e:
        raise deny(e)

    recipient = org_service.get_by_oin(req.recipientOrganization)
    if recipient is None:
        logger.warning("recipient organization not found for OIN: %s", doel_oin)
        raise OrganizationNotFound(req.recipientOrganization)

    try:
        assert_may_receive_reversible_pseudonym(recipient)
    except ExchangeNotAuthorized as e:
        raise deny(e)

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

    pub_key, pub_key_id = key_resolver.resolve(recipient.id, req.recipientScope)
    if pub_key is None:
        logger.warning(
            "no public key found for organization '%s' and scope '%s'",
            doel_oin,
            req.recipientScope,
        )
        raise PubKeyNotFound(recipient.oin, req.recipientScope)

    try:
        pseudonym = pseudonym_service.generate_reversible_pseudonym(
            personal_id=personal_id,
            recipient_organization=doel_oin,
            recipient_scope=req.recipientScope,
        )
    except ValueError as e:
        log_event(
            logger,
            PSEUDONYM_CREATE_FAILED,
            "Reversible pseudonym creation failed",
            exc_info=e,
            handelende_oin=handelende_oin,
            namens_oin=namens_oin,
            doel_oin=doel_oin,
            error_type="crypto_failure",
            endpoint=_ENDPOINT,
        )
        raise HTTPException(status_code=500, detail="Pseudonym exchange failed")

    jwe = BlindJwe.build(
        audience=doel_oin,
        scope=req.recipientScope,
        subject=_SUBJECT_PREFIX + pseudonym,
        pub_key=pub_key,
        pub_key_id=pub_key_id,
    )

    log_event(
        logger,
        PSEUDONYM_REVERSIBLE_CREATED,
        "Reversible pseudonym created",
        handelende_oin=handelende_oin,
        namens_oin=namens_oin,
        doel_oin=doel_oin,
        domein=req.recipientScope,
    )
    return Response(status_code=201, content=jwe, media_type="application/jwe")
