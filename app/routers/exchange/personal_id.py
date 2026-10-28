import logging
from typing import Annotated

import gfmodules.logging as gflog
from fastapi import APIRouter, Depends, Security
from jwcrypto.jwk import JWK
from starlette.responses import Response

from app import container
from app.auth import require_scopes
from app.enums.personal_id_type import PersonalIdType
from app.exceptions.pseudonym import PseudonymOperationError
from app.logging.events import Log
from app.logging.exchange_audit import ExchangeAudit
from app.models.auth.context import AuthContext
from app.models.auth.data import AuthorizationScope
from app.models.requests.exchange import ReversiblePseudonymInputRequest
from app.routers.exchange.support import (
    authorize_exchange,
    get_recipient_public_key,
    log_pseudonym_failure,
)
from app.services.authorization_service import AuthorizationService
from app.services.jwe_token import Jwe
from app.services.organization_public_key_service import OrganizationPublicKeyService
from app.services.reversible.service import ReversiblePseudonymService

logger = logging.getLogger(__name__)
router = APIRouter()

_OPERATION = "exchange:personal-id"


@router.post(
    "/personal-id",
    summary="Exchange a reversible pseudonym for a personal ID",
    status_code=201,
    response_class=Response,
    responses={
        201: {
            "description": (
                "A JWE encrypted to the recipient's public key for the scope. Its "
                "decrypted `subject` claim is the personal ID."
            ),
            "content": {"application/jwe": {}},
        },
        400: {
            "description": (
                "The reversible pseudonym cannot be reversed for the calling "
                "organization."
            )
        },
        403: {
            "description": (
                "Insufficient scope (the token requires `prs:pseudonym`), the "
                "calling organization is not registered, or it is not allowed to "
                "request personal IDs."
            )
        },
        404: {
            "description": (
                "The recipient organization is unknown, is not allowed to receive "
                "personal IDs, or has no public key registered for the scope."
            )
        },
        410: {
            "description": (
                "The reversible pseudonym was issued under a key version of the "
                "calling organization that is no longer active."
            )
        },
        500: {"description": "The personal ID could not be recovered."},
        503: {"description": "The HSM could not be reached; retry later."},
    },
    description="""
Exchange a reversible pseudonym that was issued to the calling organization for
the personal ID it was made from, encrypted to the recipient organization's
public key for the scope. The pseudonym is accepted as the bare value or as
received (`pseudonym:reversible:<...>`).

Requires the `prs:pseudonym` OAuth scope. Before the pseudonym is reversed, two
administrator-managed authorizations are checked: the calling organization must
be allowed to request personal IDs, and the recipient organization must be
allowed to receive them. The sender is checked first, so an unauthorized caller
cannot probe which recipient organizations exist.
""",
)
def exchange_personal_id(
    req: ReversiblePseudonymInputRequest,
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
    authorize_exchange(
        logger,
        authorization_service,
        auth,
        req.recipientOrganization,
        PersonalIdType.PERSONAL_ID,
        _OPERATION,
    )
    audit = ExchangeAudit.from_auth(auth, req.recipientOrganization)

    public_key = get_recipient_public_key(
        logger,
        organization_public_key_service,
        audit,
        req.recipientOrganization,
        req.recipientScope,
    )

    try:
        reversed_pseudonym = pseudonym_service.reverse(
            req.reversiblePseudonym, auth.claims.organization_id
        )
    except PseudonymOperationError as e:
        log_pseudonym_failure(
            logger,
            audit,
            e,
            Log.PERSONAL_ID_EXCHANGE_FAILED,
            "Personal ID exchange failed",
        )
        raise

    jwe = Jwe.build(
        audience=str(req.recipientOrganization),
        scope=req.recipientScope,
        subject=reversed_pseudonym.personal_id.as_str(),
        pub_key=JWK(**public_key.jwk),
    )

    gflog.emit(
        logger,
        Log.PERSONAL_ID_EXCHANGED,
        "Personal ID exchanged",
        fields={
            **audit.fields(),
            "domein": req.recipientScope,
            "sleutel_versie": reversed_pseudonym.version,
            "ontvanger_pubkey_id": public_key.jwk.get("kid"),
        },
    )
    return Response(status_code=201, content=jwe, media_type="application/jwe")
