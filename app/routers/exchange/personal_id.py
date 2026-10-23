import logging
from typing import Annotated

import gfmodules.logging as gflog
from fastapi import APIRouter, Depends, Security
from jwcrypto.jwk import JWK
from starlette.responses import Response

from app import container
from app.auth import require_scopes
from app.enums.personal_id_type import PersonalIdType
from app.exceptions.access import UnauthorizedRequestError
from app.exceptions.pseudonym import PseudonymOperationError
from app.logging.events import Log
from app.logging.exchange_audit import ExchangeAudit
from app.models.auth.context import AuthContext
from app.models.auth.data import AuthorizationScope
from app.models.oin import RecipientOrganizationOin
from app.models.requests.exchange import PersonalIdFromReversiblePseudonymRequest
from app.routers.exchange.support import authorize_exchange, log_pseudonym_failure
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
                "A JWE encrypted to the calling organization's public key for the scope. "
                "Its decrypted `subject` is the canonical personal ID "
                "(`<landCode>:<type>:<value>`); no pseudonym key-version claims "
                "are included."
            ),
            "content": {"application/jwe": {}},
        },
        400: {"description": "The pseudonym cannot be reversed for the caller."},
        403: {
            "description": (
                "Missing `prs:pseudonym` scope, an unregistered caller, the "
                "caller is not allowed to request reversible pseudonyms, or "
                "`recipientOrganization` does not match the verified caller."
            )
        },
        404: {
            "description": (
                "The caller is not allowed to receive reversible pseudonyms, "
                "or has no public key registered for the scope."
            )
        },
        410: {
            "description": "The source pseudonym's key version has since been destroyed."
        },
        500: {"description": "The personal ID exchange failed."},
        503: {"description": "The HSM could not be reached; retry later."},
    },
    description="""
Reverse a pseudonym issued to the verified calling organization and encrypt the
canonical personal ID to that same organization's registered public key. Accepts
the bare pseudonym or its `pseudonym:reversible:` subject prefix.

`recipientOrganization` is required and must match the verified calling organization.
`recipientScope` selects the caller's delivery key and may differ from the source
pseudonym's scope.

Requires `prs:pseudonym` and reuses the administrator-managed
`reversible_pseudonym` grants: the caller must be allowed to both request and
receive that type. These grants therefore also authorize recovering a personal ID.

The caller needs a public encryption key registered for the requested scope.
""",
)
def exchange_personal_id(
    req: PersonalIdFromReversiblePseudonymRequest,
    auth: Annotated[
        AuthContext,
        Security(require_scopes, scopes=[AuthorizationScope.PSEUDONYM.value]),
    ],
    authorization_service: Annotated[
        AuthorizationService, Depends(container.get_authorization_service)
    ],
    organization_public_key_service: Annotated[
        OrganizationPublicKeyService,
        Depends(container.get_organization_public_key_service),
    ],
    reversible_service: Annotated[
        ReversiblePseudonymService,
        Depends(container.get_reversible_pseudonym_service),
    ],
) -> Response:
    recipient = RecipientOrganizationOin(auth.claims.organization_id)
    # TODO: Verify whether personal-ID recovery must remain caller-only or allow
    # cross-organization delivery (PRS-DOC-DRFT.pdf §8.13).
    if req.recipientOrganization != recipient:
        gflog.emit(
            logger,
            Log.AUTHORIZATION_DENIED,
            "Authorization denied (recipient_must_match_caller)",
            fields={
                **ExchangeAudit.from_auth(auth, req.recipientOrganization).fields(),
                "requested_operation": _OPERATION,
            },
        )
        raise UnauthorizedRequestError()

    # TODO: Replace reversible-pseudonym grants with separate administrator-managed
    # personal-ID delivery and receive grants (PRS-DOC-DRFT.pdf,
    # §§7.2.32–35, 10.23; flow §8.13.2).
    authorize_exchange(
        logger,
        authorization_service,
        auth,
        recipient,
        PersonalIdType.REVERSIBLE_PSEUDONYM,
        _OPERATION,
    )
    audit = ExchangeAudit.from_auth(auth, recipient)
    public_key = organization_public_key_service.get_by_org_and_domain(
        recipient, req.recipientScope
    )

    try:
        reversed_pseudonym = reversible_service.reverse(
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
        audience=str(recipient),
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
