import logging
from typing import Annotated

import gfmodules.logging as gflog
from fastapi import APIRouter, Depends, Security
from jwcrypto.jwk import JWK
from starlette.responses import Response

from app import container
from app.auth import require_scopes
from app.enums.personal_id_type import PersonalIdType
from app.exceptions import PseudonymOperationError
from app.logging.events import Log
from app.models.auth.context import AuthContext
from app.models.auth.data import AuthorizationScope
from app.models.requests import ReversiblePseudonymExchangeRequest
from app.services.authorization_service import AuthorizationService
from app.services.exchange_support import (
    authorize_exchange,
    raise_pseudonym_error,
    resolve_personal_id,
)
from app.services.jwe_token import Jwe
from app.services.organization_public_key_service import OrganizationPublicKeyService
from app.services.reversible.service import ReversiblePseudonymService

logger = logging.getLogger(__name__)
router = APIRouter()

_ENDPOINT = "/exchange/reversible-pseudonym"
_OPERATION = "exchange:reversible-pseudonym"
_SUBJECT_PREFIX = "pseudonym:reversible:"


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
        400: {
            "description": (
                "The personal ID is malformed, or the reversible pseudonym "
                "cannot be reversed for the calling organization."
            )
        },
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
        410: {
            "description": (
                "The reversiblePseudonym was issued under a key version of the "
                "calling organization that has since been destroyed, so it can "
                "no longer be reversed."
            )
        },
        500: {"description": "The pseudonym could not be produced."},
        503: {"description": "The HSM could not be reached; retry later."},
    },
    description="""
Exchange a personal ID for a reversible pseudonym bound to the recipient
organization and scope. The pseudonym is deterministic for the same input and
can only be reversed to the personal ID by the PRS itself.

Instead of a personal ID, `reversiblePseudonym` may hold a reversible
pseudonym that was issued to the calling organization; the PRS reverses it
first and uses the resulting personal ID.

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
    audit = authorize_exchange(
        logger,
        authorization_service,
        auth,
        req.recipientOrganization,
        PersonalIdType.REVERSIBLE_PSEUDONYM,
        _OPERATION,
    )

    personal_id = resolve_personal_id(
        logger, req.personalId, req.reversiblePseudonym, auth, pseudonym_service, audit
    )

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
    except PseudonymOperationError as e:
        raise_pseudonym_error(logger, audit, e)

    jwe = Jwe.build(
        audience=audit.doel_oin,
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
            **audit.fields(),
            "domein": req.recipientScope,
            "sleutel_versie": pseudonym.version,
        },
    )
    return Response(status_code=201, content=jwe, media_type="application/jwe")
