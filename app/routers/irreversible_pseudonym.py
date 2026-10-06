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
from app.models.requests import IrreversiblePseudonymExchangeRequest
from app.services.authorization_service import AuthorizationService
from app.services.exchange_support import (
    authorize_exchange,
    raise_pseudonym_error,
    resolve_personal_id,
)
from app.services.irreversible.service import IrreversiblePseudonymService
from app.services.jwe_token import Jwe
from app.services.organization_public_key_service import OrganizationPublicKeyService
from app.services.reversible.service import ReversiblePseudonymService

logger = logging.getLogger(__name__)
router = APIRouter()

_ENDPOINT = "/exchange/irreversible-pseudonym"
_OPERATION = "exchange:irreversible-pseudonym"
_SUBJECT_PREFIX = "pseudonym:irreversible:"


@router.post(
    _ENDPOINT,
    summary="Exchange a personal ID or reversible pseudonym for an irreversible pseudonym",
    tags=["Exchange Services"],
    status_code=201,
    response_class=Response,
    responses={
        201: {
            "description": (
                "A JWE encrypted to the recipient's public key for the scope. Its "
                "decrypted `subject` claim is `pseudonym:irreversible:<...>` for "
                "the recipient's latest key version; during a key rotation the "
                "`extraVersions` claim holds the pseudonym per older active version."
            ),
            "content": {"application/jwe": {}},
        },
        400: {
            "description": (
                "The personal ID is malformed, or the reversible pseudonym cannot "
                "be reversed for the calling organization."
            )
        },
        403: {
            "description": (
                "Insufficient scope (the token requires `prs:pseudonym`), the "
                "calling organization is not registered, or it is not allowed to "
                "request irreversible pseudonyms."
            )
        },
        404: {
            "description": (
                "The recipient organization is unknown, is not allowed to receive "
                "irreversible pseudonyms, has no public key registered for the "
                "scope, or has no active HSM key version."
            )
        },
        410: {
            "description": (
                "The reversible pseudonym was issued under a key version of the "
                "calling organization that has since been destroyed, so it can "
                "no longer be reversed."
            )
        },
        500: {"description": "The pseudonym could not be produced."},
        503: {"description": "The HSM could not be reached; retry later."},
    },
    description="""
Exchange a personal ID for an irreversible pseudonym bound to the recipient
organization and scope. The pseudonym is a keyed one-way function
(HMAC-SHA256 under the recipient's key version) of the personal ID: it is
deterministic for the same input, and nobody, the PRS included, can reverse it.

Instead of a personal ID, `reversiblePseudonym` may hold a reversible
pseudonym that was issued to the calling organization; the PRS reverses it
first and never returns the personal ID.

Requires the `prs:pseudonym` OAuth scope. Before the input is processed, two
administrator-managed authorizations are checked: the calling organization
must be allowed to request irreversible pseudonyms, and the recipient
organization must be allowed to receive them. The sender is checked first, so
an unauthorized caller cannot probe which recipient organizations exist.
""",
)
def exchange_irreversible_pseudonym(
    req: IrreversiblePseudonymExchangeRequest,
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
        IrreversiblePseudonymService,
        Depends(container.get_irreversible_pseudonym_service),
    ],
    reversible_service: Annotated[
        ReversiblePseudonymService,
        Depends(container.get_reversible_pseudonym_service),
    ],
) -> Response:
    audit = authorize_exchange(
        logger,
        authorization_service,
        auth,
        req.recipientOrganization,
        PersonalIdType.IRREVERSIBLE_PSEUDONYM,
        _OPERATION,
    )

    personal_id = resolve_personal_id(
        logger,
        req.personalId,
        req.reversiblePseudonym,
        auth,
        reversible_service,
        audit,
    )

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

    extra_claims: dict[str, object] = {"keyVersion": pseudonym.version}
    if pseudonym.older:
        extra_claims["extraVersions"] = {
            str(version): value for version, value in sorted(pseudonym.older)
        }
    jwe = Jwe.build(
        audience=audit.doel_oin,
        scope=req.recipientScope,
        subject=_SUBJECT_PREFIX + pseudonym.value,
        pub_key=JWK(**public_key.jwk),
        extra_claims=extra_claims,
    )

    if pseudonym.older:
        gflog.emit(
            logger,
            Log.PSEUDONYM_IRREVERSIBLE_DUAL_CREATED,
            "Irreversible pseudonym created for old and current key version",
            fields={
                **audit.fields(),
                "domein": req.recipientScope,
                "sleutel_versie_oud": max(version for version, _ in pseudonym.older),
                "sleutel_versie_actueel": pseudonym.version,
            },
        )
    else:
        gflog.emit(
            logger,
            Log.PSEUDONYM_IRREVERSIBLE_CREATED,
            "Irreversible pseudonym created",
            fields={
                **audit.fields(),
                "domein": req.recipientScope,
                "sleutel_versie": pseudonym.version,
            },
        )
    return Response(status_code=201, content=jwe, media_type="application/jwe")
