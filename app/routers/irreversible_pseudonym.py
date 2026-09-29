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
from app.models.requests import IrreversiblePseudonymExchangeRequest
from app.personal_id import PersonalId, PersonalIdValidationError
from app.services.authorization_service import AuthorizationService
from app.services.irreversible.service import (
    IrreversiblePseudonymError,
    IrreversiblePseudonymService,
)
from app.services.oprf.jwe_token import BlindJwe
from app.services.organization_public_key_service import OrganizationPublicKeyService
from app.services.reversible.service import (
    ReversiblePseudonymError,
    ReversiblePseudonymService,
)

logger = logging.getLogger(__name__)
router = APIRouter()

_ENDPOINT = "/exchange/irreversible-pseudonym"
_OPERATION = "exchange:irreversible-pseudonym"
_SUBJECT_PREFIX = "pseudonym:irreversible:"
_REVERSIBLE_PREFIX = "pseudonym:reversible:"


def _parse_personal_id(raw: str | dict[str, str]) -> PersonalId:
    if isinstance(raw, str):
        return PersonalId.from_str(raw)
    return PersonalId.from_dict(raw)


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
        500: {"description": "The pseudonym could not be produced."},
        503: {"description": "The HSM could not be reached; retry later."},
    },
    description="""
Exchange a personal ID for an irreversible pseudonym bound to the recipient
organization and scope. The pseudonym is a keyed one-way function
(HMAC-SHA256 under the recipient's key version) of the personal ID: it is
deterministic for the same input, and nobody, the PRS included, can reverse it.

Instead of a personal ID, `personalId` may hold a reversible pseudonym
(`pseudonym:reversible:<...>`) that was issued to the calling organization;
the PRS reverses it first and never returns the personal ID.

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
    handelende_oin = str(auth.claims.client_organization_id)
    namens_oin = str(auth.claims.organization_id)
    doel_oin = str(req.recipientOrganization)
    audit = {
        "handelende_oin": handelende_oin,
        "namens_oin": namens_oin,
        "doel_oin": doel_oin,
    }

    def deny(reason: str, error: DomainError) -> None:
        gflog.emit(
            logger,
            Log.AUTHORIZATION_DENIED,
            f"Authorization denied ({reason}): {error.message}",
            fields={**audit, "requested_operation": _OPERATION},
        )

    def failed(error_type: str, exc: Exception | None = None) -> None:
        # PRS-PSE-004
        gflog.emit(
            logger,
            Log.PSEUDONYM_CREATE_FAILED,
            "Irreversible pseudonym creation failed",
            exc_info=exc,
            fields={**audit, "error_type": error_type},
        )

    personal_id_type = PersonalIdType.IRREVERSIBLE_PSEUDONYM
    try:
        authorization_service.validate_allowed_to_request(
            auth.claims.organization_id, personal_id_type
        )
    except DomainError as e:
        deny("sender_may_not_request_irreversible_pseudonym", e)
        raise

    try:
        authorization_service.validate_allowed_to_receive(
            req.recipientOrganization, personal_id_type
        )
    except DomainError as e:
        deny("recipient_may_not_receive_irreversible_pseudonym", e)
        raise

    if isinstance(req.personalId, str) and req.personalId.startswith(
        _REVERSIBLE_PREFIX
    ):
        # A reversible pseudonym issued to the caller; reverse it for them.
        try:
            reversed_pseudonym = reversible_service.reverse(
                req.personalId.removeprefix(_REVERSIBLE_PREFIX),
                auth.claims.organization_id,
            )
        except ReversiblePseudonymError as e:
            failed(e.error_type, e)
            if e.error_type == "hsm_unreachable":
                raise HTTPException(
                    status_code=503, detail="Pseudonym exchange failed"
                ) from e
            raise HTTPException(status_code=400, detail="Invalid pseudonym") from e
        personal_id = reversed_pseudonym.personal_id
    else:
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
    except IrreversiblePseudonymError as e:
        failed(e.error_type, e)
        if e.error_type == "no_active_key_version":
            # Same message as for an unknown recipient, so a caller cannot tell
            # the two apart.
            raise RecipientNotFoundError()
        status = 503 if e.error_type == "hsm_unreachable" else 500
        raise HTTPException(status_code=status, detail="Pseudonym exchange failed")

    extra_claims: dict[str, object] = {"keyVersion": pseudonym.version}
    if pseudonym.older:
        extra_claims["extraVersions"] = {
            str(version): value for version, value in sorted(pseudonym.older.items())
        }
    jwe = BlindJwe.build(
        audience=doel_oin,
        scope=req.recipientScope,
        subject=_SUBJECT_PREFIX + pseudonym.value,
        pub_key=JWK(**public_key.jwk),
        extra_claims=extra_claims,
    )

    if pseudonym.older:
        # PRS-PSE-003: dual-version during the grace period of a rotation.
        gflog.emit(
            logger,
            Log.PSEUDONYM_IRREVERSIBLE_DUAL_CREATED,
            "Irreversible pseudonym created for old and current key version",
            fields={
                **audit,
                "domein": req.recipientScope,
                "sleutel_versie_oud": max(pseudonym.older),
                "sleutel_versie_actueel": pseudonym.version,
            },
        )
    else:
        # PRS-PSE-002
        gflog.emit(
            logger,
            Log.PSEUDONYM_IRREVERSIBLE_CREATED,
            "Irreversible pseudonym created",
            fields={
                **audit,
                "domein": req.recipientScope,
                "sleutel_versie": pseudonym.version,
            },
        )
    return Response(status_code=201, content=jwe, media_type="application/jwe")
