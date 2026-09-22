import logging
from typing import Annotated

import gfmodules.logging as gflog
from fastapi import APIRouter, Depends, HTTPException, Security
from jwcrypto.jwk import JWK
from starlette.responses import JSONResponse

from app import container
from app.auth import require_scopes
from app.enums.personal_id_type import PersonalIdType
from app.exceptions import DomainError
from app.logging.events import Log
from app.models.auth.context import AuthContext
from app.models.auth.data import AuthorizationScope
from app.models.requests import BlindRequest
from app.services.authorization_service import AuthorizationService
from app.services.oprf.oprf_service import OprfService
from app.services.organization_public_key_service import OrganizationPublicKeyService

logger = logging.getLogger(__name__)
router = APIRouter()

_ENDPOINT = "/oprf/eval"


@router.post(
    _ENDPOINT,
    summary="Evaluate OPRF blind and returns an encrypted JWE for the organization",
    tags=["OPRF Services"],
)
def post_eval(
    req: BlindRequest,
    oprf_service: Annotated[OprfService, Depends(container.get_oprf_service)],
    organization_public_key_service: Annotated[
        OrganizationPublicKeyService,
        Depends(container.get_organization_public_key_service),
    ],
    authorization_service: Annotated[
        AuthorizationService, Depends(container.get_authorization_service)
    ],
    auth_ctx: Annotated[
        AuthContext,
        Security(
            require_scopes,
            scopes=[AuthorizationScope.OPRF_PSEUDONYM.value],
        ),
    ],
) -> JSONResponse:
    recipient_oin = req.recipientOrganization
    personal_id_type = PersonalIdType.OPRF

    # Audit identities (PRS-OPRF): the acting client and the organization it
    # acts on behalf of come from the proxy-verified headers, the target from
    # the request body.
    audit_oins = {
        "handelende_oin": str(auth_ctx.claims.client_organization_id),
        "namens_oin": str(auth_ctx.claims.organization_id),
        "doel_oin": str(recipient_oin),
    }

    authorization_service.validate_allowed_to_request(
        auth_ctx.claims.organization_id, personal_id_type
    )

    try:
        authorization_service.validate_allowed_to_receive(
            recipient_oin, personal_id_type
        )
        organization_public_key = organization_public_key_service.get_by_org_and_domain(
            recipient_oin, req.recipientScope
        )
    except DomainError as e:
        # PRS-OPRF-004: the target organization is unknown, may not receive
        # OPRF pseudonyms, or has no public key registered for the scope.
        gflog.emit(
            logger,
            Log.OPRF_REFUSED_NO_ACTIVE_PUBKEY,
            f"OPRF refused: {e.message}",
            fields=audit_oins,
        )
        raise

    try:
        result = oprf_service.eval_blind(req, JWK(**organization_public_key.jwk))
    except ValueError as e:
        # PRS-OPRF-003
        gflog.emit(
            logger,
            Log.OPRF_EVAL_FAILED,
            "OPRF evaluation failed",
            fields={
                **audit_oins,
                "error_type": getattr(e, "error_type", "crypto_evaluation_failure"),
            },
        )
        raise HTTPException(status_code=400, detail="Unable to evaluate blind") from e

    # PRS-OPRF-001
    gflog.emit(
        logger,
        Log.OPRF_EVAL_OK,
        "OPRF evaluation succeeded",
        fields={
            **audit_oins,
            "oprf_secret_versie": max(result.key_versions),
            "ontvanger_pubkey_id": organization_public_key.jwk.get("kid"),
        },
    )
    return JSONResponse({"jwe": result.jwe})
