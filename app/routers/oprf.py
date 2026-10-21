import logging
from typing import Annotated

import gfmodules.logging as gflog
from fastapi import APIRouter, Depends, HTTPException, Security
from jwcrypto.jwk import JWK
from starlette.responses import JSONResponse

from app import container
from app.auth import require_scopes
from app.enums.personal_id_type import PersonalIdType
from app.enums.pseudonym_error_type import PseudonymErrorType
from app.exceptions import DomainError, PseudonymOperationError
from app.logging.events import Log
from app.logging.exchange_audit import ExchangeAudit
from app.models.auth.context import AuthContext
from app.models.auth.data import AuthorizationScope
from app.models.requests import BlindRequest
from app.routers.exchange.support import authorize_exchange
from app.services.authorization_service import AuthorizationService
from app.services.oprf.oprf_service import OprfService
from app.services.organization_public_key_service import OrganizationPublicKeyService

logger = logging.getLogger(__name__)
router = APIRouter()

EVAL_FAILURE_STATUS_CODES = {
    PseudonymErrorType.INVALID_BLINDED_INPUT: 400,
    PseudonymErrorType.HSM_OPERATION_FAILED: 502,
    PseudonymErrorType.HSM_UNREACHABLE: 503,
    PseudonymErrorType.HSM_TIMEOUT: 504,
}


@router.post(
    "/oprf/eval",
    summary="Evaluate OPRF blind and returns an encrypted JWE for the organization",
    tags=["OPRF Services"],
    responses={
        400: {"description": "The blinded input is invalid."},
        403: {
            "description": (
                "Insufficient scope (the token requires `prs:oprf-pseudonym`), the "
                "calling organization is not registered, or it is not allowed to "
                "request OPRF pseudonyms."
            )
        },
        404: {
            "description": (
                "The recipient organization is unknown, is not allowed to receive "
                "OPRF pseudonyms, has no public key registered for the scope, or "
                "has no active HSM key version."
            )
        },
        502: {"description": "The HSM refused the evaluation."},
        503: {"description": "The HSM could not be reached; retry later."},
        504: {"description": "The HSM did not answer in time; retry later."},
    },
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
    authorize_exchange(
        logger,
        authorization_service,
        auth_ctx,
        req.recipientOrganization,
        PersonalIdType.OPRF,
        "oprf:eval",
    )
    audit = ExchangeAudit.from_auth(auth_ctx, req.recipientOrganization)

    try:
        organization_public_key = organization_public_key_service.get_by_org_and_domain(
            req.recipientOrganization, req.recipientScope
        )
        result = oprf_service.eval_blind(req, JWK(**organization_public_key.jwk))
    except DomainError as e:
        gflog.emit(
            logger,
            Log.OPRF_REFUSED_NO_ACTIVE_PUBKEY,
            f"OPRF refused: {e.message}",
            fields=audit.fields(),
        )
        raise
    except PseudonymOperationError as e:
        # PRS-OPRF-003
        gflog.emit(
            logger,
            Log.OPRF_EVAL_FAILED,
            "OPRF evaluation failed",
            fields={**audit.fields(), "error_type": e.error_type},
        )
        raise HTTPException(
            status_code=EVAL_FAILURE_STATUS_CODES[e.error_type],
            detail="Unable to evaluate blind",
        ) from e

    # PRS-OPRF-001
    gflog.emit(
        logger,
        Log.OPRF_EVAL_OK,
        "OPRF evaluation succeeded",
        fields={
            **audit.fields(),
            "oprf_secret_versie": max(result.key_versions),
            "ontvanger_pubkey_id": organization_public_key.jwk.get("kid"),
        },
    )
    return JSONResponse({"jwe": result.jwe})
