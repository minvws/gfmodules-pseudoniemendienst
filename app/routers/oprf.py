import logging
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from jwcrypto.jwk import JWK
from starlette.responses import JSONResponse

from app import container
from app.auth import get_auth_ctx
from app.enums.personal_id_type import PersonalIdType
from fastapi import APIRouter, Depends, Security
from jwcrypto import jwk
from starlette.responses import JSONResponse

from app import container
from app.auth import require_scopes
from app.logging.events import (
    OPRF_EVAL_FAILED,
    OPRF_EVAL_OK,
    OPRF_REFUSED_NO_ACTIVE_PUBKEY,
    log_event,
)
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
    "/oprf/eval",
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
    auth_ctx: AuthContext = Security(
        require_scopes, scopes=[AuthorizationScope.OPRF.value]
    ),
) -> JSONResponse:
    recipient_oin = req.recipientOrganization
    personal_id_type = PersonalIdType.OPRF
    authorization_service.validate_allowed_to_request(
        auth_ctx.claims.organization_id, personal_id_type
    )
    authorization_service.validate_allowed_to_receive(
        req.recipientOrganization, personal_id_type
    )

    organization_public_key = organization_public_key_service.get_by_org_and_domain(
        recipient_oin, req.recipientScope
    )
    try:
        result = oprf_service.eval_blind(req, JWK(**organization_public_key.jwk))
    except ValueError as e:
        raise HTTPException(status_code=400, detail="Unable to evaluate blind") from e

    return JSONResponse({"jwe": result.jwe})
