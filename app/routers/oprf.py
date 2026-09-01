import json
import logging
from typing import Annotated

from fastapi import APIRouter, Depends
from jwcrypto.jwk import JWK
from starlette.responses import JSONResponse

from app import container
from app.auth import get_auth_ctx
from app.enums.personal_id_type import PersonalIdType
from app.models.auth.context import AuthContext
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
    auth_ctx: Annotated[AuthContext, Depends(get_auth_ctx)],
    oprf_service: Annotated[OprfService, Depends(container.get_oprf_service)],
    organization_public_key_service: Annotated[
        OrganizationPublicKeyService,
        Depends(container.get_organization_public_key_service),
    ],
    authorization_service: Annotated[
        AuthorizationService, Depends(container.get_authorization_service)
    ],
) -> JSONResponse:
    recipient_oin = req.recipientOrganization
    personal_id_type = PersonalIdType.OPRF
    authorization_service.validate_allowed_to_request(
        auth_ctx.claims.organization_id, personal_id_type
    )
    authorization_service.validate_allowed_to_receive(
        req.recipientOrganization, personal_id_type
    )

    # TODO GB: Move to service to reuse db session
    organization_public_key = organization_public_key_service.get_by_org_and_domain(
        recipient_oin, req.recipientScope
    )
    result = oprf_service.eval_blind(req, JWK(**organization_public_key.jwk), None)

    return JSONResponse({"jwe": result.jwe})
