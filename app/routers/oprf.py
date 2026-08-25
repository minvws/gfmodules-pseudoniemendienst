import json
import logging

from fastapi import APIRouter, Depends
from jwcrypto.jwk import JWK
from starlette.responses import JSONResponse

from app import container
from app.auth import get_auth_ctx
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
    auth: AuthContext = Depends(get_auth_ctx),
    oprf_service: OprfService = Depends(container.get_oprf_service),
    organization_public_key_service: OrganizationPublicKeyService = Depends(
        container.get_organization_public_key_service
    ),
    authorization_service: AuthorizationService = Depends(
        container.get_authorization_service
    ),
) -> JSONResponse:
    recipient_oin = req.recipientOrganization
    _object = "oprf"
    # TODO GB: enum receive and object
    print(authorization_service.exists(auth.claims.organization_id, "request", _object))
    if not authorization_service.exists(
        auth.claims.organization_id, "request", _object
    ):
        raise Exception("TODO NICE EXCEPTION, unauthorized to do this request")
    if not authorization_service.exists(recipient_oin, "receive", _object):
        raise Exception(
            "TODO NICE EXCEPTION, recipient organization not found (no authorization)"
        )

    organization_public_key = organization_public_key_service.get_by_org_and_domain(
        recipient_oin, req.recipientScope
    )
    if not organization_public_key:
        organization_public_key = organization_public_key_service.get_by_org_and_domain(
            recipient_oin, "*"
        )
    if not organization_public_key:
        raise Exception("TODO NICE EXCEPTION, Recipient not found")

    result = oprf_service.eval_blind(
        req, JWK(**json.loads(organization_public_key.jwk)), organization_public_key.kid
    )

    return JSONResponse({"jwe": result.jwe})
    # TODO GB: Check if recpipient has authorization
    # TODO GB: Fetch recipient pub key
    # org = org_service.get_by_oin(oin)
    # if org is None:
    #    log_event(
    #        logger,
    #        OPRF_REFUSED_NO_ACTIVE_PUBKEY,
    #        "OPRF refused: no organization found for target OIN",
    #        handelende_oin=handelende_oin,
    #        doel_oin=doel_oin,
    #        endpoint=_ENDPOINT,
    #    )
    #    return JSONResponse(
    #        {"error": "No organization found for this OIN"}, status_code=404
    #    )
    # key_entry = key_resolver.resolve_entry(org.id, req.recipientScope)
    # if key_entry is None:
    #    log_event(
    #        logger,
    #        OPRF_REFUSED_NO_ACTIVE_PUBKEY,
    #        "OPRF refused: target organization has no active public key for scope",
    #        handelende_oin=handelende_oin,
    #        doel_oin=doel_oin,
    #        endpoint=_ENDPOINT,
    #    )
    #    return JSONResponse(
    #        {"error": "No public key found for this organization and/or scope"},
    #        status_code=404,
    #    )
    # pub_key_jwk = jwk.JWK.from_pem(key_entry.key_data.encode("ascii"))

    # try:
    #    result = oprf_service.eval_blind(req, pub_key_jwk, key_entry.key_id)
    # except ValueError as e:
    #    log_event(
    #        logger,
    #        OPRF_EVAL_FAILED,
    #        "OPRF evaluation failed",
    #        handelende_oin=handelende_oin,
    #        doel_oin=doel_oin,
    #        error_type=getattr(e, "error_type", "crypto_evaluation_failure"),
    #        endpoint=_ENDPOINT,
    #    )
    #    return JSONResponse({"error": "Unable to evaluate blind"}, status_code=400)

    # log_event(
    #    logger,
    #    OPRF_EVAL_OK,
    #    "OPRF evaluation succeeded",
    #    handelende_oin=handelende_oin,
    #    doel_oin=doel_oin,
    #    oprf_secret_versie=max(result.key_versions),
    #    ontvanger_pubkey_id=key_entry.key_id,
    # )
    # return JSONResponse({"jwe": result.jwe})
