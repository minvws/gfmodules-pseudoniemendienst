import logging

from fastapi import APIRouter, Depends
from starlette.responses import JSONResponse

from app import container
from app.models.oin import Oin
from app.models.requests import BlindRequest
from app.services.key_resolver import KeyResolver
from app.services.oprf.oprf_service import OprfService
from app.services.org_service import OrgService

logger = logging.getLogger(__name__)
router = APIRouter()


@router.post(
    "/oprf/eval",
    summary="Evaluate OPRF blind and returns an encrypted JWE for the organization",
    tags=["OPRF Services"],
)
def post_eval(
    req: BlindRequest,
    key_resolver: KeyResolver = Depends(container.get_key_resolver),
    org_service: OrgService = Depends(container.get_org_service),
    oprf_service: OprfService = Depends(container.get_oprf_service),
) -> JSONResponse:
    if not req.recipientOrganization.startswith("oin:"):
        logger.warning("does not start with oin: %s" % req.recipientOrganization)
        return JSONResponse(
            {"error": "Invalid recipient organization. Format: oin:<oin_number>"},
            status_code=400,
        )
    oin = Oin(req.recipientOrganization[4:])

    org = org_service.get_by_oin(oin)
    if org is None:
        logger.warning("no organization found for OIN %r", oin)
        return JSONResponse(
            {"error": "No organization found for this OIN"}, status_code=404
        )
    pub_key_jwk = key_resolver.resolve(org.id, req.recipientScope)
    if pub_key_jwk is None:
        logger.warning(
            "no public key found for organization %r and scope %r",
            org.id,
            req.recipientScope,
        )
        return JSONResponse(
            {"error": "No public key found for this organization and/or scope"},
            status_code=404,
        )

    try:
        jwe_str = oprf_service.eval_blind(req, pub_key_jwk)
    except ValueError as e:
        logger.warning("unable to evaluate blind: %r", e)
        return JSONResponse({"error": "Unable to evaluate blind"}, status_code=400)

    return JSONResponse({"jwe": jwe_str})
