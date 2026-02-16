import logging

from fastapi import APIRouter, Depends
from starlette.responses import JSONResponse

from app import container
from app.services.key_resolver import KeyResolver
from app.services.oprf.oprf_service import BlindRequest, OprfService
from app.services.org_service import OrgService

logger = logging.getLogger(__name__)
router = APIRouter()

@router.post("/oprf/eval", summary="Evaluate OPRF blind and returns an encrypted JWE for the organization", tags=["OPRF Services"])
def post_eval(
    req: BlindRequest,
    key_resolver: KeyResolver = Depends(container.get_key_resolver),
    org_service: OrgService = Depends(container.get_org_service),
    oprf_service: OprfService = Depends(container.get_oprf_service),
) -> JSONResponse:

    if not req.recipientOrganization.startswith("ura:"):
        logger.error("does not start with ura: %s" % req.recipientOrganization)
        return JSONResponse({"error": "Invalid recipient organization. Format: ura:<ura_number>"}, status_code=400)
    ura = req.recipientOrganization[4:]

    org = org_service.get_by_ura(ura)
    if org is None:
        logger.error("no organization found for URA %r", ura)
        return JSONResponse({"error": "No organization found for this ura"}, status_code=404)

    pub_key_jwk = key_resolver.resolve(org.id, req.recipientScope)
    if pub_key_jwk is None:
        logger.error("no public key found for organization %r and scope %r", org.id, req.recipientScope)
        return JSONResponse({"error": "No public key found for this organization and/or scope"}, status_code=404)


    try:
        jwe_str = oprf_service.eval_blind(req, pub_key_jwk)
    except ValueError as e:
        logger.exception("unable to evaluate blind: %r", e)
        return JSONResponse({"error": "Unable to evaluate blind"}, status_code=400)

    return JSONResponse({"jwe": jwe_str})
