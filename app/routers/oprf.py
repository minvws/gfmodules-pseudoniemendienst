import logging

from fastapi import APIRouter, Depends
from starlette.responses import JSONResponse

from app import container
from app.services.key_resolver import KeyResolver
from app.services.oprf.oprf_service import BlindRequest, OprfService

logger = logging.getLogger(__name__)
router = APIRouter()

@router.post("/oprf/eval", summary="Evaluate OPRF blind and returns an encrypted JWE for the organization", tags=["oprf"])
def post_eval(
    req: BlindRequest,
    key_resolver: KeyResolver = Depends(container.get_key_resolver),
    oprf_service: OprfService = Depends(container.get_oprf_service),
) -> JSONResponse:

    pub_key_jwk = key_resolver.resolve(req.recipientOrganization, req.recipientScope)
    if pub_key_jwk is None:
        return JSONResponse({"error": "No public key found for this organization"}, status_code=404)


    try:
        jwe_str = oprf_service.eval_blind(req, pub_key_jwk)
    except ValueError as e:
        logger.warning(f"Unable to evaluate blind: {e}")
        return JSONResponse({"error": "Unable to evaluate blind"}, status_code=400)

    return JSONResponse({"jwe": jwe_str})

