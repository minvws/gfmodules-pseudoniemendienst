import logging
from datetime import timezone, datetime

from fastapi import APIRouter, Query, Depends
from starlette.requests import Request
from starlette.responses import JSONResponse

from app import container
from app.config import get_config
from app.middleware.auth_required import auth_required
from app.services.bpg_service import BpgService
from app.services.pdn_service import PdnService
from app.services.rid_cache import RidCache
from app.services.rid_service import RidService, NoExchangeAllowedException, VerificationException, RidException
from app.services.tls_service import CertAuthentications, TLSService
from app.types import BasePseudonym, Rid, OrganisationId

logger = logging.getLogger(__name__)
router = APIRouter()

@router.post("/rid/exchange/pdn", summary="Exchange a RID for a PDN")
@auth_required([CertAuthentications.AUTH_UZI_CERT])
def exchange_to_pdn(
    request: Request,
    rid: str = Query(str, description="The RID to exchange"),
    org_id: str = Query(str, description="The organization ID"),
    rid_service: RidService = Depends(container.get_rid_service),
    rid_cache: RidCache = Depends(container.get_rid_cache),
    pdn_service: PdnService = Depends(container.get_pdn_service),
):
    """
    Converts a RID into a PDN for the specific organisation
    """
    result = verify_rid(rid_service, rid_cache, Rid(rid))
    if isinstance(result, JSONResponse):
        logger.error(f"Error verifying RID: {result.body}")
        return result

    bp = rid_service.extract_bp(Rid(rid))
    if not bp:
        return JSONResponse({"error": "Invalid BP"}, status_code=400)

    pdn = pdn_service.exchange(bp, OrganisationId(org_id))

    # Remove from cache so it can't be exchanged again
    rid_cache.remove_rid_from_cache(Rid(rid))

    return JSONResponse({"pdn": str(pdn)})


@router.post("/bp/exchange/rid", summary="generate a RID from a BP")
@auth_required([CertAuthentications.AUTH_UZI_CERT])
def exchange_bp_to_rid(
    request: Request,
    bp: str = Query(str, description="The BP to generate a RID for"),
    rid_service: RidService = Depends(container.get_rid_service),
    bpg_service: BpgService = Depends(container.get_bpg_service),
):
    if not bpg_service.is_valid(BasePseudonym(bp)):
        logger.error(f"Invalid BP: {bp}")
        return JSONResponse({"error": "Invalid BP"}, status_code=400)

    try:
        rid = rid_service.exchange_bp(BasePseudonym(bp), get_issuer(request))
        return JSONResponse([str(rid)])
    except NoExchangeAllowedException:
        logger.error("No more exchanges allowed for this RID")
        return JSONResponse({"error": "No more exchanges allowed for this RID"}, status_code=400)
    except Exception as e:
        logger.error("General exception while generating RID: " + str(e))
        return JSONResponse({"error": "Error generating RID"}, status_code=500)


@router.post("/rid/exchange/rid")
@auth_required([CertAuthentications.AUTH_ALL])
def exchange_to_rids(
    request: Request,
    rid: str = Query(str, description="The RID to exchange"),
    count: int = Query(1, description="The number of RIDs to exchange"),
    rid_service: RidService = Depends(container.get_rid_service),
):
    """
    Exchange a RID for a set of new RIDs
    """
    if count < 1:
        return JSONResponse({"error": "Invalid count"}, status_code=400)
    if count > 100:
        return JSONResponse({"error": "Count too high"}, status_code=400)

    if not rid_service.is_valid(Rid(rid)):
        logger.error(f"Invalid RID: {rid}")
        return JSONResponse({"error": "Invalid RID"}, status_code=400)

    try:
        new_rids = rid_service.exchange_rid(Rid(rid), count=count, issuer=get_issuer(request))
    except NoExchangeAllowedException:
        logger.error("No more exchanges allowed for this RID")
        return JSONResponse({"error": "No more exchanges allowed for this RID"}, status_code=400)

    return JSONResponse([str(rid) for rid in new_rids])



def verify_rid(rid_service: RidService, rid_cache: RidCache, rid: Rid) -> JSONResponse|None:
    """
    Verify that a RID can be exchanged. Will return a JSONResponse on error, or None if all is good and we can continue
    """

    # Verify (and decode) the RID first
    try:
        parts = rid_service.verify_and_decode_rid(rid)
    except RidException as e:
        logger.error(f"Error verifying RID: {e}")
        return JSONResponse({"error": "Error verifying RID"}, status_code=400)

    # Check if the RID is cached. If not, we can't exchange it
    if not rid_cache.is_rid_cached(rid):
        logger.warning(f"RID not found in cache: {rid}. It's already exchanged")
        return JSONResponse({"error": "RID already exchanged"}, status_code=400)

    # Only VAD issued RIDs can be exchanged for PDNs
    if parts["iss"] == "VAD":
        if parts['iat'] + get_config().rid.max_age_for_pdn_exchange_via_vad < datetime.now(
                tz=timezone.utc).timestamp():
            logger.warning(f"RID expired for VAD: {rid}")
            return JSONResponse({"error": "RID expired"}, status_code=400)
    elif parts["iss"] == "PRS":
        if parts['iat'] + get_config().rid.max_age_for_pdn_exchange_via_healthcare_provider < datetime.now(
                tz=timezone.utc).timestamp():
            logger.warning(f"RID expired for PRS: {rid}")
            return JSONResponse({"error": "RID expired"}, status_code=400)
    else:
        logger.error(f"Invalid issuer for RID: {rid}")
        return JSONResponse({"error": "Only VAD and PRS RIDs can be exchanged"}, status_code=400)

    # All is good
    return None


def get_issuer(request: Request) -> str:
    """
    The issuser depends on the certificate that is used to authenticate the request
    :return:
    """
    tls_service = TLSService()
    cert_type = tls_service.get_certificate_type(request)

    if cert_type == CertAuthentications.AUTH_UZI_CERT:
        return "VAD"
    elif cert_type == CertAuthentications.AUTH_OV_CERT:
        return "PRS"
    elif cert_type == CertAuthentications.AUTH_EV_CERT:
        return "PRS"

    logger.error(f"Invalid certificate type: {cert_type}")
    raise Exception("Invalid certificate type")
