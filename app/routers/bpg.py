import logging

from fastapi import APIRouter, Query, Depends
from starlette.requests import Request
from starlette.responses import JSONResponse

from app import container
from app.bsn import is_valid_bsn
from app.middleware.auth_required import auth_required
from app.routers.rid import get_issuer
from app.services.bpg_service import BpgService
from app.services.pdn_service import PdnService
from app.services.rid_service import RidService
from app.services.tls_service import CertAuthentications
from app.prs_types import OrganisationId

logger = logging.getLogger(__name__)
router = APIRouter()

@router.post("/base_pseudonym")
@auth_required([CertAuthentications.AUTH_UZI_CERT])
def get_base_pseudonym(
    request: Request,
    bsn: str = Query(str, description="The BSN to generate a Base Pseudonym for"),
    bpg_service: BpgService = Depends(container.get_bpg_service),
) -> JSONResponse:
    """
    Converts a BSN into a Base Pseudonym (BP)
    """
    if not is_valid_bsn(bsn):
        logger.error(f"Invalid BSN: {bsn}")
        return JSONResponse({"error": "Invalid BSN"}, status_code=400)

    bp = bpg_service.exchange(bsn)
    if not bp:
        return JSONResponse({"error": "Invalid BP"}, status_code=400)

    return JSONResponse({"bp": str(bp)})

@router.post("/bsn/exchange/rid", summary="generate a RID directly from a BSN")
@auth_required([CertAuthentications.AUTH_UZI_CERT])
def exhange_to_rid(
    request: Request,
    bsn: str = Query(str, description="The BSN to generate a RID for"),
    bpg_service: BpgService = Depends(container.get_bpg_service),
    rid_service: RidService = Depends(container.get_rid_service)
) -> JSONResponse:
    """
    Converts a BSN into a Base Pseudonym (BP)
    """
    if not is_valid_bsn(bsn):
        logger.error(f"Invalid BSN: {bsn}")
        return JSONResponse({"error": "Invalid BSN"}, status_code=400)

    bp = bpg_service.exchange(bsn)
    if not bp:
        return JSONResponse({"error": "Cannot generate BP"}, status_code=400)

    rid = rid_service.exchange_bp(bp, get_issuer(request))
    if not rid:
        return JSONResponse({"error": "Cannot generate RID"}, status_code=400)

    return JSONResponse({"rid": str(bp)})


@router.post("/org_pseudonym")
@auth_required([CertAuthentications.AUTH_UZI_CERT])
def get_org_pseudonym(
        request: Request,
        bsn: str = Query(str, description="The BSN to generate the PDN for"),
        org_id: str = Query(str, description="The organisation ID for this PDN"),
        bpg_service: BpgService = Depends(container.get_bpg_service),
        pdn_service: PdnService = Depends(container.get_pdn_service),
) -> JSONResponse:
    """
    Converts a BSN into a Pseudonym (PDN) for a specific organisation
    """
    if not is_valid_bsn(bsn):
        logger.error(f"Invalid BSN: {bsn}")
        return JSONResponse({"error": "Invalid BSN"}, status_code=400)

    bp = bpg_service.exchange(bsn)
    if not bp:
        return JSONResponse({"error": "Invalid BP"}, status_code=400)

    pdn = pdn_service.exchange(bp, OrganisationId(org_id))

    return JSONResponse({"pdn": str(pdn)})
