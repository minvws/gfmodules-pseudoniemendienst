import logging

from fastapi import APIRouter, Query, Depends
from starlette.requests import Request
from starlette.responses import JSONResponse

from app import container
from app.bsn import is_valid_bsn
from app.middleware.auth_required import auth_required
from app.services.bpg_service import BpgService
from app.services.pdn_service import PdnService
from app.services.tls_service import CertAuthentications
from app.types import OrganisationId

logger = logging.getLogger(__name__)
router = APIRouter()

@router.post("/base_pseudonym")
@auth_required([CertAuthentications.AUTH_UZI_CERT])
def get_base_pseudonym(
    request: Request,
    bsn: str = Query(str, description="The BSN to generate a Base Pseudonym for"),
    bpg_service: BpgService = Depends(container.get_bpg_service),
):
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


@router.post("/org_pseudonym")
@auth_required([CertAuthentications.AUTH_UZI_CERT])
def get_base_pseudonym(
        request: Request,
        bsn: str = Query(str, description="The BSN to generate the PDN for"),
        org_id: str = Query(str, description="The organisation ID for this PDN"),
        bpg_service: BpgService = Depends(container.get_bpg_service),
        pdn_service: PdnService = Depends(container.get_pdn_service),
):
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