import logging

from fastapi import APIRouter, Depends, HTTPException
from starlette.responses import JSONResponse

from app import container
from app.models.requests import OrgRequest
from app.rid import RidUsage
from app.services.key_resolver import KeyResolver
from app.services.org_service import OrgService

logger = logging.getLogger(__name__)
router = APIRouter()

@router.post("/orgs", summary="Create new organization", tags=["org-service"])
def post_org(
    req: OrgRequest,
    org_service: OrgService = Depends(container.get_org_service),
) -> JSONResponse:
    org = org_service.get_by_ura(req.ura)
    if org is not None:
        raise HTTPException(status_code=409, detail="organization with this ura already exists")
    try:
        org_service.create(req.ura, req.name, req.max_key_usage)
    except Exception as e:
        logger.error(f"failed to create org: {e}")
        raise HTTPException(status_code=500, detail="failed to create organization")
    return JSONResponse(status_code=201, content={"message": "Org created successfully"})


@router.get("/org/{ura}", summary="List organization", tags=["org-service"])
def list_keys_for_org(
    ura: str,
    org_service: OrgService = Depends(container.get_org_service),
) -> JSONResponse:
    org = org_service.get_by_ura(ura)
    if org is None:
        raise HTTPException(status_code=404, detail="organization not found")

    return JSONResponse(status_code=200, content=org.to_dict())


@router.put("/org/{ura}", summary="Update specific org", tags=["org-service"])
def put_org(
    ura: str,
    req: OrgRequest,
    org_service: OrgService = Depends(container.get_org_service),
) -> JSONResponse:

    org = org_service.get_by_ura(ura)
    if org is None:
        raise HTTPException(status_code=404, detail="organization not found")

    if org.ura != req.ura:
        raise HTTPException(status_code=404, detail="Ura cannot be changed")

    org_service.update(org.id, req.name, req.max_key_usage or RidUsage.IrreversiblePseudonym)
    updated_entry = org_service.get_by_ura(ura)
    if updated_entry is None:
        raise HTTPException(status_code=500, detail="failed to retrieve updated org")

    return JSONResponse(status_code=200, content=updated_entry.to_dict())


@router.delete("/org/{ura}", summary="Delete specific org", tags=["org-service"])
def delete_org(
    ura: str,
    org_service: OrgService = Depends(container.get_org_service),
    key_resolver: KeyResolver = Depends(container.get_key_resolver),
) -> JSONResponse:

    org = org_service.get_by_ura(ura)
    if org is None:
        raise HTTPException(status_code=404, detail="organization not found")

    key_resolver.delete_by_org(org.id)  # Should be cascade, but just in case
    org_service.delete(org.id)
    return JSONResponse(status_code=200, content={"message": "org and keys deleted"})





