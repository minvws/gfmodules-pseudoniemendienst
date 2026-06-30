import logging

from fastapi import APIRouter, Depends, HTTPException
from starlette.responses import JSONResponse

from app import container
from app.models.oin import Oin
from app.models.requests import OrgRequest
from app.rid import RidUsage
from app.services.key_resolver import KeyResolver
from app.services.org_service import OrgService

logger = logging.getLogger(__name__)
router = APIRouter()


@router.post(
    "/orgs", summary="Create new organization", tags=["Organizational Services"]
)
def post_org(
    req: OrgRequest,
    org_service: OrgService = Depends(container.get_org_service),
) -> JSONResponse:
    org = org_service.get_by_oin(req.oin)
    if org is not None:
        logger.warning("organization with OIN %s already exists", req.oin)
        raise HTTPException(
            status_code=409, detail="organization with this OIN already exists"
        )
    try:
        org_service.create(req.oin, req.name, req.max_key_usage)
    except Exception:
        logger.exception("failed to create organization")
        raise HTTPException(status_code=500, detail="failed to create organization")
    return JSONResponse(
        status_code=201, content={"message": "Org created successfully"}
    )


@router.get("/org/{oin}", summary="List organization", tags=["Organizational Services"])
def list_keys_for_org(
    oin: Oin,
    org_service: OrgService = Depends(container.get_org_service),
) -> JSONResponse:
    org = org_service.get_by_oin(oin)
    if org is None:
        logger.warning("organization for OIN %s not found", oin)
        raise HTTPException(status_code=404, detail="organization not found")

    return JSONResponse(status_code=200, content=org.to_dict())


@router.put(
    "/org/{oin}", summary="Update specific org", tags=["Organizational Services"]
)
def put_org(
    oin: Oin,
    req: OrgRequest,
    org_service: OrgService = Depends(container.get_org_service),
) -> JSONResponse:

    org = org_service.get_by_oin(oin)
    if org is None:
        logger.warning("organization for OIN %s not found", oin)
        raise HTTPException(status_code=404, detail="organization not found")

    if org.oin != req.oin:
        logger.warning("attempt to change OIN from %s to %s", org.oin, req.oin)
        raise HTTPException(status_code=404, detail="OIN cannot be changed")

    org_service.update(
        org.id, req.name, req.max_key_usage or RidUsage.IrreversiblePseudonym
    )
    updated_entry = org_service.get_by_oin(oin)
    if updated_entry is None:
        logger.error("failed to retrieve updated org for OIN %s", oin)
        raise HTTPException(status_code=500, detail="failed to retrieve updated org")

    return JSONResponse(status_code=200, content=updated_entry.to_dict())


@router.delete(
    "/org/{oin}", summary="Delete specific org", tags=["Organizational Services"]
)
def delete_org(
    oin: Oin,
    org_service: OrgService = Depends(container.get_org_service),
    key_resolver: KeyResolver = Depends(container.get_key_resolver),
) -> JSONResponse:

    org = org_service.get_by_oin(oin)
    if org is None:
        logger.warning(
            "organization not found for delete request, requested_oin=%s", oin
        )
        raise HTTPException(status_code=404, detail="organization not found")

    key_resolver.delete_by_org(org.id)  # Should be cascade, but just in case
    org_service.delete(org.id)

    logger.info(
        "deleted organization id=%s requested_oin=%s and all associated keys",
        org.id,
        org.oin,
    )
    return JSONResponse(status_code=200, content={"message": "org and keys deleted"})
