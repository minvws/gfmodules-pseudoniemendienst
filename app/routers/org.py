import logging
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Path
from starlette.responses import JSONResponse

from app import container
from app.models.requests import OrgRequest, URA_PATTERN
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
    org = org_service.get_by_ura(req.ura)
    if org is not None:
        logger.warning("organization with URA %s already exists", req.ura)
        raise HTTPException(
            status_code=409, detail="organization with this ura already exists"
        )
    try:
        org_service.create(req.ura, req.name, req.max_key_usage)
    except Exception:
        logger.exception("failed to create organization")
        raise HTTPException(status_code=500, detail="failed to create organization")
    return JSONResponse(
        status_code=201, content={"message": "Org created successfully"}
    )


@router.get("/org/{ura}", summary="List organization", tags=["Organizational Services"])
def list_keys_for_org(
    ura: Annotated[str, Path(pattern=URA_PATTERN)],
    org_service: OrgService = Depends(container.get_org_service),
) -> JSONResponse:
    org = org_service.get_by_ura(ura)
    if org is None:
        logger.warning("organization for URA %s not found", ura)
        raise HTTPException(status_code=404, detail="organization not found")

    return JSONResponse(status_code=200, content=org.to_dict())


@router.put(
    "/org/{ura}", summary="Update specific org", tags=["Organizational Services"]
)
def put_org(
    ura: Annotated[str, Path(pattern=URA_PATTERN)],
    req: OrgRequest,
    org_service: OrgService = Depends(container.get_org_service),
) -> JSONResponse:

    org = org_service.get_by_ura(ura)
    if org is None:
        logger.warning("organization for URA %s not found", ura)
        raise HTTPException(status_code=404, detail="organization not found")

    if org.ura != req.ura:
        logger.warning("attempt to change URA from %s to %s", org.ura, req.ura)
        raise HTTPException(status_code=404, detail="Ura cannot be changed")

    org_service.update(
        org.id, req.name, req.max_key_usage or RidUsage.IrreversiblePseudonym
    )
    updated_entry = org_service.get_by_ura(ura)
    if updated_entry is None:
        logger.error("failed to retrieve updated org for URA %s", ura)
        raise HTTPException(status_code=500, detail="failed to retrieve updated org")

    return JSONResponse(status_code=200, content=updated_entry.to_dict())


@router.delete(
    "/org/{ura}", summary="Delete specific org", tags=["Organizational Services"]
)
def delete_org(
    ura: Annotated[str, Path(pattern=URA_PATTERN)],
    org_service: OrgService = Depends(container.get_org_service),
    key_resolver: KeyResolver = Depends(container.get_key_resolver),
) -> JSONResponse:

    org = org_service.get_by_ura(ura)
    if org is None:
        logger.warning(
            "organization not found for delete request, requested_ura=%s", ura
        )
        raise HTTPException(status_code=404, detail="organization not found")

    key_resolver.delete_by_org(org.id)  # Should be cascade, but just in case
    org_service.delete(org.id)

    logger.info(
        "deleted organization id=%s requested_ura=%s and all associated keys",
        org.id,
        org.ura,
    )
    return JSONResponse(status_code=200, content={"message": "org and keys deleted"})
