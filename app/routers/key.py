import logging

from fastapi import APIRouter, Depends, HTTPException
from starlette.responses import JSONResponse

from app import container
from app.rid import RidUsage
from app.services.key_resolver import KeyResolver, KeyRequest

logger = logging.getLogger(__name__)
router = APIRouter()

@router.post("/keys", summary="Insert public key information for an organization", tags=["key-service"])
def post_key(
    req: KeyRequest,
    key_resolver: KeyResolver = Depends(container.get_key_resolver),
) -> JSONResponse:
    key_resolver.create(req.organization, req.scope, req.pub_key)
    return JSONResponse(status_code=201, content={"message": "Key created successfully"})


@router.get("/keys/{ura}", summary="List public key information for an organization", tags=["key-service"])
def list_keys_for_org(
    ura: str,
    key_resolver: KeyResolver = Depends(container.get_key_resolver),
) -> JSONResponse:
    entries = key_resolver.get_by_org(ura)
    if entries is None:
        raise HTTPException(status_code=404, detail="organization not found")

    return JSONResponse(status_code=200, content=[e.to_dict() for e in entries])


@router.put("/keys/{key_id}", summary="Update specific key for key/scope", tags=["key-service"])
def put_key(
    key_id: str,
    req: KeyRequest,
    key_resolver: KeyResolver = Depends(container.get_key_resolver),
) -> JSONResponse:

    entry = key_resolver.get_by_id(key_id)
    if entry is None:
        raise HTTPException(status_code=404, detail="key not found")

    if entry.organization != req.organization:
        raise HTTPException(status_code=404, detail="organization not found")

    key_resolver.update(str(entry.entry_id), req.scope, req.pub_key, req.max_key_usage or RidUsage.IrreversiblePseudonym)
    updated_entry = key_resolver.get_by_id(key_id)
    if updated_entry is None:
        raise HTTPException(status_code=500, detail="failed to retrieve updated key")

    return JSONResponse(status_code=200, content=updated_entry.to_dict())


@router.delete("/keys/{key_id}", summary="Delete specific key for key/scope", tags=["key-service"])
def delete_key(
    key_id: str,
    key_resolver: KeyResolver = Depends(container.get_key_resolver),
) -> JSONResponse:

    entry = key_resolver.get_by_id(key_id)
    if entry is None:
        raise HTTPException(status_code=404, detail="key not found")

    key_resolver.delete(str(entry.entry_id))
    return JSONResponse(status_code=200, content={"message": "key deleted"})





