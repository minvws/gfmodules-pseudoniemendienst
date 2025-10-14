import logging

from fastapi import APIRouter, Depends, HTTPException
from starlette.requests import Request
from starlette.responses import JSONResponse

from app import container
from app.models.requests import RegisterRequest
from app.services.mtls_service import MtlsService
from app.rid import RidUsage
from app.services.key_resolver import KeyResolver, KeyRequest, AlreadyExistsError
from app.services.org_service import OrgService

logger = logging.getLogger(__name__)
router = APIRouter()

@router.post("/register/certificate", summary="Insert public key information for an organization", tags=["key-service"])
def post_key(
    req: RegisterRequest,
    request: Request,
    mtls_service: MtlsService = Depends(container.get_mtls_service),
    key_resolver: KeyResolver = Depends(container.get_key_resolver),
    org_service: OrgService = Depends(container.get_org_service),
) -> JSONResponse:

    # Fetch public key from the client certificate
    mtls_pub_key = mtls_service.get_mtls_pub_key(request)

    # Extract URA from the client certificate and validate S-type
    data = mtls_service.get_mtls_uzi_data(request)
    if data["CardType"] != "S":
        raise HTTPException(status_code=401, detail="Invalid client certificate. Need an UZI S-type certificate.")
    ura = data["UziNumber"]

    # Make sure we have (pre)registered the organization for this URa
    org = org_service.get_by_ura(ura)
    if org is None:
        raise HTTPException(status_code=404, detail="organization for this URA is not registered")

    # Create the key entry
    try:
        key_resolver.create(org.id, req.scope, mtls_pub_key)
    except AlreadyExistsError as e:
        logger.error(f"failed to create key entry: {e}")
        raise HTTPException(status_code=409, detail="key for this org/scope already exists")
    except Exception as e:
        logger.error(f"failed to create key entry: {e}")
        raise HTTPException(status_code=500, detail="failed to create key entry")

    return JSONResponse(status_code=201, content={"message": "Key created successfully"})


@router.get("/keys/{ura}", summary="List public key information for an organization", tags=["key-service"])
def list_keys_for_org(
    ura: str,
    key_resolver: KeyResolver = Depends(container.get_key_resolver),
    org_service: OrgService = Depends(container.get_org_service),
) -> JSONResponse:
    org = org_service.get_by_ura(ura)
    if org is None:
        raise HTTPException(status_code=400, detail="organization for this URA is not registered")

    entries = key_resolver.get_by_org(org.id)
    if entries is None:
        raise HTTPException(status_code=404, detail="no keys found")

    print(entries)

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





