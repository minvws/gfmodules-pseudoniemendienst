import logging
import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Path
from starlette.requests import Request
from starlette.responses import JSONResponse

from app import container
from app.auth import AuthContext, get_auth_ctx
from app.models.requests import RegisterRequest, URA_PATTERN
from app.services.mtls_service import MtlsService
from app.services.key_resolver import KeyResolver, KeyRequest, AlreadyExistsError
from app.services.org_service import OrgService

logger = logging.getLogger(__name__)
router = APIRouter()


@router.post(
    "/register/certificate",
    summary="Insert public key information for an organization",
    tags=["Key Registration Services"],
)
def post_key(
    req: RegisterRequest,
    request: Request,
    mtls_service: MtlsService = Depends(container.get_mtls_service),
    key_resolver: KeyResolver = Depends(container.get_key_resolver),
) -> JSONResponse:

    mtls_pub_key = mtls_service.get_mtls_pub_key(request)
    org = mtls_service.get_org_from_request(request)

    # Create the key entry
    try:
        key_resolver.create(org.id, req.scope, mtls_pub_key)
    except AlreadyExistsError:
        logger.warning("key already exists for org_id=%s scope=%r", org.id, req.scope)
        raise HTTPException(
            status_code=409, detail="key for this org/scope already exists"
        )
    except Exception:
        logger.exception(
            "failed to create key entry for org_id=%s scope=%r", org.id, req.scope
        )
        raise HTTPException(status_code=500, detail="failed to create key entry")

    return JSONResponse(
        status_code=201, content={"message": "Key created successfully"}
    )


@router.get(
    "/keys/{ura}",
    summary="List public key information for an organization",
    tags=["Key Registration Services"],
)
def list_keys_for_org(
    ura: Annotated[str, Path(pattern=URA_PATTERN)],
    key_resolver: KeyResolver = Depends(container.get_key_resolver),
    org_service: OrgService = Depends(container.get_org_service),
) -> JSONResponse:
    org = org_service.get_by_ura(ura)
    if org is None:
        logger.warning("organization for URA %r not found", ura)
        raise HTTPException(
            status_code=400, detail="organization for this URA is not registered"
        )

    entries = key_resolver.get_by_org(org.id)
    if entries is None:
        logger.warning("no keys found for organization %s", org.id)
        raise HTTPException(status_code=404, detail="no keys found")

    return JSONResponse(status_code=200, content=[e.to_dict() for e in entries])


@router.put(
    "/keys/{key_id}",
    summary="Update specific key for key/scope",
    tags=["Key Registration Services"],
)
def put_key(
    key_id: str,
    req: KeyRequest,
    auth_ctx: AuthContext = Depends(get_auth_ctx),
    key_resolver: KeyResolver = Depends(container.get_key_resolver),
    org_service: OrgService = Depends(container.get_org_service),
) -> JSONResponse:

    try:
        key_uuid = uuid.UUID(key_id)
    except ValueError:
        logger.warning("invalid key id: %r", key_id)
        raise HTTPException(status_code=400, detail="invalid key id")

    entry = key_resolver.get_by_id(key_uuid)
    if entry is None:
        logger.warning("key with id %r not found", key_id)
        raise HTTPException(status_code=404, detail="key not found")

    caller_org = org_service.get_by_ura(str(auth_ctx.ura_number))
    if caller_org is None or entry.organization_id != caller_org.id:
        logger.warning(
            "caller ura=%s attempted to update key %s owned by org %s",
            auth_ctx.ura_number,
            key_id,
            entry.organization_id,
        )
        raise HTTPException(status_code=403, detail="forbidden")

    key_resolver.update(entry.id, req.scope, req.pub_key)
    updated_entry = key_resolver.get_by_id(key_uuid)
    if updated_entry is None:
        logger.error("failed to retrieve updated key with id %r", key_id)
        raise HTTPException(status_code=500, detail="failed to retrieve updated key")

    return JSONResponse(status_code=200, content=updated_entry.to_dict())


@router.delete(
    "/keys/{key_id}",
    summary="Delete specific key for key/scope",
    tags=["Key Registration Services"],
)
def delete_key(
    key_id: str,
    auth_ctx: AuthContext = Depends(get_auth_ctx),
    key_resolver: KeyResolver = Depends(container.get_key_resolver),
    org_service: OrgService = Depends(container.get_org_service),
) -> JSONResponse:
    try:
        key_uuid = uuid.UUID(key_id)
    except ValueError:
        logger.warning("invalid key id: %r", key_id)
        raise HTTPException(status_code=400, detail="invalid key id")

    entry = key_resolver.get_by_id(key_uuid)
    if entry is None:
        logger.warning("key with id %r not found", key_id)
        raise HTTPException(status_code=404, detail="key not found")

    caller_org = org_service.get_by_ura(str(auth_ctx.ura_number))
    if caller_org is None or entry.organization_id != caller_org.id:
        logger.warning(
            "caller ura=%s attempted to delete key %s owned by org %s",
            auth_ctx.ura_number,
            key_id,
            entry.organization_id,
        )
        raise HTTPException(status_code=403, detail="forbidden")

    key_resolver.delete(entry.id)
    logger.info("key with id %s deleted successfully", key_id)
    return JSONResponse(status_code=200, content={"message": "key deleted"})
